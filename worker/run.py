from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx


def _load_dotenv() -> None:
    if os.path.exists(".env"):
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v


@dataclass(frozen=True)
class Settings:
    work_dir: str

    # Anthropic
    anthropic_api_key: str | None
    anthropic_model_default: str
    anthropic_model_heavy: str

    # OpenAI-compatible (e.g., vLLM)
    openai_base_url: str | None
    openai_api_key: str | None
    openai_model_default: str

    # Guardrail
    guardrail_max_attempts: int
    guardrail_min_confidence: float


def load_settings() -> Settings:
    _load_dotenv()

    anth_key = os.getenv("ANTHROPIC_API_KEY")
    openai_base = os.getenv("OPENAI_BASE_URL")
    openai_key = os.getenv("OPENAI_API_KEY")

    if not anth_key and not openai_base:
        raise RuntimeError("Set ANTHROPIC_API_KEY or OPENAI_BASE_URL")

    return Settings(
        work_dir=os.getenv("AUTORE_WORK_DIR", "/home/ubuntu/clawd/autore/work"),

        anthropic_api_key=anth_key,
        anthropic_model_default=os.getenv("ANTHROPIC_MODEL_DEFAULT", "claude-sonnet-4-5"),
        anthropic_model_heavy=os.getenv("ANTHROPIC_MODEL_HEAVY", "claude-opus-4-5"),

        openai_base_url=openai_base,
        openai_api_key=openai_key,
        openai_model_default=os.getenv("OPENAI_MODEL_DEFAULT", "gpt-oss-120b"),

        guardrail_max_attempts=max(1, min(int(os.getenv("AUTORE_GUARDRAIL_MAX_ATTEMPTS", "4")), 10)),
        guardrail_min_confidence=float(os.getenv("AUTORE_GUARDRAIL_MIN_CONFIDENCE", "0.55")),
    )


def _analysis_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


_JST = timezone(timedelta(hours=9))


def _now_jst_iso() -> str:
    return datetime.now(_JST).isoformat()


def _atomic_write(path: Path, obj: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _update_index(idx_path: Path, fid: str, patch: dict) -> dict:
    """Safely update a single function entry in index.json.

    Avoids clobbering concurrent updates from backend/other worker runs.
    """

    index = _load_json(idx_path, {})
    prev = index.get(fid) if isinstance(index.get(fid), dict) else {}
    index[fid] = {**prev, **patch}
    _atomic_write(idx_path, index)
    return index


def _write_function_summary(base: Path, fid: str, summary_ja: str, confidence: float | None, *, source: str, model: str, provider: str) -> None:
    p = base / "ai" / "summaries" / f"{fid}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "function_id": fid,
        "status": "ok",
        "summary_ja": summary_ja,
        "confidence": confidence,
        "source": source,
        "provider": provider,
        "model": model,
        "updated_at": _now_jst_iso(),
    }
    _atomic_write(p, payload)


def _load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


PROMPT_V2 = """You are a senior reverse engineer.
You will be given a function context bundle extracted from Ghidra + minimal surrounding context.
Your job: produce a highly readable, high-precision decompilation-style output.

Hard rules:
- Do NOT execute anything.
- Prefer correctness over verbosity; be explicit about uncertainties.
- Preserve types/calling conventions when confident; otherwise mark unknown.
- If Ghidra's C-like decompile conflicts with disassembly, reconcile and mention the conflict.
- Return ONLY valid JSON (no markdown fences, no extra commentary).

Output JSON keys (ALL REQUIRED):
- pseudocode (string)  // readable C-like pseudocode
- proposed_name (string|null)
- signature (string|null) // best-effort function prototype
- summary_ja (string) // Japanese summary of what the function does (3-8 lines)
- key_points (array of strings)
- iocs (array of strings)
- needs_review (array of strings)
- confidence (number 0..1)

Notes:
- Use provided type_context (Ghidra prototype, API signatures, inferred types).
- Use provided minimal_context (calls_in/out, strings, imports) sparingly.
"""

PROMPT_SUMMARY_JA = """You are a senior reverse engineer.
You will be given a function context bundle extracted from Ghidra.
Your job: write a concise and accurate Japanese summary of what the function does.

Hard rules:
- Do NOT execute anything.
- Return ONLY valid JSON.
- Do NOT include pseudocode.

Output JSON keys (ALL REQUIRED):
- summary_ja (string) // 3-8 lines, Japanese. mention purpose + important behaviors + noteworthy APIs/IOCs if any.
- confidence (number 0..1)
"""

PROMPT_EXE_SUMMARY_JA = """You are a senior reverse engineer.
You will be given a set of per-function Japanese summaries for an executable.
Your job: produce a high-precision Japanese summary for the whole EXE.

Hard rules:
- Return ONLY valid JSON.

Output JSON keys (ALL REQUIRED):
- summary_ja (string) // Japanese, structured: overview, behavior, network/file/registry/process, persistence, crypto, indicators, uncertainties.
- confidence (number 0..1)
"""


def _extract_json_from_text(text: str) -> dict | None:
    """Best-effort JSON extraction from model output.

    Handles:
    - plain JSON
    - ```json ...``` fenced blocks
    - extra leading/trailing commentary (extract first {...} block)
    """

    raw = (text or "").strip()
    if not raw:
        return None

    # Strip markdown fences
    if raw.startswith("```"):
        lines = raw.splitlines()
        # drop first line (``` or ```json)
        if lines:
            lines = lines[1:]
        # drop trailing fence
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        raw = "\n".join(lines).strip()

    # If it is now plain JSON
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    # Try extracting the first JSON object-ish block
    import re

    m = re.search(r"\{[\s\S]*\}", raw)
    if m:
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass

    return None


def _normalize_anthropic_model(model: str) -> str:
    """Map UI/Clawdbot-friendly aliases to Anthropic API model ids."""

    m = (model or "").strip()
    ml = m.lower()

    # Common aliases used in this repo/UI
    if ml in ("sonnet", "claude-sonnet-4-5", "claude-3-5-sonnet", "claude-3-5-sonnet-latest"):
        return "claude-3-5-sonnet-latest"
    if ml in ("opus", "claude-opus-4-5", "claude-3-opus", "claude-3-opus-latest"):
        return "claude-3-opus-latest"

    # Otherwise assume caller provided a valid Anthropic model id.
    return m


def _extract_text_from_openai_responses(data: dict) -> str:
    """Best-effort text extraction from OpenAI Responses API."""

    if not isinstance(data, dict):
        return ""

    # Newer SDKs sometimes provide convenience fields.
    ot = data.get("output_text")
    if isinstance(ot, str) and ot.strip():
        return ot

    out = data.get("output")
    if isinstance(out, list):
        parts: list[str] = []
        for item in out:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, list):
                for c in content:
                    if not isinstance(c, dict):
                        continue
                    if c.get("type") == "output_text" and isinstance(c.get("text"), str):
                        parts.append(c.get("text"))
        txt = "\n".join([p for p in parts if p])
        return txt

    return ""


def call_openai_responses(
    base_url: str,
    api_key: str | None,
    model: str,
    user_text: str,
    reasoning: str | None = None,
    *,
    system_prompt: str = PROMPT_V2,
) -> dict:
    """OpenAI-compatible responses.create() call.

    Many internal gateways implement /v1/responses.
    """

    base = (base_url or "").rstrip("/")
    if base.endswith("/v1"):
        url = base + "/responses"
    else:
        url = base + "/v1/responses"

    headers = {"content-type": "application/json"}
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"

    body: dict = {
        "model": model,
        "input": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_text[:45000]},
        ],
        "max_output_tokens": 6000,
        "temperature": 0.2,
    }

    if reasoning:
        # OpenAI format: { effort: "low"|"medium"|"high" }
        body["reasoning"] = {"effort": reasoning}

    t0 = time.time()
    with httpx.Client(timeout=180) as client:
        r = client.post(url, headers=headers, json=body)
        api_ms = int((time.time() - t0) * 1000)

        if not r.is_success:
            raise httpx.HTTPStatusError(
                f"{r.status_code} {r.reason_phrase}: {r.text}", request=r.request, response=r
            )

        data = r.json()

    text = _extract_text_from_openai_responses(data)

    obj = _extract_json_from_text(text)
    if obj is None:
        obj = {"pseudocode": "", "confidence": 0.0, "_raw_text": text}

    obj["_api_ms"] = api_ms
    obj["_status_code"] = r.status_code
    obj["_request"] = {
        "url": url,
        "model": model,
        "max_output_tokens": body.get("max_output_tokens"),
        "input_chars": min(len(user_text), 45000),
        "reasoning": reasoning or "",
    }

    if isinstance(data.get("usage"), dict):
        obj["usage"] = data.get("usage")

    return obj


def call_openai_chat(
    base_url: str,
    api_key: str | None,
    model: str,
    user_text: str,
    reasoning: str | None = None,
    *,
    system_prompt: str = PROMPT_V2,
) -> dict:
    """OpenAI-compatible chat.completions call.

    Notes:
    - Some internal endpoints already include /v1 in the configured base_url.
    - Some internal endpoints do not require authentication.
    - We do NOT rely on response_format; guardrail retries enforce structure.
    """

    base = (base_url or "").rstrip("/")
    if base.endswith("/v1"):
        url = base + "/chat/completions"
    else:
        url = base + "/v1/chat/completions"

    headers = {"content-type": "application/json"}
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"

    # OpenAI-style messages
    body = {
        "model": model,
        "temperature": 0.2,
        "max_tokens": 6000,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_text[:45000]},
        ],
    }

    # Some OpenAI-compatible endpoints accept reasoning_effort.
    if reasoning:
        body["reasoning_effort"] = reasoning

    t0 = time.time()
    with httpx.Client(timeout=180) as client:
        r = client.post(url, headers=headers, json=body)
        api_ms = int((time.time() - t0) * 1000)

        if not r.is_success:
            raise httpx.HTTPStatusError(
                f"{r.status_code} {r.reason_phrase}: {r.text}", request=r.request, response=r
            )

        data = r.json()

    # Extract text
    text = ""
    try:
        choices = data.get("choices") or []
        if choices:
            msg = (choices[0] or {}).get("message") or {}
            text = msg.get("content") or ""
    except Exception:
        text = ""

    obj = _extract_json_from_text(text)
    if obj is None:
        obj = {"pseudocode": "", "confidence": 0.0, "_raw_text": text}

    obj["_api_ms"] = api_ms
    obj["_status_code"] = r.status_code
    obj["_request"] = {"url": url, "model": model, "max_tokens": body.get("max_tokens"), "input_chars": min(len(user_text), 45000)}

    # capture minimal usage when present
    if isinstance(data.get("usage"), dict):
        obj["usage"] = data.get("usage")

    return obj



def call_anthropic(api_key: str, model: str, user_text: str, *, system_prompt: str = PROMPT_V2) -> dict:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": _normalize_anthropic_model(model),
        # Bump to reduce truncation; still bounded for latency/cost.
        "max_tokens": 6000,
        "temperature": 0.2,
        "system": system_prompt,
        "messages": [
            {"role": "user", "content": user_text[:45000]},
        ],
    }

    t0 = time.time()
    status_code = None
    with httpx.Client(timeout=120) as client:
        def _post(model_id: str):
            b = dict(body)
            b["model"] = model_id
            return client.post("https://api.anthropic.com/v1/messages", headers=headers, json=b)

        model_id = body["model"]
        r = _post(model_id)
        status_code = r.status_code
        api_ms = int((time.time() - t0) * 1000)

        if r.status_code == 400:
            # Some accounts/models return 400 for unknown/unsupported model ids.
            # Retry once with sonnet-latest as a safe default.
            try:
                txt = r.text
            except Exception:
                txt = ""
            if "model" in txt.lower() or "not_found" in txt.lower() or "unsupported" in txt.lower():
                r2 = _post("claude-3-5-sonnet-latest")
                status_code = r2.status_code
                if r2.is_success:
                    r = r2
                    model_id = "claude-3-5-sonnet-latest"
                else:
                    r = r2

        if not r.is_success:
            # Include response body for debugging.
            raise httpx.HTTPStatusError(
                f"{r.status_code} {r.reason_phrase}: {r.text}", request=r.request, response=r
            )

        data = r.json()
    data["_api_ms"] = api_ms
    data["_status_code"] = status_code
    data["_request"] = {
        "url": "https://api.anthropic.com/v1/messages",
        "model": model,
        "max_tokens": body.get("max_tokens"),
        "input_chars": min(len(user_text), 45000),
        "timeout_s": 120,
    }

    # Anthropic returns content as list; extract text
    text = ""
    for c in data.get("content", []) or []:
        if c.get("type") == "text":
            text += c.get("text", "")

    obj = _extract_json_from_text(text)
    if obj is not None:
        # Attach timing + usage for debugging.
        obj["_api_ms"] = data.get("_api_ms")
        if isinstance(data.get("usage"), dict):
            obj["usage"] = data.get("usage")
        return obj

    # Salvage: sometimes the model wraps fields in a JSON-looking blob but escapes are invalid.
    # In that case, extract the first fenced code block as pseudocode.
    import re

    t = (text or "").strip()
    # normal (real newlines)
    m = re.search(r"```(?:c|cpp|C)?\s*\n([\s\S]*?)\n```", t)
    if not m:
        # try un-escaping literal \\n sequences
        t2 = t.replace("\\n", "\n")
        m = re.search(r"```(?:c|cpp|C)?\s*\n([\s\S]*?)\n```", t2)
    if m:
        return {
            "pseudocode": m.group(1).strip(),
            "proposed_name": None,
            "signature": None,
            "key_points": [],
            "iocs": [],
            "needs_review": ["Model returned invalid JSON; extracted code block"],
            "confidence": 0.35,
            "_api_ms": data.get("_api_ms"),
            "usage": (data.get("usage") if isinstance(data.get("usage"), dict) else None),
        }

    return {
        "pseudocode": t,
        "proposed_name": None,
        "signature": None,
        "key_points": [],
        "iocs": [],
        "needs_review": ["Model did not return JSON; stored raw output"],
        "confidence": 0.3,
        "_api_ms": data.get("_api_ms"),
        "usage": (data.get("usage") if isinstance(data.get("usage"), dict) else None),
    }


def _append_log(base: Path, event: dict) -> None:
    """Append one JSON log line to job-local debug log.

    NOTE: do not include secrets (API key) or huge blobs (full disasm/decomp).
    """

    # Unified LLM log (Anthropic/OpenAI-compatible)
    lp = base / "ai" / "logs" / "llm.jsonl"
    lp.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(lp, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _read_text(p: Path, limit: int) -> str:
    if not p.exists():
        return ""
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return ""


def _extract_calls_from_text(text: str) -> list[str]:
    import re

    hits = []
    seen = set()

    # Ghidra-ish symbols: FUN_1400..., sub_1400..., function_1400...
    for m in re.finditer(r"\b(?:FUN|sub|function)_[0-9A-Fa-f]+\b", text):
        s = m.group(0)
        if s not in seen:
            seen.add(s)
            hits.append(s)

    # Also include named imports/calls (best-effort): CamelCase/WinAPI-like.
    for m in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_@\$]{2,}\b", text):
        s = m.group(0)
        if s.startswith(("FUN_", "sub_", "function_")):
            continue
        # heuristic: prefer likely symbols
        if any(ch.isupper() for ch in s) or s.endswith(("A", "W")):
            if s not in seen:
                seen.add(s)
                hits.append(s)
        if len(hits) >= 50:
            break

    return hits


def _extract_strings_from_ghidra_decomp(text: str) -> list[str]:
    import re

    out = []
    seen = set()
    for m in re.finditer(r"\"([^\"\\]{1,120})\"", text):
        s = m.group(1)
        if s and s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= 30:
            break
    return out


def _guess_ghidra_signature(ghidra_c: str) -> str | None:
    # Try to recover the function prototype from Ghidra decompile output.
    # Typically the first line looks like: 'int __cdecl FUN_1400...(args)'
    if not ghidra_c:
        return None
    line = ghidra_c.strip().splitlines()[0].strip()
    if not line:
        return None
    # strip opening brace if present on same line
    if "{" in line:
        line = line.split("{", 1)[0].strip()
    # basic sanity
    if "(" in line and ")" in line:
        return line
    return None


# A tiny set of well-known WinAPI signatures (best-effort). Expand as needed.
_WINAPI_SIGS: dict[str, str] = {
    "GetFileVersionInfoW": "BOOL GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)",
    "GetFileVersionInfoSizeW": "DWORD GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle)",
    "VerQueryValueW": "BOOL VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen)",
    "LoadLibraryW": "HMODULE LoadLibraryW(LPCWSTR lpLibFileName)",
    "GetProcAddress": "FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)",
}


def _build_context_bundle(base: Path, fid: str, disasm_text: str) -> tuple[str, dict]:
    """Construct the model input text + a small summary for logs."""

    # Keep each section bounded.
    ghidra_path = base / "extract" / "decomp" / f"{fid}.c"
    pcode_path = base / "extract" / "pcode" / f"{fid}.txt"

    ghidra_c = _read_text(ghidra_path, 22000)
    pcode = _read_text(pcode_path, 12000)
    if not pcode:
        raise RuntimeError("pcode missing (extract/pcode/{fid}.txt). Please Re-extract to generate pcode.")

    calls_out = _extract_calls_from_text(disasm_text)[:20]
    # calls_in: best-effort scan a limited number of disasm files (can be expensive)
    calls_in: list[str] = []
    try:
        disasm_dir = base / "extract" / "disasm"
        want = fid
        # scan up to N files
        scanned = 0
        for p in sorted(disasm_dir.glob("*.txt")):
            if p.name == f"{fid}.txt":
                continue
            scanned += 1
            if scanned > 250:
                break
            try:
                t = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if want in t:
                calls_in.append(p.stem)
            if len(calls_in) >= 20:
                break
    except Exception:
        pass

    strings = _extract_strings_from_ghidra_decomp(ghidra_c)[:20]

    # Heuristic imports: symbols that look like WinAPI and are not FUN_/sub_.
    imports = [x for x in calls_out if not x.startswith(("FUN_", "sub_", "function_"))]
    imports = imports[:20]

    winapi_sigs = {name: _WINAPI_SIGS.get(name) for name in imports if _WINAPI_SIGS.get(name)}

    type_context = {
        "ghidra_signature": _guess_ghidra_signature(ghidra_c),
        "winapi_signatures": winapi_sigs,
        "notes": [
            "If a called API is listed without a signature, infer it conservatively and mark unknown parameters/types.",
        ],
    }

    minimal_context = {
        "calls_out": calls_out,
        "calls_in": calls_in,
        "strings": strings,
        "imports_called": imports,
    }

    bundle = {
        "function_id": fid,
        "ghidra_decompiler_c": ghidra_c or None,
        "ghidra_pcode": pcode or None,
        "disasm": disasm_text[:26000],
        "type_context": type_context,
        "minimal_context": minimal_context,
        "requirements": [
            "Use Ghidra decompiler output as primary reference; verify against disassembly.",
            "Attach a best-effort typed function signature.",
            "Use only minimal context; do not hallucinate unseen strings/imports.",
        ],
    }

    user_text = (
        "INPUT_BUNDLE_JSON\n" + json.dumps(bundle, ensure_ascii=False, indent=2)
    )

    summary = {
        "has_ghidra": bool(ghidra_c),
        "has_pcode": bool(pcode),
        "calls_out_n": len(calls_out),
        "calls_in_n": len(calls_in),
        "imports_n": len(imports),
        "strings_n": len(strings),
    }

    return user_text, summary


def _validate_decompile_obj(obj: dict, min_conf: float) -> tuple[bool, str | None]:
    # Must be a dict with at least pseudocode, summary_ja and confidence.
    if not isinstance(obj, dict):
        return False, "not a JSON object"
    pc = obj.get("pseudocode")
    if not isinstance(pc, str) or len(pc.strip()) < 80:
        return False, "pseudocode too short/missing"
    sj = obj.get("summary_ja")
    if not isinstance(sj, str) or len(sj.strip()) < 30:
        return False, "summary_ja too short/missing"
    conf = obj.get("confidence")
    try:
        conf_f = float(conf)
    except Exception:
        return False, "confidence missing/not a number"
    if conf_f < min_conf:
        return False, f"confidence below threshold ({conf_f:.2f} < {min_conf:.2f})"
    return True, None


def _validate_summary_obj(obj: dict, min_conf: float) -> tuple[bool, str | None]:
    if not isinstance(obj, dict):
        return False, "not a JSON object"
    sj = obj.get("summary_ja")
    if not isinstance(sj, str) or len(sj.strip()) < 30:
        return False, "summary_ja too short/missing"
    conf = obj.get("confidence")
    try:
        conf_f = float(conf)
    except Exception:
        return False, "confidence missing/not a number"
    if conf_f < max(0.0, min_conf * 0.7):
        # Allow slightly lower confidence for summary-only.
        return False, f"confidence below threshold ({conf_f:.2f})"
    return True, None


def process_request(s: Settings, req: dict) -> None:
    job_id = req["job_id"]
    fid = req["function_id"]
    provider = (req.get("provider") or "anthropic").strip().lower()
    model = req.get("model") or (
        s.anthropic_model_default if provider == "anthropic" else s.openai_model_default
    )
    force = bool(req.get("force") or False)
    task = (req.get("task") or "decompile").strip().lower()

    base = Path(s.work_dir) / job_id

    # Special task: build EXE-level summary from stored per-function summaries.
    if task in ("summarize_exe", "exe_summary", "summarize_binary"):
        exe_out = base / "ai" / "exe_summary.json"
        lock_path = base / "ai" / "locks" / "__exe_summary__.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)

        _append_log(
            base,
            {
                "ts": _now_jst_iso(),
                "job_id": job_id,
                "function_id": "__exe__",
                "event": "exe_summary_received",
                "task": task,
                "model": model,
                "enqueued_at": req.get("enqueued_at"),
            },
        )

        # Lock
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
        except FileExistsError:
            return

        try:
            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": "__exe__",
                    "event": "exe_summary_started",
                    "task": task,
                    "model": model,
                },
            )

            # Load all function summaries
            summ_dir = base / "ai" / "summaries"
            items = []
            if summ_dir.exists():
                for fp in sorted(summ_dir.glob('*.json')):
                    try:
                        obj = json.loads(fp.read_text(encoding='utf-8'))
                        sj = obj.get('summary_ja')
                        if isinstance(sj, str) and sj.strip():
                            items.append({"function_id": obj.get("function_id") or fp.stem, "summary_ja": sj.strip()})
                    except Exception:
                        continue

            if not items:
                _atomic_write(exe_out, {"status": "error", "error": "no function summaries yet", "updated_at": _now_jst_iso()})
                return

            # Build prompt input
            joined = "\n\n".join([f"[{it['function_id']}]\n{it['summary_ja']}" for it in items[:400]])
            user_text = (
                "Per-function summaries (Japanese):\n" + joined + "\n\n" +
                "Now generate an EXE-level summary as JSON."
            )

            result = None

            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": "__exe__",
                    "event": "api_request",
                    "task": task,
                    "provider": provider,
                    "model": model,
                    "input_chars": min(len(user_text), 45000),
                },
            )

            t0 = time.time()
            if provider == 'anthropic':
                if not s.anthropic_api_key:
                    raise RuntimeError('ANTHROPIC_API_KEY not set')
                result = call_anthropic(s.anthropic_api_key, model, user_text, system_prompt=PROMPT_EXE_SUMMARY_JA)
            else:
                base_url = (req.get('openai_base_url') or s.openai_base_url)
                api_key = (req.get('openai_api_key') or s.openai_api_key)
                if not base_url:
                    raise RuntimeError('OPENAI_BASE_URL not set')
                api_mode = (req.get('openai_api_mode') or 'chat').strip().lower()
                reasoning = (req.get('openai_reasoning') or '').strip().lower() or None
                if api_mode == 'responses':
                    result = call_openai_responses(base_url, api_key, model, user_text, reasoning=reasoning, system_prompt=PROMPT_EXE_SUMMARY_JA)
                else:
                    result = call_openai_chat(base_url, api_key, model, user_text, reasoning=reasoning, system_prompt=PROMPT_EXE_SUMMARY_JA)

            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": "__exe__",
                    "event": "api_response",
                    "task": task,
                    "provider": provider,
                    "model": model,
                    "api_ms": int((time.time() - t0) * 1000),
                    "status_code": (result or {}).get('_status_code'),
                },
            )

            ok, why = _validate_summary_obj(result or {}, s.guardrail_min_confidence)
            if not ok:
                raise RuntimeError(f"exe summary invalid: {why}")

            payload = {
                "status": "ok",
                "provider": provider,
                "model": model,
                "summary_ja": (result or {}).get('summary_ja'),
                "confidence": float((result or {}).get('confidence', 0.5)),
                "functions_n": len(items),
                "updated_at": _now_jst_iso(),
            }
            exe_out.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(exe_out, payload)

            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": "__exe__",
                    "event": "exe_summary_finished",
                    "task": task,
                    "status": "ok",
                    "model": model,
                    "functions_n": len(items),
                },
            )
        except Exception as e:
            exe_out.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(exe_out, {"status": "error", "error": str(e), "updated_at": _now_jst_iso()})
            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": "__exe__",
                    "event": "exe_summary_finished",
                    "task": task,
                    "status": "error",
                    "model": model,
                    "error": str(e),
                },
            )
        finally:
            try:
                os.unlink(lock_path)
            except Exception:
                pass
        return

    is_summary_task = task in ("summarize", "summary", "summarize_function")

    _append_log(
        base,
        {
            "ts": _now_jst_iso(),
            "job_id": job_id,
            "function_id": fid,
            "event": ("summary_received" if is_summary_task else "decompile_received"),
            "task": task,
            "model": model,
            "force": force,
            "enqueued_at": req.get("enqueued_at"),
        },
    )
    def _resolve_extracted_path(base_dir: Path, subdir: str, fid_in: str, ext: str) -> Path:
        """Resolve extracted artifact path for a function.

        Filenames are sanitized by the Ghidra extraction script and may have minor variations
        (e.g., trailing underscores, double underscores).
        """
        d = base_dir / "extract" / subdir
        p0 = d / f"{fid_in}{ext}"
        if p0.exists():
            return p0
        try:
            import re

            safe = re.sub(r"[^A-Za-z0-9_\-\.]", "_", fid_in)
            cands = [
                safe,
                safe.rstrip("_"),
                safe.rstrip("_") + "_",
                safe.rstrip("_") + "__",
                re.sub(r"_+", "_", safe),
                re.sub(r"_+", "_", safe).rstrip("_"),
            ]
            seen = set()
            for s in cands:
                if not s or s in seen:
                    continue
                seen.add(s)
                p = d / f"{s}{ext}"
                if p.exists():
                    return p
            # last resort: scan dir
            cand_l = {s.lower() for s in seen if s}
            if d.exists():
                for fp in d.iterdir():
                    if fp.is_file() and fp.suffix.lower() == ext.lower() and fp.stem.lower() in cand_l:
                        return fp
        except Exception:
            pass
        return p0

    disasm_path = _resolve_extracted_path(base, "disasm", fid, ".txt")
    idx_path = base / "ai" / "index.json"

    out_path = (base / "ai" / "summaries" / f"{fid}.json") if is_summary_task else (base / "ai" / "results" / f"{fid}.json")

    lock_path = base / "ai" / "locks" / f"{fid}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    # Acquire lock (best-effort)
    # If a lock is stale (e.g., worker crashed mid-run), drop it.
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            meta = {"pid": os.getpid(), "ts": _now_jst_iso(), "job_id": job_id, "function_id": fid}
            os.write(fd, json.dumps(meta, ensure_ascii=False).encode("utf-8"))
        finally:
            os.close(fd)
    except FileExistsError:
        try:
            age = time.time() - lock_path.stat().st_mtime
        except Exception:
            age = None
        if age is not None and age > 10 * 60:
            # stale lock
            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": fid,
                    "event": "lock_stale_removed",
                    "lock_age_s": int(age),
                },
            )
            try:
                os.unlink(lock_path)
            except Exception:
                return
            # retry once
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                try:
                    meta = {"pid": os.getpid(), "ts": _now_jst_iso(), "job_id": job_id, "function_id": fid}
                    os.write(fd, json.dumps(meta, ensure_ascii=False).encode("utf-8"))
                finally:
                    os.close(fd)
            except FileExistsError:
                return
        else:
            return

    try:
        if task in ("summarize", "summary", "summarize_function"):
            _update_index(
                idx_path,
                fid,
                {
                    "summary_status": "running",
                    "summary_started_at": _now_jst_iso(),
                    "summary_provider": provider,
                    "summary_model": model,
                    "summary_enqueued_at": req.get("enqueued_at"),
                },
            )
            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": fid,
                    "event": "summary_started",
                    "model": model,
                },
            )
        else:
            _update_index(
                idx_path,
                fid,
                {
                    "status": "running",
                    "started_at": _now_jst_iso(),
                    "provider": provider,
                    "model": model,
                    "enqueued_at": req.get("enqueued_at"),
                },
            )
            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": fid,
                    "event": "decompile_started",
                    "model": model,
                },
            )

        if not disasm_path.exists():
            raise RuntimeError("disasm not found")

        disasm_text = disasm_path.read_text(encoding="utf-8", errors="replace")
        user_text, ctx_summary = _build_context_bundle(base, fid, disasm_text)
        ah = _analysis_hash(user_text)

        # cache: if existing and hash matches (unless forced)
        if (not force) and out_path.exists():
            existing = _load_json(out_path, {})
            if existing.get("analysis_hash") == ah and existing.get("status") == "ok":
                # If we introduced new required fields (e.g., summary_ja), do not treat older cached files as valid.
                if not is_summary_task:
                    sj = existing.get("summary_ja")
                    if not isinstance(sj, str) or len(sj.strip()) < 30:
                        existing = None

                if existing is not None:
                    if is_summary_task:
                        _update_index(
                            idx_path,
                            fid,
                            {
                                "summary_status": "ok",
                                "summary_updated_at": existing.get("updated_at"),
                                "summary_confidence": existing.get("confidence"),
                                "summary_model": existing.get("model"),
                            },
                        )
                    else:
                        _update_index(
                            idx_path,
                            fid,
                            {
                                "status": "ok",
                                "updated_at": existing.get("updated_at"),
                                "confidence": existing.get("confidence"),
                                "proposed_name": existing.get("proposed_name"),
                                "model": existing.get("model"),
                            },
                        )
                    _append_log(
                        base,
                        {
                            "ts": _now_jst_iso(),
                            "job_id": job_id,
                            "function_id": fid,
                            "event": "cache_hit",
                            "model": existing.get("model"),
                            "updated_at": existing.get("updated_at"),
                            "task": task,
                        },
                    )
                    return

        # Guardrail loop: retry until we get a satisfactory JSON payload.
        t_start = time.time()
        user_text_cur = user_text
        result: dict | None = None
        last_invalid: str | None = None

        max_attempts = s.guardrail_max_attempts
        try:
            if req.get("guardrail_max_attempts") is not None:
                max_attempts = int(req.get("guardrail_max_attempts"))
        except Exception:
            max_attempts = s.guardrail_max_attempts
        max_attempts = max(1, min(int(max_attempts), 10))

        min_conf = s.guardrail_min_confidence
        try:
            if req.get("guardrail_min_confidence") is not None:
                min_conf = float(req.get("guardrail_min_confidence"))
        except Exception:
            min_conf = s.guardrail_min_confidence
        min_conf = max(0.0, min(float(min_conf), 1.0))

        for attempt in range(1, max_attempts + 1):
            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": fid,
                    "event": "api_request",
                    "task": task,
                    "provider": provider,
                    "model": model,
                    "attempt": attempt,
                    "max_tokens": 6000,
                    "input_chars": min(len(user_text_cur), 45000),
                    "ctx": ctx_summary,
                    "note": last_invalid,
                },
            )

            try:
                if provider == "anthropic":
                    if not s.anthropic_api_key:
                        raise RuntimeError("ANTHROPIC_API_KEY not set")
                    result = call_anthropic(
                        s.anthropic_api_key,
                        model,
                        user_text_cur,
                        system_prompt=(PROMPT_SUMMARY_JA if is_summary_task else PROMPT_V2),
                    )
                elif provider in ("openai", "vllm"):
                    base_url = (req.get("openai_base_url") or s.openai_base_url)
                    api_key = (req.get("openai_api_key") or s.openai_api_key)
                    if not base_url:
                        raise RuntimeError("OPENAI_BASE_URL not set")
                    api_mode = (req.get("openai_api_mode") or "chat").strip().lower()
                    reasoning = (req.get("openai_reasoning") or "").strip().lower() or None
                    if reasoning not in (None, "low", "medium", "high"):
                        reasoning = None

                    if api_mode == "responses":
                        result = call_openai_responses(
                            base_url,
                            api_key,
                            model,
                            user_text_cur,
                            reasoning=reasoning,
                            system_prompt=(PROMPT_SUMMARY_JA if is_summary_task else PROMPT_V2),
                        )
                    else:
                        result = call_openai_chat(
                            base_url,
                            api_key,
                            model,
                            user_text_cur,
                            reasoning=reasoning,
                            system_prompt=(PROMPT_SUMMARY_JA if is_summary_task else PROMPT_V2),
                        )
                else:
                    raise RuntimeError(f"unknown provider: {provider}")
            except Exception as e:
                _append_log(
                    base,
                    {
                        "ts": _now_jst_iso(),
                        "job_id": job_id,
                        "function_id": fid,
                        "event": "api_response",
                        "task": task,
                        "provider": provider,
                        "model": model,
                        "attempt": attempt,
                        "status": "error",
                        "error": str(e),
                    },
                )
                raise

            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": fid,
                    "event": "api_response",
                    "task": task,
                    "provider": provider,
                    "model": model,
                    "attempt": attempt,
                    "status_code": result.get("_status_code"),
                    "api_ms": result.get("_api_ms"),
                    "output_chars": len(result.get("pseudocode") or "") if isinstance(result.get("pseudocode"), str) else None,
                },
            )

            ok, why = (_validate_summary_obj(result, min_conf) if is_summary_task else _validate_decompile_obj(result, min_conf))
            if ok:
                break

            last_invalid = why
            # Ask the model to try again; we don't have format-fixed endpoints, so we iterate.
            user_text_cur = (
                user_text
                + "\n\n---\nGuardrail: The previous output was not acceptable ("
                + str(why)
                + ("). Produce better JSON ONLY, with higher confidence and a clearer/longer Japanese summary.\n" if is_summary_task else "). Produce better JSON ONLY, with higher confidence and more complete pseudocode.\n")
            )
        else:
            raise RuntimeError(f"guardrail failed after {max_attempts} attempts: {last_invalid}")

        t_done = time.time()

        needs = (result or {}).get("needs_review", [])
        api_ms = None
        try:
            api_ms = int(((result or {}).get("_api_ms") or 0))
        except Exception:
            api_ms = None
        if isinstance(needs, bool):
            needs = [] if needs is False else ["needs_review flagged"]

        if is_summary_task:
            payload = {
                "function_id": fid,
                "status": "ok",
                "provider": provider,
                "model": model,
                "prompt_version": "summary_v1",
                "analysis_hash": ah,
                "context_summary": ctx_summary,
                "summary_ja": (result or {}).get("summary_ja"),
                "confidence": float((result or {}).get("confidence", 0.5)),
                "queued_at": req.get("enqueued_at"),
                "started_at": datetime.fromtimestamp(t_start, tz=_JST).isoformat(),
                "finished_at": datetime.fromtimestamp(t_done, tz=_JST).isoformat(),
                "total_ms": int((t_done - t_start) * 1000),
                "api_ms": api_ms,
                "usage": ((result or {}).get("usage") if isinstance((result or {}).get("usage"), dict) else None),
                "updated_at": _now_jst_iso(),
            }
            out_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(out_path, payload)

            # Also persist to dedicated summary store (same content, stable path)
            try:
                _write_function_summary(
                    base,
                    fid,
                    str(payload.get("summary_ja") or ""),
                    float(payload.get("confidence") or 0.0),
                    source="summarize",
                    model=model,
                    provider=provider,
                )
            except Exception:
                pass

            _update_index(
                idx_path,
                fid,
                {
                    "summary_status": "ok",
                    "summary_updated_at": payload["updated_at"],
                    "summary_confidence": payload.get("confidence"),
                    "summary_model": payload.get("model"),
                    "summary_queued_at": payload.get("queued_at"),
                    "summary_started_at": payload.get("started_at"),
                    "summary_finished_at": payload.get("finished_at"),
                    "summary_total_ms": payload.get("total_ms"),
                    "summary_api_ms": payload.get("api_ms"),
                },
            )

            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": fid,
                    "event": "summary_finished",
                    "model": model,
                    "status": "ok",
                    "total_ms": payload.get("total_ms"),
                    "api_ms": payload.get("api_ms"),
                    "usage": payload.get("usage"),
                },
            )
        else:
            payload = {
                "function_id": fid,
                "status": "ok",
                "provider": provider,
                "model": model,
                "prompt_version": "v2",
                "analysis_hash": ah,
                "context_summary": ctx_summary,
                "pseudocode": (result or {}).get("pseudocode"),
                "proposed_name": (result or {}).get("proposed_name"),
                "signature": (result or {}).get("signature"),
                "summary_ja": (result or {}).get("summary_ja"),
                "key_points": (result or {}).get("key_points", []) or [],
                "iocs": (result or {}).get("iocs", []) or [],
                "needs_review": needs or [],
                "confidence": float((result or {}).get("confidence", 0.5)),
                "queued_at": req.get("enqueued_at"),
                "started_at": datetime.fromtimestamp(t_start, tz=_JST).isoformat(),
                "finished_at": datetime.fromtimestamp(t_done, tz=_JST).isoformat(),
                "total_ms": int((t_done - t_start) * 1000),
                "api_ms": api_ms,
                "usage": ((result or {}).get("usage") if isinstance((result or {}).get("usage"), dict) else None),
                "updated_at": _now_jst_iso(),
            }
            out_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(out_path, payload)

            # Persist per-function summary for later EXE aggregation
            try:
                if isinstance(payload.get("summary_ja"), str) and str(payload.get("summary_ja") or "").strip():
                    _write_function_summary(
                        base,
                        fid,
                        str(payload.get("summary_ja") or ""),
                        float(payload.get("confidence") or 0.0),
                        source="decompile",
                        model=model,
                        provider=provider,
                    )
            except Exception:
                pass

            _update_index(
                idx_path,
                fid,
                {
                    "status": "ok",
                    "updated_at": payload["updated_at"],
                    "confidence": payload.get("confidence"),
                    "proposed_name": payload.get("proposed_name"),
                    "model": payload.get("model"),
                    "queued_at": payload.get("queued_at"),
                    "started_at": payload.get("started_at"),
                    "finished_at": payload.get("finished_at"),
                    "total_ms": payload.get("total_ms"),
                    "api_ms": payload.get("api_ms"),
                },
            )

            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": fid,
                    "event": "decompile_finished",
                    "model": model,
                    "status": "ok",
                    "total_ms": payload.get("total_ms"),
                    "api_ms": payload.get("api_ms"),
                    "usage": payload.get("usage"),
                },
            )

    except Exception as e:
        if is_summary_task:
            _update_index(
                idx_path,
                fid,
                {
                    "summary_status": "error",
                    "summary_error": str(e),
                    "summary_finished_at": _now_jst_iso(),
                },
            )
            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": fid,
                    "event": "summary_finished",
                    "model": model,
                    "status": "error",
                    "error": str(e),
                },
            )
        else:
            _update_index(
                idx_path,
                fid,
                {
                    "status": "error",
                    "error": str(e),
                    "finished_at": _now_jst_iso(),
                },
            )
            _append_log(
                base,
                {
                    "ts": _now_jst_iso(),
                    "job_id": job_id,
                    "function_id": fid,
                    "event": "decompile_finished",
                    "model": model,
                    "status": "error",
                    "error": str(e),
                },
            )
    finally:
        try:
            os.unlink(lock_path)
        except Exception:
            pass


def tail_jsonl(path: Path, offset: int) -> tuple[list[dict], int]:
    if not path.exists():
        return [], offset

    # If the queue file was truncated/rotated, clamp/reset the saved offset.
    try:
        size = path.stat().st_size
        if offset > size:
            offset = 0
    except Exception:
        pass

    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read()
        new_offset = f.tell()
    if not data:
        return [], new_offset
    lines = data.decode("utf-8", errors="replace").splitlines()
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out, new_offset


def _load_offsets(work_dir: str) -> dict[str, int]:
    p = Path(work_dir) / ".queue_offsets.json"
    if not p.exists():
        return {}
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(obj, dict):
            out: dict[str, int] = {}
            for k, v in obj.items():
                try:
                    out[str(k)] = int(v)
                except Exception:
                    continue
            return out
    except Exception:
        return {}
    return {}


def _save_offsets(work_dir: str, offsets: dict[str, int]) -> None:
    p = Path(work_dir) / ".queue_offsets.json"
    tmp = p.with_suffix(p.suffix + ".tmp")
    try:
        tmp.write_text(json.dumps(offsets, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, p)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def main() -> None:
    s = load_settings()
    print("worker starting; work_dir=", s.work_dir)

    # Persist offsets so we don't replay old queue entries after a restart.
    offsets: dict[str, int] = _load_offsets(s.work_dir)

    while True:
        changed = False
        for job in Path(s.work_dir).iterdir():
            if not job.is_dir():
                continue
            q = job / "queue" / "requests.jsonl"
            off = offsets.get(job.name, 0)
            reqs, new_off = tail_jsonl(q, off)
            if new_off != off:
                offsets[job.name] = new_off
                changed = True
            for req in reqs:
                process_request(s, req)

        if changed:
            _save_offsets(s.work_dir, offsets)

        time.sleep(1)


if __name__ == "__main__":
    main()
