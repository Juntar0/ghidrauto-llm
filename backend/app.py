from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile, Query
from pydantic import BaseModel

from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response

from sse_starlette.sse import EventSourceResponse

from .config import load_settings
from .extractor import run_capa_analysis, run_ghidra_extract
from .memory_peek import memory_view

import shutil
import subprocess
from .pecheck import looks_like_pe
from .storage import (
    ensure_job_dirs,
    fs_safe_name,
    read_json,
    sha256_file,
    write_json_atomic,
)

from .chat_llm import (
    SYSTEM_PROMPT_FINAL_ANSWER,
    SYSTEM_PROMPT_REACT_PLANNER,
    SYSTEM_PROMPT_REACT_VERIFIER,
    build_anthropic_messages,
    build_messages,
    call_anthropic_messages,
    call_openai_compatible,
)
from .chat_tools_v2 import TOOL_DESCRIPTIONS, dispatch_tool_v2

# In-memory session state for multi-step exploration
# Structure: {job_id: {step_count: int, active_function_id: str | None, last_updated: float}}
chat_sessions: dict[str, dict] = {}


def _spawn_extract(job_id: str, sample_path: Path, *, force: bool = False) -> None:
    """Run extraction in a separate Python process.

    FastAPI BackgroundTasks run inside the request worker process; if we run Ghidra/CAPA
    there, it can stall unrelated UI fetches. Spawning a subprocess keeps browsing snappy.
    """

    # Run as module so relative imports work.
    cmd = [sys.executable or "python3", "-m", "backend.extract_worker", job_id, str(sample_path)]
    if force:
        cmd.append("--force")

    try:
        # Detach; logs go to current stdout/stderr (uvicorn). Non-fatal if spawn fails.
        subprocess.Popen(cmd, cwd=str(Path(__file__).resolve().parents[1]))
    except Exception as e:
        print(f"[extract] failed to spawn extract_worker: {e}")


app = FastAPI(title="AutoRE Backend")
settings = load_settings()


@app.middleware("http")
async def _no_cache_html(request, call_next):
    resp = await call_next(request)
    try:
        ct = resp.headers.get("content-type", "")
        if ct.startswith("text/html"):
            resp.headers["Cache-Control"] = "no-store"
    except Exception:
        pass
    return resp


def _job_paths(job_id: str):
    return ensure_job_dirs(settings.work_dir, job_id)


def _analysis_path(job_id: str) -> Path:
    return Path(settings.work_dir) / job_id / "extract" / "analysis.json"


def _meta_path(job_id: str) -> Path:
    return Path(settings.work_dir) / job_id / "meta.json"


def _write_job_meta(
    *,
    job_id: str,
    source_type: str,
    source_path: str | None,
    original_name: str | None,
) -> None:
    mp = _meta_path(job_id)
    if mp.exists():
        return

    jst = timezone(timedelta(hours=9))
    meta = {
        "job_id": job_id,
        "created_at": datetime.now(jst).isoformat(),
        "source_type": source_type,
        "source_path": source_path,
        "original_name": original_name,
    }
    write_json_atomic(mp, meta)

    # Append an index line for quick discovery (best-effort)
    try:
        idx = Path(settings.work_dir) / "jobs.jsonl"
        with open(idx, "a", encoding="utf-8") as f:
            f.write(json.dumps(meta, ensure_ascii=False) + "\n")
    except Exception:
        pass


@app.post("/api/jobs")
async def create_job_upload(
    background: BackgroundTasks,
    file: UploadFile = File(...),
):
    # Save upload to temp, hash, then move into job dir
    tmp = Path(settings.work_dir) / ".uploads"
    tmp.mkdir(parents=True, exist_ok=True)
    tmp_path = tmp / file.filename
    data = await file.read()
    tmp_path.write_bytes(data)

    if not looks_like_pe(tmp_path):
        raise HTTPException(400, "not a PE file")

    job_id = sha256_file(tmp_path)
    paths = _job_paths(job_id)
    dest = paths["input"] / fs_safe_name(file.filename)
    dest.write_bytes(data)

    _write_job_meta(job_id=job_id, source_type="upload", source_path=None, original_name=file.filename)

    _spawn_extract(job_id, dest)

    return {"job_id": job_id}


@app.post("/api/jobs/by-path")
async def create_job_by_path(background: BackgroundTasks, path: str = Form(...)):
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise HTTPException(400, "path not found")

    if not looks_like_pe(p):
        raise HTTPException(400, "not a PE file")

    job_id = sha256_file(p)
    paths = _job_paths(job_id)
    dest = paths["input"] / fs_safe_name(p.name)
    if not dest.exists():
        dest.write_bytes(p.read_bytes())

    _write_job_meta(job_id=job_id, source_type="path", source_path=str(p), original_name=p.name)

    _spawn_extract(job_id, dest)

    return {"job_id": job_id}


def _run_extract(job_id: str, sample_path: Path, *, force: bool = False) -> None:
    # idempotent by default
    ap = _analysis_path(job_id)
    base = Path(settings.work_dir) / job_id
    status_path = base / "extract" / "status.json"

    if ap.exists() and not force:
        return

    # best-effort status marker
    try:
        jst = timezone(timedelta(hours=9))
        write_json_atomic(
            status_path,
            {
                "stage": "running",
                "started_at": datetime.now(jst).isoformat(),
                "job_id": job_id,
            },
        )
    except Exception:
        pass

    try:
        run_ghidra_extract(
            work_dir=settings.work_dir,
            job_id=job_id,
            sample_path=sample_path,
            analyze_headless=settings.ghidra_analyze_headless,
            scripts_dir=settings.ghidra_scripts_dir,
        )
        
        # Run CAPA (non-fatal if it fails)
        try:
            run_capa_analysis(
                work_dir=settings.work_dir,
                job_id=job_id,
                sample_path=sample_path,
            )
        except Exception as capa_err:
            # CAPA failed - not fatal, log and continue
            print(f"[extract] CAPA failed for {job_id}: {capa_err}")
        
        try:
            jst = timezone(timedelta(hours=9))
            write_json_atomic(
                status_path,
                {
                    "stage": "done",
                    "finished_at": datetime.now(jst).isoformat(),
                    "job_id": job_id,
                },
            )
        except Exception:
            pass
    except Exception as e:
        try:
            jst = timezone(timedelta(hours=9))
            write_json_atomic(
                status_path,
                {
                    "stage": "error",
                    "error": str(e),
                    "finished_at": datetime.now(jst).isoformat(),
                    "job_id": job_id,
                },
            )
        except Exception:
            pass
        raise


@app.get("/api/jobs/{job_id}/analysis")
async def get_analysis(job_id: str):
    ap = _analysis_path(job_id)
    if not ap.exists():
        return JSONResponse({"status": "analyzing"}, status_code=202)
    return JSONResponse(read_json(ap, {}))


@app.get("/api/jobs/{job_id}/memory/view")
async def get_memory_view(job_id: str, addr: str = Query(...), len: int = Query(0x200, ge=1, le=0x4000)):
    try:
        return JSONResponse(memory_view(job_id, addr, len))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "peek memory timeout")
    except subprocess.CalledProcessError:
        raise HTTPException(500, "peek memory failed; see extract/peekmem.log")
    except Exception as e:
        raise HTTPException(500, f"peek memory error: {e}")


@app.get("/api/jobs/{job_id}/capa")
async def get_capa(job_id: str):
    """Get CAPA malware capability detection results.

    CAPA sometimes emits warnings or non-JSON text; also capa.json may be empty if the run failed.
    This endpoint is tolerant and will return a structured error instead of 500.
    """
    capa_path = Path(settings.work_dir) / job_id / "extract" / "capa.json"
    if not capa_path.exists():
        raise HTTPException(404, "CAPA results not found")

    raw = capa_path.read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        return JSONResponse(
            {
                "error": "capa.json is empty",
                "hint": "Re-run re-extract to regenerate CAPA output. Check extract/capa.log for details.",
            },
            status_code=200,
        )

    # Try strict JSON parse first
    try:
        return JSONResponse(json.loads(raw))
    except Exception:
        pass

    # Try to recover JSON by locating the first '{'
    try:
        i = raw.find("{")
        if i >= 0:
            return JSONResponse(json.loads(raw[i:]))
    except Exception:
        pass

    # Fallback: return error + a preview for debugging
    return JSONResponse(
        {
            "error": "capa.json is not valid JSON",
            "preview": raw[:300],
            "hint": "Check extract/capa.log for the CAPA stderr output.",
        },
        status_code=200,
    )


@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: str):
    """Delete a job and all derived analysis artifacts.

    WARNING: destructive. Removes work_dir/{job_id} entirely.
    """

    base = Path(settings.work_dir) / job_id
    if not base.exists() or not base.is_dir():
        raise HTTPException(404, "job not found")

    try:
        shutil.rmtree(base)
    except Exception as e:
        raise HTTPException(500, f"delete failed: {e}")

    return {"status": "deleted", "job_id": job_id}


@app.post("/api/jobs/{job_id}/reextract")
async def reextract_job(job_id: str, background: BackgroundTasks):
    """Force re-run Ghidra extraction.

    This is needed when extraction scripts change (e.g. adding decompiler output).
    """

    base = Path(settings.work_dir) / job_id
    inp = base / "input"
    if not inp.exists():
        raise HTTPException(404, "job not found")

    # Choose a sample path from the input dir.
    files = [p for p in inp.iterdir() if p.is_file()]
    if not files:
        raise HTTPException(400, "no input file")

    sample = sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)[0]

    _spawn_extract(job_id, sample, force=True)
    return {"status": "queued"}


@app.get("/api/jobs")
async def list_jobs(limit: int = 50, q: str | None = None):
    """List recent jobs from the work_dir.

    Returns: {jobs: [{job_id, created_at, source_type, source_path, original_name, sample_path, analyzed}]}
    """
    work = Path(settings.work_dir)
    if not work.exists():
        return {"jobs": []}

    query = (q or "").strip().lower()

    jobs: list[dict[str, Any]] = []
    for d in work.iterdir():
        if not d.is_dir():
            continue
        jid = d.name
        if len(jid) != 64:
            continue

        meta = read_json(d / "meta.json", {})
        ap = d / "extract" / "analysis.json"
        analysis = read_json(ap, {}) if ap.exists() else {}
        sample_path = (analysis.get("sample") or {}).get("path")

        sp = d / "extract" / "status.json"
        st = read_json(sp, {}) if sp.exists() else {}
        stage = str(st.get("stage") or "").strip().lower()
        extracting = stage in ("running", "extracting")

        item = {
            "job_id": jid,
            "created_at": meta.get("created_at"),
            "source_type": meta.get("source_type"),
            "source_path": meta.get("source_path"),
            "original_name": meta.get("original_name"),
            "sample_path": sample_path,
            # analyzed should reflect finished extract; during re-extract show not analyzed
            "analyzed": bool(ap.exists() and stage == "done"),
            "extract_stage": stage or None,
            "mtime": d.stat().st_mtime,
        }

        if query:
            hay = " ".join(
                [
                    jid,
                    str(item.get("original_name") or ""),
                    str(item.get("source_path") or ""),
                    str(item.get("sample_path") or ""),
                ]
            ).lower()
            if query not in hay:
                continue

        jobs.append(item)

    jobs.sort(key=lambda x: float(x.get("mtime") or 0), reverse=True)
    for j in jobs:
        j.pop("mtime", None)

    limit = max(1, min(int(limit), 500))
    return {"jobs": jobs[:limit]}


def _extract_calls_from_disasm(text: str) -> set[str]:
    import re

    # Common Ghidra-ish symbols: FUN_1400..., sub_1400..., function_1400...
    hits = set(re.findall(r"\b(?:FUN|sub|function)_[0-9A-Fa-f]+\b", text))
    return hits


def _guess_main_function_id(job_id: str) -> dict[str, Any]:
    """Heuristically guess the program's 'main' function.

    This is best-effort. For Windows PE especially, there may be multiple CRT entry wrappers.
    Strategy:
    - Start from UI default (often 'entry')
    - Build a shallow call neighborhood from disasm
    - Prefer larger, non-trivial functions
    """

    analysis = read_json(_analysis_path(job_id), {})
    funcs = analysis.get("functions") or []
    sizes: dict[str, int] = {str(f.get("id")): int(f.get("size") or 0) for f in funcs if f.get("id")}

    entry_id = (analysis.get("ui") or {}).get("default_function_id") or "entry"

    disasm_dir = Path(settings.work_dir) / job_id / "extract" / "disasm"

    def read_disasm(fid: str) -> str:
        p = disasm_dir / f"{fid}.txt"
        if not p.exists():
            return ""
        try:
            return p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    # BFS depth 0..2 collecting candidates
    seen: set[str] = set()
    frontier: list[tuple[str, int]] = [(entry_id, 0)]
    candidates: dict[str, dict[str, Any]] = {}

    while frontier:
        fid, depth = frontier.pop(0)
        if fid in seen or depth > 2:
            continue
        seen.add(fid)

        txt = read_disasm(fid)
        calls = _extract_calls_from_disasm(txt)
        for callee in calls:
            # record callee as candidate
            if callee not in candidates:
                candidates[callee] = {
                    "function_id": callee,
                    "size": sizes.get(callee, 0),
                    "depth": depth + 1,
                }
            if depth + 1 < 2:
                frontier.append((callee, depth + 1))

    # score: prefer depth-1 calls (direct from entry) and larger size
    def score(c: dict[str, Any]) -> float:
        sz = float(c.get("size") or 0)
        d = int(c.get("depth") or 3)
        if sz < 64:
            return -1.0
        depth_weight = {1: 1.0, 2: 0.65, 3: 0.35}.get(d, 0.25)
        return sz * depth_weight

    ranked = sorted(candidates.values(), key=score, reverse=True)

    # If we didn't find any call target, fallback to the largest function in the binary.
    if not ranked:
        best = max(sizes.items(), key=lambda kv: kv[1], default=(entry_id, 0))
        return {
            "function_id": best[0],
            "reason": "fallback_largest_function",
            "entry_id": entry_id,
            "candidates": [],
        }

    best = ranked[0]
    return {
        "function_id": best["function_id"],
        "reason": "heuristic_from_entry_calls",
        "entry_id": entry_id,
        "candidates": ranked[:20],
    }


@app.get("/api/jobs/{job_id}/main")
async def guess_main(job_id: str):
    ap = _analysis_path(job_id)
    if not ap.exists():
        return JSONResponse({"status": "analyzing"}, status_code=202)
    return JSONResponse(_guess_main_function_id(job_id))


# Small in-memory file cache to avoid slow filesystem reads on rapid navigation.
# Keyed by (path, mtime_ns, size).
_FILE_CACHE: dict[tuple[str, int, int], bytes] = {}
_FILE_CACHE_MAX = 256


def _read_file_cached(path: Path) -> bytes:
    st = path.stat()
    key = (str(path), int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))), int(st.st_size))
    b = _FILE_CACHE.get(key)
    if b is not None:
        return b
    data = path.read_bytes()
    _FILE_CACHE[key] = data
    # best-effort prune
    if len(_FILE_CACHE) > _FILE_CACHE_MAX:
        try:
            for k in list(_FILE_CACHE.keys())[: len(_FILE_CACHE) - _FILE_CACHE_MAX]:
                _FILE_CACHE.pop(k, None)
        except Exception:
            pass
    return data


@app.get("/api/jobs/{job_id}/functions/{function_id}/disasm")
async def get_disasm(job_id: str, function_id: str):
    p = Path(settings.work_dir) / job_id / "extract" / "disasm" / f"{function_id}.txt"
    if not p.exists():
        raise HTTPException(404, "disasm not found")
    data = _read_file_cached(p)
    return Response(content=data, media_type="text/plain; charset=utf-8")


@app.get("/api/jobs/{job_id}/functions/{function_id}/ghidra")
async def get_ghidra_decompile(job_id: str, function_id: str):
    p = Path(settings.work_dir) / job_id / "extract" / "decomp" / f"{function_id}.c"
    if not p.exists():
        raise HTTPException(404, "ghidra decompile not found")
    data = _read_file_cached(p)
    return Response(content=data, media_type="text/plain; charset=utf-8")


@app.get("/api/jobs/{job_id}/functions/{function_id}")
async def get_ai_result(job_id: str, function_id: str):
    p = Path(settings.work_dir) / job_id / "ai" / "results" / f"{function_id}.json"
    if p.exists():
        return JSONResponse(read_json(p, {}))

    idx = Path(settings.work_dir) / job_id / "ai" / "index.json"
    index = read_json(idx, {})
    st = index.get(function_id, {"status": "not_started"})
    return JSONResponse({"function_id": function_id, **st})


@app.post("/api/jobs/{job_id}/functions/{function_id}/decompile")
async def enqueue_decompile(
    job_id: str,
    function_id: str,
    provider: str | None = Form(None),
    model: str | None = Form(None),
    openai_base_url: str | None = Form(None),
    openai_api_key: str | None = Form(None),
    openai_api_mode: str | None = Form(None),
    openai_reasoning: str | None = Form(None),
    guardrail_max_attempts: int | None = Form(None),
    guardrail_min_confidence: float | None = Form(None),
    force: bool = Form(False),
):
    """Enqueue (re)decompile for a function.

    - Default behavior: if already queued/running/ok, treat as cached/no-op.
    - force=true: always enqueue a new request and mark queued.
    """

    idxp = Path(settings.work_dir) / job_id / "ai" / "index.json"
    index = read_json(idxp, {})
    cur = index.get(function_id)

    # Never enqueue duplicates while a run is already queued/running.
    if cur and cur.get("status") in ("queued", "running"):
        return {"status": cur.get("status"), "cached": False}

    # If already ok and not forcing, treat as cached.
    if not force and cur and cur.get("status") == "ok":
        return {"status": cur.get("status"), "cached": True}

    # Mark queued (preserve any display fields we might already have)
    prev = cur if isinstance(cur, dict) else {}
    jst = timezone(timedelta(hours=9))

    index[function_id] = {
        **prev,
        "status": "queued",
        "queued_at": datetime.now(jst).isoformat(),
        "provider": provider,
        "model": model,
        "openai_base_url": openai_base_url,
        "openai_api_mode": openai_api_mode,
        "openai_reasoning": openai_reasoning,
        "guardrail_max_attempts": guardrail_max_attempts,
        "guardrail_min_confidence": guardrail_min_confidence,
        "force": bool(force),
    }
    write_json_atomic(idxp, index)

    enqueued_at = datetime.now(jst).isoformat()

    req = {
        "job_id": job_id,
        "function_id": function_id,
        "provider": provider,
        "model": model,
        "openai_base_url": openai_base_url,
        "openai_api_key": openai_api_key,
        "openai_api_mode": openai_api_mode,
        "openai_reasoning": openai_reasoning,
        "guardrail_max_attempts": guardrail_max_attempts,
        "guardrail_min_confidence": guardrail_min_confidence,
        "force": bool(force),
        "enqueued_at": enqueued_at,
    }
    qp = Path(settings.work_dir) / job_id / "queue" / "requests.jsonl"
    with open(qp, "a", encoding="utf-8") as f:
        f.write(json.dumps(req, ensure_ascii=False) + "\n")

    return {"status": "queued"}


@app.get("/api/jobs/{job_id}/functions/{function_id}/summary")
async def get_function_summary(job_id: str, function_id: str):
    p = Path(settings.work_dir) / job_id / "ai" / "summaries" / f"{function_id}.json"
    if p.exists():
        return JSONResponse(read_json(p, {}))

    idx = Path(settings.work_dir) / job_id / "ai" / "index.json"
    index = read_json(idx, {})
    st = index.get(function_id, {}) if isinstance(index.get(function_id), dict) else {}
    return JSONResponse({"function_id": function_id, "status": st.get("summary_status") or "not_started", **{k: v for k, v in st.items() if str(k).startswith('summary_')}})


@app.post("/api/jobs/{job_id}/functions/{function_id}/summarize")
async def enqueue_summarize(
    job_id: str,
    function_id: str,
    provider: str | None = Form(None),
    model: str | None = Form(None),
    openai_base_url: str | None = Form(None),
    openai_api_key: str | None = Form(None),
    openai_api_mode: str | None = Form(None),
    openai_reasoning: str | None = Form(None),
    guardrail_max_attempts: int | None = Form(None),
    guardrail_min_confidence: float | None = Form(None),
    force: bool = Form(False),
):
    """Enqueue summary_ja generation for a function (no pseudocode).

    Stores output in ai/summaries/{fid}.json and status in ai/index.json under summary_* keys.
    """

    idxp = Path(settings.work_dir) / job_id / "ai" / "index.json"
    index = read_json(idxp, {})
    cur = index.get(function_id) if isinstance(index.get(function_id), dict) else {}

    if cur and cur.get("summary_status") in ("queued", "running"):
        return {"status": cur.get("summary_status"), "cached": False}

    summ_path = Path(settings.work_dir) / job_id / "ai" / "summaries" / f"{function_id}.json"
    if not force and summ_path.exists():
        return {"status": "ok", "cached": True}

    jst = timezone(timedelta(hours=9))
    index[function_id] = {
        **cur,
        "summary_status": "queued",
        "summary_queued_at": datetime.now(jst).isoformat(),
        "summary_provider": provider,
        "summary_model": model,
    }
    write_json_atomic(idxp, index)

    enqueued_at = datetime.now(jst).isoformat()
    req = {
        "job_id": job_id,
        "function_id": function_id,
        "task": "summarize",
        "provider": provider,
        "model": model,
        "openai_base_url": openai_base_url,
        "openai_api_key": openai_api_key,
        "openai_api_mode": openai_api_mode,
        "openai_reasoning": openai_reasoning,
        "guardrail_max_attempts": guardrail_max_attempts,
        "guardrail_min_confidence": guardrail_min_confidence,
        "force": bool(force),
        "enqueued_at": enqueued_at,
    }
    qp = Path(settings.work_dir) / job_id / "queue" / "requests.jsonl"
    with open(qp, "a", encoding="utf-8") as f:
        f.write(json.dumps(req, ensure_ascii=False) + "\n")

    return {"status": "queued"}


@app.get("/api/jobs/{job_id}/exe_summary")
async def get_exe_summary(job_id: str):
    p = Path(settings.work_dir) / job_id / "ai" / "exe_summary.json"
    if not p.exists():
        return JSONResponse({"status": "not_started"})
    return JSONResponse(read_json(p, {}))


@app.get("/api/jobs/{job_id}/callgraph")
async def get_callgraph(
    job_id: str,
    root: str = Query(..., description="root function id"),
    depth: int = Query(3, ge=1, le=5),
):
    """Return a shallow call graph (calls_out) from root up to depth.

    Nodes include display_name and summary_ja if available.
    Summary source priority:
    1) ai/summaries/{fid}.json
    2) ai/results/{fid}.json (decompile result)
    """

    ap = _analysis_path(job_id)
    if not ap.exists():
        return JSONResponse({"status": "analyzing"}, status_code=202)

    analysis = read_json(ap, {})
    funcs = analysis.get("functions") or []
    func_by_id = {str(f.get("id")): f for f in funcs if f.get("id")}

    if root not in func_by_id:
        raise HTTPException(404, f"function not found: {root}")

    base = Path(settings.work_dir) / job_id

    def load_summary(fid: str) -> tuple[str | None, float | None, str | None]:
        sp = base / "ai" / "summaries" / f"{fid}.json"
        if sp.exists():
            obj = read_json(sp, {})
            sj = obj.get("summary_ja")
            conf = obj.get("confidence")
            return (
                sj if isinstance(sj, str) and sj.strip() else None,
                float(conf) if isinstance(conf, (int, float)) else None,
                "summaries",
            )
        rp = base / "ai" / "results" / f"{fid}.json"
        if rp.exists():
            obj = read_json(rp, {})
            sj = obj.get("summary_ja")
            conf = obj.get("confidence")
            return (
                sj if isinstance(sj, str) and sj.strip() else None,
                float(conf) if isinstance(conf, (int, float)) else None,
                "results",
            )
        return (None, None, None)

    # BFS up to depth
    nodes: dict[str, dict] = {}
    edges: set[tuple[str, str]] = set()

    q: list[tuple[str, int]] = [(root, 0)]
    seen: set[str] = set()

    while q:
        cur, d = q.pop(0)
        if cur in seen:
            continue
        seen.add(cur)

        f = func_by_id.get(cur) or {}
        sj, conf, src = load_summary(cur)

        nodes[cur] = {
            "id": cur,
            "name": f.get("name") or cur,
            "entry": f.get("entry"),
            "is_external": bool(f.get("is_external")),
            "is_winapi": bool(f.get("is_winapi")),
            "dll": f.get("dll"),
            "summary_ja": sj,
            "summary_confidence": conf,
            "summary_source": src,
        }

        if d >= depth:
            continue

        outs = f.get("calls_out") or []
        for callee in outs:
            cid = str(callee)
            edges.add((cur, cid))
            if cid not in seen:
                q.append((cid, d + 1))

    # ensure nodes exist for edge endpoints
    for a, b in list(edges):
        if b not in nodes:
            f = func_by_id.get(b)
            sj, conf, src = load_summary(b)
            nodes[b] = {
                "id": b,
                "name": (f or {}).get("name") or b,
                "entry": (f or {}).get("entry") if f else None,
                "is_external": bool((f or {}).get("is_external")) if f else True,
                "is_winapi": bool((f or {}).get("is_winapi")) if f else False,
                "dll": (f or {}).get("dll") if f else None,
                "summary_ja": sj,
                "summary_confidence": conf,
                "summary_source": src,
            }

    return {
        "job_id": job_id,
        "root": root,
        "depth": depth,
        "nodes": list(nodes.values()),
        "edges": [{"from": a, "to": b} for (a, b) in sorted(edges)],
    }


@app.post("/api/jobs/{job_id}/summarize_exe")
async def enqueue_summarize_exe(
    job_id: str,
    provider: str | None = Form(None),
    model: str | None = Form(None),
    openai_base_url: str | None = Form(None),
    openai_api_key: str | None = Form(None),
    openai_api_mode: str | None = Form(None),
    openai_reasoning: str | None = Form(None),
):
    """Generate/update EXE-level summary from stored per-function summaries."""
    jst = timezone(timedelta(hours=9))
    req = {
        "job_id": job_id,
        "function_id": "__exe__",
        "task": "summarize_exe",
        "provider": provider,
        "model": model,
        "openai_base_url": openai_base_url,
        "openai_api_key": openai_api_key,
        "openai_api_mode": openai_api_mode,
        "openai_reasoning": openai_reasoning,
        "enqueued_at": datetime.now(jst).isoformat(),
    }
    qp = Path(settings.work_dir) / job_id / "queue" / "requests.jsonl"
    with open(qp, "a", encoding="utf-8") as f:
        f.write(json.dumps(req, ensure_ascii=False) + "\n")
    return {"status": "queued"}


@app.get("/api/jobs/{job_id}/stream")
async def stream(job_id: str):
    idxp = Path(settings.work_dir) / job_id / "ai" / "index.json"

    async def gen():
        last = None
        while True:
            if idxp.exists():
                cur = idxp.read_text(encoding="utf-8")
                if cur != last:
                    last = cur
                    yield {"event": "function_status", "data": cur}
            await asyncio.sleep(1)

    return EventSourceResponse(gen())


@app.get("/api/debug/settings")
async def debug_settings():
    """Expose safe runtime settings (no secrets) for UI debugging."""

    # These come from .env but are not secret.
    return {
        "work_dir": settings.work_dir,
        "bind_host": settings.bind_host,
        "bind_port": settings.bind_port,
    }


@app.get("/api/tools/capa/status")
async def capa_status():
    """Return whether capa is installed and its version (if available)."""

    p = shutil.which("capa")
    if not p:
        return {"installed": False, "path": None}

    ver = None
    try:
        r = subprocess.run([p, "--version"], capture_output=True, text=True, timeout=5)
        if r.stdout:
            ver = r.stdout.strip().splitlines()[0]
        elif r.stderr:
            ver = r.stderr.strip().splitlines()[0]
    except Exception:
        ver = None

    return {"installed": True, "path": p, "version": ver}


@app.post("/api/tools/capa/install")
async def capa_install():
    """Install capa on the host (best-effort)."""

    # If already installed, just return status
    p = shutil.which("capa")
    if p:
        return {"ok": True, "installed": True, "path": p}

    script = Path(__file__).resolve().parents[1] / "install_capa.sh"
    if not script.exists():
        raise HTTPException(500, "install_capa.sh not found")

    try:
        r = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=300)
        out = (r.stdout or "") + ("\n" + r.stderr if r.stderr else "")
        ok = r.returncode == 0
        p2 = shutil.which("capa")
        return {"ok": ok, "installed": bool(p2), "path": p2, "output": out[-4000:]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "installed": False, "error": "install timeout"}
    except Exception as e:
        return {"ok": False, "installed": False, "error": str(e)}


@app.get("/api/jobs/{job_id}/debug/function/{function_id}")
async def debug_function(job_id: str, function_id: str):
    """Debug endpoint to inspect file status for a given function."""

    base = Path(settings.work_dir) / job_id
    disasm_path = base / "extract" / "disasm" / f"{function_id}.txt"
    out_path = base / "ai" / "results" / f"{function_id}.json"
    lock_path = base / "ai" / "locks" / f"{function_id}.lock"
    idx_path = base / "ai" / "index.json"
    q_path = base / "queue" / "requests.jsonl"

    def stat(p: Path):
        if not p.exists():
            return {"exists": False}
        try:
            st = p.stat()
            return {"exists": True, "size": st.st_size, "mtime": st.st_mtime}
        except Exception as e:
            return {"exists": True, "error": str(e)}

    index = read_json(idx_path, {})

    res = read_json(out_path, {}) if out_path.exists() else None
    disasm_head = None
    if disasm_path.exists():
        try:
            disasm_head = disasm_path.read_text(encoding="utf-8", errors="replace")[:400]
        except Exception:
            disasm_head = None

    return {
        "job_id": job_id,
        "function_id": function_id,
        "index": index.get(function_id),
        "paths": {
            "disasm": {"path": str(disasm_path), **stat(disasm_path)},
            "result": {"path": str(out_path), **stat(out_path)},
            "lock": {"path": str(lock_path), **stat(lock_path)},
            "queue": {"path": str(q_path), **stat(q_path)},
        },
        "result": res,
        "disasm_head": disasm_head,
    }


@app.get("/api/jobs/{job_id}/debug/queue")
async def debug_queue(job_id: str, n: int = 30):
    """Return last N queue entries for a job."""

    n = max(1, min(int(n), 500))
    q_path = Path(settings.work_dir) / job_id / "queue" / "requests.jsonl"
    if not q_path.exists():
        return {"job_id": job_id, "path": str(q_path), "lines": []}

    try:
        lines = q_path.read_text(encoding="utf-8", errors="replace").splitlines()
        tail = lines[-n:]
        parsed = []
        for line in tail:
            line = line.strip()
            if not line:
                continue
            try:
                parsed.append(json.loads(line))
            except Exception:
                parsed.append({"_raw": line})
        return {"job_id": job_id, "path": str(q_path), "lines": parsed}
    except Exception as e:
        return {"job_id": job_id, "path": str(q_path), "error": str(e), "lines": []}


@app.get("/api/jobs/{job_id}/debug/extract")
async def debug_extract(job_id: str, tail: int = 200):
    """Return extract status + tail of ghidra.log (if any)."""

    tail = max(0, min(int(tail), 2000))
    base = Path(settings.work_dir) / job_id / "extract"
    sp = base / "status.json"
    lp = base / "ghidra.log"

    status = read_json(sp, {}) if sp.exists() else {"stage": "unknown"}

    log_tail: list[str] = []
    if lp.exists() and tail:
        try:
            lines = lp.read_text(encoding="utf-8", errors="replace").splitlines()
            log_tail = lines[-tail:]
        except Exception as e:
            log_tail = [f"<failed to read log: {e}>"]

    return {
        "job_id": job_id,
        "status": status,
        "paths": {
            "status": str(sp),
            "log": str(lp),
        },
        "log_tail": log_tail,
    }


@app.get("/api/jobs/{job_id}/debug/logs")
async def debug_logs(job_id: str, n: int = 200):
    """Return last N LLM log entries for a job."""

    n = max(1, min(int(n), 2000))
    lp = Path(settings.work_dir) / job_id / "ai" / "logs" / "llm.jsonl"
    if not lp.exists():
        lp = Path(settings.work_dir) / job_id / "ai" / "logs" / "anthropic.jsonl"  # backward compat
    if not lp.exists():
        return {"job_id": job_id, "path": str(lp), "lines": []}

    try:
        lines = lp.read_text(encoding="utf-8", errors="replace").splitlines()
        tail = lines[-n:]
        parsed: list[Any] = []
        for line in tail:
            line = line.strip()
            if not line:
                continue
            try:
                parsed.append(json.loads(line))
            except Exception:
                parsed.append({"_raw": line})
        return {"job_id": job_id, "path": str(lp), "lines": parsed}
    except Exception as e:
        return {"job_id": job_id, "path": str(lp), "error": str(e), "lines": []}


@app.get("/api/jobs/{job_id}/debug/logs/stream")
async def debug_logs_stream(job_id: str, tail: int = 200):
    """Stream LLM log entries (Anthropic/OpenAI-compatible) as SSE."""

    tail = max(0, min(int(tail), 2000))
    lp = Path(settings.work_dir) / job_id / "ai" / "logs" / "llm.jsonl"
    if not lp.exists():
        lp = Path(settings.work_dir) / job_id / "ai" / "logs" / "anthropic.jsonl"  # backward compat

    async def gen():
        last_size = 0
        if lp.exists():
            try:
                if tail > 0:
                    # send last N lines as init
                    lines = lp.read_text(encoding="utf-8", errors="replace").splitlines()
                    for line in lines[-tail:]:
                        line = line.strip()
                        if not line:
                            continue
                        yield {"event": "log", "data": line}
                last_size = lp.stat().st_size
            except Exception:
                last_size = 0

        while True:
            if lp.exists():
                try:
                    cur_size = lp.stat().st_size
                    if cur_size < last_size:
                        last_size = 0
                    if cur_size > last_size:
                        with open(lp, "rb") as f:
                            f.seek(last_size)
                            data = f.read()
                            last_size = f.tell()
                        for line in data.decode("utf-8", errors="replace").splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            yield {"event": "log", "data": line}
                except Exception:
                    pass
            await asyncio.sleep(0.5)

    return EventSourceResponse(gen())


# -----------------
# Chat Assistant API
# -----------------


class ChatMessage(BaseModel):
    role: str
    content: str
    name: str | None = None
    tool_call_id: str | None = None


class ChatRequest(BaseModel):
    job_id: str
    message: str
    history: list[ChatMessage] = []
    model: str | None = None
    provider: str | None = None  # currently only openai-compatible is implemented
    base_url: str | None = None  # Override OPENAI_BASE_URL from Settings
    api_key: str | None = None   # Override OPENAI_API_KEY from Settings


@app.post("/api/chat")
async def chat(req: ChatRequest):
    """Interactive chat endpoint with 2-phase tool calling.

    Phase 1: LLM selects tools to use (JSON output)
    Phase 2: Execute tools and generate final answer
    """

    job_id = req.job_id
    user_msg = (req.message or "").strip()
    if not user_msg:
        raise HTTPException(400, "message is required")

    provider = (req.provider or os.getenv("AUTORE_CHAT_PROVIDER") or "openai").strip().lower()

    # Build history list
    hist = [m.model_dump() for m in (req.history or [])]
    
    # GUARD 2: Session state management (multi-step exploration)
    import time
    
    # Reset session if history is empty (user cleared chat)
    if not hist or len(hist) == 0:
        chat_sessions[job_id] = {
            "step_count": 0,
            "active_function_id": None,
            "last_updated": time.time(),
        }
    
    if job_id not in chat_sessions:
        chat_sessions[job_id] = {
            "step_count": 0,
            "active_function_id": None,
            "last_updated": time.time(),
        }
    
    session = chat_sessions[job_id]
    session["last_updated"] = time.time()

    # GUARD 2: Step limit (max 200 ReAct iterations per session)
    MAX_STEPS = 200
    if session["step_count"] >= MAX_STEPS:
        return {
            "job_id": job_id,
            "model": "guard",
            "provider": provider,
            "reply": f"【Step Limit Reached】\n\nステップ上限（{MAX_STEPS}手）に到達しました。\n\n【Needs Review】\n次に調査すべき内容を整理してから、新しいチャットセッションを開始してください。\n\nヒント: 🗑️ボタンでチャット履歴をクリアすると、ステップカウンターもリセットされます。",
            "tool_results": [],
            "ui_actions": [],
            "debug": {"step_count": session["step_count"], "max_steps": MAX_STEPS, "step_limit_reached": True},
        }

    if provider in ("openai", "openai-compatible", "oai"):
        openai_base = req.base_url or os.getenv("OPENAI_BASE_URL")
        openai_key = req.api_key or os.getenv("OPENAI_API_KEY")
        if not openai_base:
            raise HTTPException(400, "OPENAI_BASE_URL is not set (Settings or .env)")

        model = req.model or os.getenv("OPENAI_MODEL_DEFAULT", "gpt-oss-120b")

        # ===== ReAct Loop: plan -> act -> observe -> verify (max 12 steps) =====
        def _parse_json_maybe(md: str) -> dict:
            text = (md or "").strip()
            if text.startswith("```"):
                lines = text.split("\n")
                json_lines = []
                in_block = False
                for line in lines:
                    if line.strip().startswith("```"):
                        if in_block:
                            break
                        in_block = True
                        continue
                    if in_block:
                        json_lines.append(line)
                text = "\n".join(json_lines).strip()
            return json.loads(text)

        debug_trace: list[dict] = []
        all_tool_results: list[dict] = []
        last_plan: str = ""

        # Shared state context injected into planner/verifier
        def _state_context() -> str:
            ctx = f"\n\n【Current State】\nStep: {session['step_count']}/{MAX_STEPS}"
            if session.get("active_function_id"):
                ctx += f"\nActive function: {session['active_function_id']}"
            if session["step_count"] >= 10:
                ctx += f"\n⚠️ WARNING: Approaching step limit ({session['step_count']}/{MAX_STEPS}). Prioritize critical investigations."
            return ctx

        # Run up to remaining steps in this request until verifier says done
        while session["step_count"] < MAX_STEPS:
            # ===== Planner =====
            planner_prompt = SYSTEM_PROMPT_REACT_PLANNER + "\n\n" + TOOL_DESCRIPTIONS + _state_context()
            planner_messages = [
                {"role": "system", "content": planner_prompt},
                {"role": "user", "content": f"User question: {user_msg}\n\nPlan next 1-3 tool calls only. JSON only."},
            ]
            resp_p = call_openai_compatible(
                base_url=openai_base,
                api_key=openai_key,
                model=model,
                messages=planner_messages,
                tools=None,
                tool_choice=None,
            )
            msg_p = ((resp_p.get("choices") or [{}])[0].get("message") or {})
            raw_plan = (msg_p.get("content") or "").strip()
            try:
                plan_obj = _parse_json_maybe(raw_plan)
            except Exception as e:
                debug_trace.append({"planner_error": str(e), "raw": raw_plan[:200]})
                plan_obj = {"plan": "parse_failed", "tool_calls": []}

            last_plan = str(plan_obj.get("plan") or "")
            tool_calls = plan_obj.get("tool_calls") or []
            if len(tool_calls) > 3:
                tool_calls = tool_calls[:3]

            debug_trace.append({"planner": {"plan": last_plan, "tool_calls": tool_calls}})

            # If planner decides no tools, break and answer directly
            if not tool_calls:
                break

            # ===== Executor (tools only) =====
            step_tool_results: list[dict] = []
            for tc in tool_calls:
                tool_name = tc.get("tool")
                tool_args = tc.get("args", {})
                try:
                    result = dispatch_tool_v2(settings.work_dir, job_id, tool_name, tool_args)
                    step_tool_results.append({"tool": tool_name, "args": tool_args, "result": result})
                    # state sync
                    if tool_name in ("get_function_code", "get_function_overview", "run_ai_decompile"):
                        fid = tool_args.get("function_id")
                        if fid:
                            session["active_function_id"] = fid
                except Exception as e:
                    step_tool_results.append({"tool": tool_name, "args": tool_args, "error": str(e)})

            all_tool_results.extend(step_tool_results)
            session["step_count"] += 1

            # ===== Verifier =====
            verifier_prompt = SYSTEM_PROMPT_REACT_VERIFIER + "\n\n" + TOOL_DESCRIPTIONS + _state_context()
            verifier_messages = [
                {"role": "system", "content": verifier_prompt},
                {"role": "user", "content": "User question: " + user_msg + "\n\nObserved tool results:\n" + json.dumps(step_tool_results, ensure_ascii=False, indent=2) + "\n\nDecide if done. If not, request next 1-3 tool calls as JSON."},
            ]
            resp_v = call_openai_compatible(
                base_url=openai_base,
                api_key=openai_key,
                model=model,
                messages=verifier_messages,
                tools=None,
                tool_choice=None,
            )
            msg_v = ((resp_v.get("choices") or [{}])[0].get("message") or {})
            raw_v = (msg_v.get("content") or "").strip()
            try:
                ver_obj = _parse_json_maybe(raw_v)
            except Exception as e:
                debug_trace.append({"verifier_error": str(e), "raw": raw_v[:200]})
                ver_obj = {"done": False, "verdict": "parse_failed", "missing": ["verifier_json"], "next_tool_calls": []}

            debug_trace.append({"verifier": ver_obj})

            if ver_obj.get("done") is True:
                break

            # If verifier requests next_tool_calls, we will loop again;
            # merge into next planner step by rewriting user_msg? keep same question.
            # (Planner will re-plan from scratch next iteration.)
            continue

        tool_results = all_tool_results

        # ===== Phase 3: Final Answer =====
        final_answer_messages = [{"role": "system", "content": SYSTEM_PROMPT_FINAL_ANSWER}]
        
        # Add history
        for m in hist:
            role = m.get("role")
            if role in ("user", "assistant"):
                final_answer_messages.append({"role": role, "content": m.get("content", "")})
        
        # Add current user message + tool results
        if tool_results:
            # Tool results available - AI MUST cite these in Evidence-First format
            user_content_with_tools = f"""User question: {user_msg}

=== TOOL RESULTS (YOU MUST USE THESE) ===
{json.dumps(tool_results, ensure_ascii=False, indent=2)}

=== INSTRUCTIONS ===
Answer in Evidence-First format:
1. 【Evidence】- List facts from tool results (addresses, function names, exact quotes)
2. 【Unknowns】- What you DON'T know yet
3. 【Needs Review】- What to investigate next
4. 【結論】- Brief conclusion based ONLY on Evidence

Do NOT fabricate. Only use information from tool results above."""
        else:
            # No tools called - general question
            user_content_with_tools = f"User question: {user_msg}\n\n(No tool results - this is a general question. Answer directly in Japanese.)"
        
        final_answer_messages.append({"role": "user", "content": user_content_with_tools})

        resp2 = call_openai_compatible(
            base_url=openai_base,
            api_key=openai_key,
            model=model,
            messages=final_answer_messages,
            tools=None,
            tool_choice=None,
        )

        choice2 = (resp2.get("choices") or [{}])[0]
        msg2 = choice2.get("message") or {}
        reply = (msg2.get("content") or "").strip() or "(no response)"

        # Build debug info
        debug_info = {
            "thought": last_plan,
            "tool_calls_requested": [
                {"tool": tr.get("tool"), "args": tr.get("args")} for tr in tool_results
            ],
            "tool_count": len(tool_results),
            "step_count": session["step_count"],
            "max_steps": MAX_STEPS,
            "active_function_id": session.get("active_function_id"),
            "react_trace": debug_trace,
        }

        return {
            "job_id": job_id,
            "model": model,
            "provider": provider,
            "reply": reply,
            "tool_results": tool_results,
            "ui_actions": [],
            "debug": debug_info,
        }

    if provider in ("anthropic", "claude"):
        raise HTTPException(400, "Anthropic provider not yet implemented for v2 tools")

    raise HTTPException(400, f"Unknown provider: {provider}")


class NoCacheStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope) -> Response:
        resp = await super().get_response(path, scope)
        # Avoid stale UI during rapid iteration: always revalidate HTML.
        # Assets are fingerprinted by Vite, so caching them is fine.
        if path == "" or path.endswith(".html"):
            resp.headers["Cache-Control"] = "no-store"
        return resp


# Serve built frontend (A: single-port deployment)
# Mount AFTER /api routes so /api isn't shadowed.
_frontend_dist = Path(__file__).resolve().parents[1] / "frontend" / "dist"
if _frontend_dist.exists():
    app.mount("/", NoCacheStaticFiles(directory=str(_frontend_dist), html=True), name="ui")
