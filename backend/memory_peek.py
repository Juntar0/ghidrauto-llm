from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .config import load_settings
from .storage import ensure_job_dirs, read_json


# In-memory cache: (job_id, va, len) -> response dict
_MEM_CACHE: dict[tuple[str, int, int], dict[str, Any]] = {}
_MEM_CACHE_MAX = 512


def _normalize_va(addr: str) -> int:
    s = (addr or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = s.replace("_", "")
    if not s or any(c not in "0123456789abcdef" for c in s):
        raise ValueError("addr must be hex VA (e.g. 0x140003000)")
    return int(s, 16)


def memory_view(job_id: str, addr: str, length: int) -> dict[str, Any]:
    settings = load_settings()
    paths = ensure_job_dirs(settings.work_dir, job_id)

    va = _normalize_va(addr)
    ln = int(length)
    if ln <= 0:
        ln = 0x200
    ln = max(1, min(ln, 0x4000))

    key = (job_id, va, ln)
    cached = _MEM_CACHE.get(key)
    if cached is not None:
        return cached

    # Use existing project created by extract.
    project_root = paths["base"] / "ghidra_project"
    if not project_root.exists():
        raise FileNotFoundError("ghidra project not found; run extract first")
    project_name = "proj"

    out_json = paths["extract"] / f"mem_{va:016x}_{ln}.json"
    log_path = paths["extract"] / "peekmem.log"

    # Get program name from meta.json
    meta_path = paths["base"] / "meta.json"
    meta = read_json(meta_path, {})
    program_name = meta.get("original_name", "sample.exe")

    # -process: specify program name so currentProgram is set.
    # -noanalysis skips heavy re-analysis; script just reads memory.
    cmd = [
        settings.ghidra_analyze_headless,
        str(project_root),
        project_name,
        "-process",
        program_name,
        "-noanalysis",
        "-scriptPath",
        settings.ghidra_scripts_dir,
        "-postScript",
        "PeekMemory.java",
        str(out_json),
        f"0x{va:x}",
        str(ln),
    ]

    env = os.environ.copy()
    env.pop("JAVA_HOME", None)

    # Run headless peek
    with open(log_path, "a", encoding="utf-8", errors="replace") as log:
        subprocess.run(cmd, check=True, env=env, timeout=120, stdout=log, stderr=subprocess.STDOUT)

    if not out_json.exists():
        # Read log tail for a useful error message
        log_tail = ""
        try:
            log_tail = log_path.read_text(encoding="utf-8", errors="replace")[-800:]
        except Exception:
            pass
        raise RuntimeError(f"PeekMemory did not produce output. log tail:\n{log_tail}")

    obj = read_json(out_json, {})
    # Basic shape validation
    if not isinstance(obj, dict) or "bytes_b64" not in obj:
        log_tail = ""
        try:
            log_tail = log_path.read_text(encoding="utf-8", errors="replace")[-800:]
        except Exception:
            pass
        raise RuntimeError(f"peek memory failed (bad output). log tail:\n{log_tail}")

    # Ensure bytes_b64 is valid base64 (defensive)
    try:
        base64.b64decode(str(obj.get("bytes_b64") or ""), validate=False)
    except Exception:
        raise RuntimeError("invalid bytes_b64 from PeekMemory")

    resp = {
        "job_id": job_id,
        "va": obj.get("va") or f"0x{va:x}",
        "len": int(obj.get("len") or ln),
        "bytes_b64": obj.get("bytes_b64"),
        "arch": obj.get("arch"),
        "ptr_size": obj.get("ptr_size"),
        "annotations": obj.get("annotations") or {},
        "error": obj.get("error"),
    }

    _MEM_CACHE[key] = resp
    if len(_MEM_CACHE) > _MEM_CACHE_MAX:
        # best-effort prune
        for k in list(_MEM_CACHE.keys())[: len(_MEM_CACHE) - _MEM_CACHE_MAX]:
            _MEM_CACHE.pop(k, None)

    return resp
