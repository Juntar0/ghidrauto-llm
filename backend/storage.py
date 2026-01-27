from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def job_dir(work_dir: str, job_id: str) -> Path:
    return Path(work_dir) / job_id


def ensure_job_dirs(work_dir: str, job_id: str) -> dict[str, Path]:
    base = job_dir(work_dir, job_id)
    paths = {
        "base": base,
        "input": base / "input",
        "extract": base / "extract",
        "disasm": base / "extract" / "disasm",
        "decomp": base / "extract" / "decomp",
        "pcode": base / "extract" / "pcode",
        "ai": base / "ai",
        "ai_results": base / "ai" / "results",
        "queue": base / "queue",
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)
    # init index.json
    idx = paths["ai"] / "index.json"
    if not idx.exists():
        idx.write_text("{}", encoding="utf-8")
    # init requests log
    req = paths["queue"] / "requests.jsonl"
    if not req.exists():
        req.write_text("", encoding="utf-8")
    return paths


def fs_safe_name(name: str) -> str:
    import re

    return re.sub(r"[^A-Za-z0-9_\-\.]+", "_", name)


def write_json_atomic(path: Path, obj: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def write_text_atomic(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding=encoding)
    os.replace(tmp, path)


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))
