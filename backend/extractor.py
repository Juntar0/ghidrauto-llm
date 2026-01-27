from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .storage import ensure_job_dirs


def run_ghidra_extract(
    *,
    work_dir: str,
    job_id: str,
    sample_path: Path,
    analyze_headless: str,
    scripts_dir: str,
    timeout_seconds: int = 1800,
) -> None:
    paths = ensure_job_dirs(work_dir, job_id)
    project_root = paths["base"] / "ghidra_project"
    # If a previous run left a lock/project, reset it for idempotence.
    if project_root.exists():
        lock = project_root / "proj.lock"
        if lock.exists():
            shutil.rmtree(project_root, ignore_errors=True)
    project_root.mkdir(parents=True, exist_ok=True)

    # Copy input into job dir (stable path)
    dest = paths["input"] / sample_path.name
    if dest.resolve() != sample_path.resolve():
        shutil.copy2(sample_path, dest)

    project_name = "proj"

    cmd = [
        analyze_headless,
        str(project_root),
        project_name,
        "-import",
        str(dest),
        "-overwrite",
        "-scriptPath",
        scripts_dir,
        "-postScript",
        "ExtractAnalysis.java",
        str(paths["extract"] / "analysis.json"),
        str(paths["disasm"]),
        str(paths["decomp"]),
        str(paths["pcode"]),
        str(paths["extract"] / "status.json"),
    ]

    env = os.environ.copy()
    # Force empty JAVA_HOME so Ghidra auto-detects Java (instead of prompting)
    env["JAVA_HOME"] = ""

    # Capture ghidra output for debugging/progress.
    log_path = paths["extract"] / "ghidra.log"
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        subprocess.run(cmd, check=True, env=env, timeout=timeout_seconds, stdout=log, stderr=subprocess.STDOUT)

    # Ghidra sometimes exits 0 even if the postScript failed (it logs an ERROR).
    # Treat that as a failure so the UI can surface it.
    try:
        txt = log_path.read_text(encoding="utf-8", errors="replace")
        if "REPORT SCRIPT ERROR" in txt or "GhidraScriptLoadException" in txt:
            raise RuntimeError("Ghidra postScript failed; see ghidra.log")
    except Exception:
        # If we can't read the log, don't mask the extract success.
        pass

    # Ensure analysis.json exists (postScript responsibility).
    ap = paths["extract"] / "analysis.json"
    if not ap.exists():
        raise RuntimeError("analysis.json missing after extract; see ghidra.log")
