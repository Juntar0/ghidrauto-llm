from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .storage import ensure_job_dirs


def _run_analyze_headless(
    *,
    analyze_headless: str,
    project_root: Path,
    project_name: str,
    scripts_dir: str,
    args: list[str],
    timeout_seconds: int,
    log_path: Path,
) -> None:
    env = os.environ.copy()
    env.pop("JAVA_HOME", None)

    cmd = [
        analyze_headless,
        str(project_root),
        project_name,
        *args,
        "-scriptPath",
        scripts_dir,
    ]

    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        subprocess.run(cmd, check=True, env=env, timeout=timeout_seconds, stdout=log, stderr=subprocess.STDOUT)

    try:
        txt = log_path.read_text(encoding="utf-8", errors="replace")
        if "REPORT SCRIPT ERROR" in txt or "GhidraScriptLoadException" in txt:
            raise RuntimeError("Ghidra postScript failed; see ghidra.log")
    except Exception:
        pass


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

    # Capture ghidra output for debugging/progress.
    log_path = paths["extract"] / "ghidra.log"

    _run_analyze_headless(
        analyze_headless=analyze_headless,
        project_root=project_root,
        project_name=project_name,
        scripts_dir=scripts_dir,
        timeout_seconds=timeout_seconds,
        log_path=log_path,
        args=[
            "-import",
            str(dest),
            "-overwrite",
            "-postScript",
            "ExtractAnalysis.java",
            str(paths["extract"] / "analysis.json"),
            str(paths["disasm"]),
            str(paths["decomp"]),
            str(paths["pcode"]),
            str(paths["extract"] / "status.json"),
        ],
    )

    # Ensure analysis.json exists (postScript responsibility).
    ap = paths["extract"] / "analysis.json"
    if not ap.exists():
        raise RuntimeError("analysis.json missing after extract; see ghidra.log")


def run_capa_analysis(
    *,
    work_dir: str,
    job_id: str,
    sample_path: Path,
    timeout_seconds: int = 300,
) -> None:
    """Run CAPA malware capability detection and save results to capa.json.
    
    Non-fatal: if CAPA is not installed or fails, we skip it (Ghidra results are still valid).
    """
    paths = ensure_job_dirs(work_dir, job_id)
    capa_json = paths["extract"] / "capa.json"
    
    # Check if capa is installed
    try:
        result = subprocess.run(["which", "capa"], capture_output=True, timeout=5)
        if result.returncode != 0:
            # CAPA not installed - skip
            capa_json.write_text(json.dumps({"error": "capa not installed", "installed": False}))
            return
    except Exception:
        capa_json.write_text(json.dumps({"error": "capa check failed", "installed": False}))
        return
    
    # Run CAPA
    # Note: CAPA uses -j (not --json) and outputs to stdout
    cmd = [
        "capa",
        str(sample_path),
        "-j",
    ]
    
    log_path = paths["extract"] / "capa.log"
    try:
        # Capture JSON output to file, stderr to log
        with open(capa_json, "w", encoding="utf-8", errors="replace") as out:
            with open(log_path, "w", encoding="utf-8", errors="replace") as log:
                subprocess.run(
                    cmd,
                    check=True,
                    timeout=timeout_seconds,
                    stdout=out,
                    stderr=log,
                )
    except subprocess.TimeoutExpired:
        capa_json.write_text(json.dumps({"error": "capa timeout", "timeout": timeout_seconds}))
    except subprocess.CalledProcessError as e:
        # CAPA failed (possibly unsupported file format)
        capa_json.write_text(json.dumps({"error": f"capa failed with exit code {e.returncode}"}))
    except Exception as e:
        capa_json.write_text(json.dumps({"error": str(e)}))
    
    # Verify output exists and looks non-empty
    try:
        if not capa_json.exists():
            capa_json.write_text(json.dumps({"error": "capa.json not created"}))
            return
        if capa_json.stat().st_size == 0:
            # If CAPA produced nothing on stdout, provide a helpful error.
            err_preview = ""
            try:
                if log_path.exists():
                    err_preview = log_path.read_text(encoding="utf-8", errors="replace")[:300]
            except Exception:
                err_preview = ""
            capa_json.write_text(
                json.dumps(
                    {
                        "error": "capa produced empty output",
                        "hint": "See extract/capa.log for details",
                        "log_preview": err_preview,
                    }
                )
            )
    except Exception:
        # Never fail the extract pipeline due to CAPA validation
        pass
