"""Standalone extraction worker.

Purpose:
- Run heavy Ghidra/CAPA extraction outside the uvicorn request worker.
- Prevent UI browsing endpoints (disasm/ghidra/summary/etc) from stalling while extract runs.

Usage:
  python3 -m backend.extract_worker <job_id> <sample_path> [--force]

This script writes the same status markers as the in-process extract.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import load_settings
from .extractor import run_capa_analysis, run_ghidra_extract
from .storage import write_json_atomic


def analysis_path(work_dir: str, job_id: str) -> Path:
    return Path(work_dir) / job_id / "extract" / "analysis.json"


def run_extract(job_id: str, sample_path: Path, *, force: bool = False) -> None:
    settings = load_settings()
    ap = analysis_path(settings.work_dir, job_id)
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("job_id")
    ap.add_argument("sample_path")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    run_extract(args.job_id, Path(args.sample_path), force=bool(args.force))


if __name__ == "__main__":
    main()
