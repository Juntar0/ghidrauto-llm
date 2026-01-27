from __future__ import annotations

import os
from dataclasses import dataclass


def _load_dotenv() -> None:
    if os.path.exists(".env"):
        try:
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
        except Exception:
            pass


@dataclass(frozen=True)
class Settings:
    work_dir: str
    bind_host: str
    bind_port: int
    ghidra_analyze_headless: str
    ghidra_scripts_dir: str


def load_settings() -> Settings:
    _load_dotenv()
    from pathlib import Path
    repo_dir = Path(__file__).parent.parent
    return Settings(
        work_dir=os.getenv("AUTORE_WORK_DIR", str(repo_dir / "work")),
        bind_host=os.getenv("AUTORE_BIND_HOST", "0.0.0.0"),
        bind_port=int(os.getenv("AUTORE_BIND_PORT", "5555")),
        ghidra_analyze_headless=os.getenv(
            "GHIDRA_ANALYZE_HEADLESS", "/usr/local/bin/analyzeHeadless"
        ),
        ghidra_scripts_dir=os.getenv(
            "GHIDRA_SCRIPTS_DIR", str(repo_dir / "ghidra_scripts")
        ),
    )


cfg = load_settings()
