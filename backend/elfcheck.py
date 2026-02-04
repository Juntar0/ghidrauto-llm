from __future__ import annotations

from pathlib import Path


def looks_like_elf(path: str | Path) -> bool:
    p = Path(path)
    try:
        data = p.read_bytes()
    except Exception:
        return False
    if len(data) < 4:
        return False
    return data[0:4] == b"\x7fELF"
