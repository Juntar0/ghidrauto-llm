from __future__ import annotations

from pathlib import Path


def looks_like_pe(path: str | Path) -> bool:
    p = Path(path)
    try:
        data = p.read_bytes()
    except Exception:
        return False
    if len(data) < 0x100:
        return False
    if data[0:2] != b"MZ":
        return False
    # e_lfanew at 0x3c
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little", signed=False)
    if e_lfanew <= 0 or e_lfanew + 4 > len(data):
        return False
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return False
    return True
