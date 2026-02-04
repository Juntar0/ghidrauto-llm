from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Section:
    name: str
    va: int
    vsz: int
    raw: int
    rawsz: int


def _u16(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o+2], 'little', signed=False)


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o+4], 'little', signed=False)


def _read_cstr(b: bytes, o: int) -> str:
    end = b.find(b'\x00', o)
    if end == -1:
        end = min(len(b), o + 256)
    try:
        return b[o:end].decode('ascii', errors='replace')
    except Exception:
        return ''


def _rva_to_off(rva: int, sections: list[Section]) -> int | None:
    for s in sections:
        start = s.va
        end = s.va + max(s.vsz, s.rawsz)
        if start <= rva < end:
            return s.raw + (rva - s.va)
    return None


def parse_pe_exports(path: str | Path, limit: int = 500) -> dict[str, Any]:
    """Parse PE export table (no external deps).

    Supports PE32 and PE32+.
    Returns a dict with dll_name and exports.
    """
    p = Path(path)
    data = p.read_bytes()
    if len(data) < 0x100 or data[0:2] != b'MZ':
        raise ValueError('not a PE')

    e_lfanew = _u32(data, 0x3C)
    if e_lfanew <= 0 or e_lfanew + 4 > len(data):
        raise ValueError('bad e_lfanew')
    if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        raise ValueError('not a PE')

    file_hdr_off = e_lfanew + 4
    opt_off = file_hdr_off + 20
    if opt_off + 2 > len(data):
        raise ValueError('bad headers')

    num_sections = _u16(data, file_hdr_off + 2)
    opt_size = _u16(data, file_hdr_off + 16)

    magic = _u16(data, opt_off)
    is_pe32_plus = (magic == 0x20B)

    # Data directory starts at fixed offset in optional header
    # PE32: 96 bytes, PE32+: 112 bytes
    dd_off = opt_off + (112 if is_pe32_plus else 96)
    if dd_off + 8 > len(data):
        raise ValueError('bad data directory')

    export_rva = _u32(data, dd_off + 0)
    export_size = _u32(data, dd_off + 4)

    # Section table
    sec_off = opt_off + opt_size
    sections: list[Section] = []
    for i in range(num_sections):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        name = data[o:o+8].split(b'\x00', 1)[0].decode('ascii', errors='replace')
        vsz = _u32(data, o + 8)
        va = _u32(data, o + 12)
        rawsz = _u32(data, o + 16)
        raw = _u32(data, o + 20)
        sections.append(Section(name=name, va=va, vsz=vsz, raw=raw, rawsz=rawsz))

    if export_rva == 0 or export_size == 0:
        return {"dll_name": None, "exports": []}

    exp_off = _rva_to_off(export_rva, sections)
    if exp_off is None or exp_off + 40 > len(data):
        return {"dll_name": None, "exports": [], "error": "export directory not mapped"}

    # IMAGE_EXPORT_DIRECTORY
    name_rva = _u32(data, exp_off + 12)
    base = _u32(data, exp_off + 16)
    num_funcs = _u32(data, exp_off + 20)
    num_names = _u32(data, exp_off + 24)
    addr_funcs_rva = _u32(data, exp_off + 28)
    addr_names_rva = _u32(data, exp_off + 32)
    addr_ord_rva = _u32(data, exp_off + 36)

    dll_name = None
    name_off = _rva_to_off(name_rva, sections)
    if name_off is not None:
        dll_name = _read_cstr(data, name_off)

    funcs_off = _rva_to_off(addr_funcs_rva, sections)
    names_off = _rva_to_off(addr_names_rva, sections)
    ord_off = _rva_to_off(addr_ord_rva, sections)
    if funcs_off is None or names_off is None or ord_off is None:
        return {"dll_name": dll_name, "exports": [], "error": "export arrays not mapped"}

    exports: list[dict[str, Any]] = []

    # Build name->ordinal map
    max_names = min(num_names, limit)
    for i in range(max_names):
        n_rva = _u32(data, names_off + i * 4)
        n_off = _rva_to_off(n_rva, sections)
        nm = _read_cstr(data, n_off) if n_off is not None else ""
        ord_idx = _u16(data, ord_off + i * 2)
        if ord_idx >= num_funcs:
            continue
        func_rva = _u32(data, funcs_off + ord_idx * 4)

        # Forwarder check: if func_rva points into export directory range
        forwarder = None
        if export_rva <= func_rva < (export_rva + export_size):
            f_off = _rva_to_off(func_rva, sections)
            if f_off is not None:
                forwarder = _read_cstr(data, f_off)

        exports.append({
            "name": nm or None,
            "ordinal": int(base + ord_idx),
            "rva": f"0x{func_rva:x}",
            "forwarder": forwarder,
        })

    return {
        "dll_name": dll_name,
        "export_count": int(num_names),
        "exports": exports,
        "note": "Exports parsed from PE export table (best-effort)",
    }
