from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from elftools.elf.elffile import ELFFile


@dataclass
class ElfInfo:
    path: str
    elfclass: str | None
    endian: str | None
    machine: str | None
    etype: str | None
    entry: str | None
    is_pie: bool | None
    interp: str | None
    build_id: str | None


def _hex(x: int | None) -> str | None:
    if x is None:
        return None
    return f"0x{x:x}"


def _read_interp(elffile: ELFFile) -> str | None:
    for seg in elffile.iter_segments():
        try:
            if seg.header.p_type == "PT_INTERP":
                data = seg.data()
                s = data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                return s
        except Exception:
            continue
    return None


def _read_build_id(elffile: ELFFile) -> str | None:
    # Build-id is usually in .note.gnu.build-id
    try:
        sec = elffile.get_section_by_name(".note.gnu.build-id")
        if not sec:
            return None
        for note in sec.iter_notes():
            if note.get("n_type") == "NT_GNU_BUILD_ID":
                desc = note.get("n_desc")
                if isinstance(desc, (bytes, bytearray)):
                    return desc.hex()
    except Exception:
        return None
    return None


def read_elf_info(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    with p.open("rb") as f:
        ef = ELFFile(f)
        hdr = ef.header
        etype = str(hdr.get("e_type"))
        info = ElfInfo(
            path=str(p),
            elfclass=str(ef.elfclass) if getattr(ef, "elfclass", None) else None,
            endian=("little" if getattr(ef, "little_endian", None) is True else "big" if getattr(ef, "little_endian", None) is False else None),
            machine=str(hdr.get("e_machine")),
            etype=etype,
            entry=_hex(int(hdr.get("e_entry")) if hdr.get("e_entry") is not None else None),
            is_pie=True if etype == "ET_DYN" else False if etype == "ET_EXEC" else None,
            interp=_read_interp(ef),
            build_id=_read_build_id(ef),
        )
        return info.__dict__


def read_elf_dynamic(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    with p.open("rb") as f:
        ef = ELFFile(f)
        sec = ef.get_section_by_name(".dynamic")
        if not sec:
            return {"needed": [], "rpath": None, "runpath": None, "soname": None}

        needed: list[str] = []
        rpath = None
        runpath = None
        soname = None
        for tag in sec.iter_tags():
            try:
                d_tag = tag.entry.d_tag
                if d_tag == "DT_NEEDED":
                    needed.append(str(tag.needed))
                elif d_tag == "DT_RPATH":
                    rpath = str(tag.rpath)
                elif d_tag == "DT_RUNPATH":
                    runpath = str(tag.runpath)
                elif d_tag == "DT_SONAME":
                    soname = str(tag.soname)
            except Exception:
                continue

        return {"needed": needed, "rpath": rpath, "runpath": runpath, "soname": soname}


def read_elf_symbols(path: str | Path, *, kind: str = "dyn", limit: int = 2000) -> dict[str, Any]:
    """Read ELF symbols.

    kind:
      - dyn: .dynsym
      - sym: .symtab

    Returns a list of {name, type, bind, vis, shndx, value, size}.
    """

    p = Path(path)
    with p.open("rb") as f:
        ef = ELFFile(f)
        secname = ".dynsym" if kind == "dyn" else ".symtab"
        sec = ef.get_section_by_name(secname)
        if not sec:
            return {"kind": kind, "section": secname, "symbols": [], "note": "section not found"}

        out: list[dict[str, Any]] = []
        for i, sym in enumerate(sec.iter_symbols()):
            if i >= limit:
                break
            try:
                name = sym.name
                info = sym.entry["st_info"]
                other = sym.entry["st_other"]
                out.append(
                    {
                        "name": name or None,
                        "type": info.get("type"),
                        "bind": info.get("bind"),
                        "vis": other.get("visibility"),
                        "shndx": sym.entry.get("st_shndx"),
                        "value": _hex(int(sym.entry.get("st_value") or 0)),
                        "size": int(sym.entry.get("st_size") or 0),
                    }
                )
            except Exception:
                continue

        return {"kind": kind, "section": secname, "count": len(out), "symbols": out}


def read_elf_imports(path: str | Path, limit: int = 5000) -> dict[str, Any]:
    """List imported functions/objects based on relocation entries.

    Focuses on x86_64 typical sections:
      - .rela.plt / .rel.plt (JUMP_SLOT)
      - .rela.dyn / .rel.dyn (GLOB_DAT, RELATIVE, etc.)

    Returns a list with {name, reloc_type, offset, addend, sym_value, sym_size}.
    """

    p = Path(path)
    with p.open("rb") as f:
        ef = ELFFile(f)

        rel_secs: list[tuple[str, Any]] = []
        for nm in (".rela.plt", ".rel.plt", ".rela.dyn", ".rel.dyn"):
            sec = ef.get_section_by_name(nm)
            if sec:
                rel_secs.append((nm, sec))

        imports: list[dict[str, Any]] = []
        for nm, sec in rel_secs:
            try:
                symtab = ef.get_section(sec.header.sh_link)
            except Exception:
                symtab = None
            for rel in sec.iter_relocations():
                if len(imports) >= limit:
                    break
                try:
                    r_info_type = rel.entry.get("r_info_type")
                    r_offset = rel.entry.get("r_offset")
                    r_addend = rel.entry.get("r_addend") if "r_addend" in rel.entry else None

                    sym_name = None
                    sym_value = None
                    sym_size = None
                    if symtab is not None and rel.entry.get("r_info_sym") is not None:
                        sym = symtab.get_symbol(rel.entry["r_info_sym"])
                        if sym is not None:
                            sym_name = sym.name
                            sym_value = _hex(int(sym.entry.get("st_value") or 0))
                            sym_size = int(sym.entry.get("st_size") or 0)

                    imports.append(
                        {
                            "section": nm,
                            "name": sym_name or None,
                            "reloc_type": r_info_type,
                            "offset": _hex(int(r_offset) if r_offset is not None else None),
                            "addend": _hex(int(r_addend) if r_addend is not None else None) if r_addend is not None else None,
                            "sym_value": sym_value,
                            "sym_size": sym_size,
                        }
                    )
                except Exception:
                    continue

        return {"count": len(imports), "imports": imports}
