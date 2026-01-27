#@author clawd
#@category AutoRE
#@keybinding
#@menupath
#@toolbar

"""Ghidra headless script.

Args:
  0: output analysis.json path
  1: disasm output directory

Produces:
- analysis.json (function metadata + ui.default_function_id)
- disasm/<function_id>.txt for each function (limited lines)

Notes:
- This script is best-effort and avoids heavy features.
"""

import json
import os
import re

from ghidra.program.model.symbol import SymbolType


def _addr_str(addr):
    try:
        return "0x" + addr.toString()
    except:
        return str(addr)


def _get_entry_point():
    # Try several APIs; fall back to min function address.
    try:
        ep = currentProgram.getEntryPoint()
        if ep:
            return ep
    except:
        pass

    # Sometimes symbol table has external entry
    try:
        it = currentProgram.getSymbolTable().getExternalEntryPointIterator()
        if it and it.hasNext():
            sym = it.next()
            return sym.getAddress()
    except:
        pass

    return None


def _default_function_id(entry_addr, functions):
    fm = currentProgram.getFunctionManager()
    if entry_addr:
        f = fm.getFunctionContaining(entry_addr)
        if f:
            return f.getName(), "entry_point"
        f = fm.getFunctionAt(entry_addr)
        if f:
            return f.getName(), "entry_point_at"

    # fallback: smallest entry
    if functions:
        return functions[0]["id"], "fallback_first"
    return None, "fallback_none"


def _sanitize_filename(s):
    return re.sub(r"[^A-Za-z0-9_\-\.]+", "_", s)


def _write_disasm(func, out_dir):
    listing = currentProgram.getListing()
    instr_iter = listing.getInstructions(func.getBody(), True)
    lines = []
    limit = 400  # cap per function
    i = 0
    while instr_iter.hasNext() and i < limit:
        ins = instr_iter.next()
        lines.append("%s %s" % (ins.getAddress(), ins))
        i += 1

    fid = _sanitize_filename(func.getName())
    path = os.path.join(out_dir, fid + ".txt")
    with open(path, "w") as f:
        f.write("\n".join(lines))


def main():
    if len(getScriptArgs()) < 2:
        print("ExtractAnalysis.py requires 2 args: <analysis.json> <disasm_dir>")
        return

    analysis_path = getScriptArgs()[0]
    disasm_dir = getScriptArgs()[1]
    if not os.path.isdir(disasm_dir):
        os.makedirs(disasm_dir)

    fm = currentProgram.getFunctionManager()

    funcs = []
    it = fm.getFunctions(True)
    while it.hasNext():
        f = it.next()
        funcs.append(f)

    # Deterministic order
    funcs.sort(key=lambda f: f.getEntryPoint().getOffset())

    functions = []
    for f in funcs:
        try:
            _write_disasm(f, disasm_dir)
        except Exception as e:
            # keep going
            pass

        functions.append(
            {
                "id": f.getName(),
                "name": f.getName(),
                "entry": str(f.getEntryPoint()),
                "size": int(f.getBody().getNumAddresses()),
            }
        )

    entry = _get_entry_point()
    default_fid, reason = _default_function_id(entry, functions)

    out = {
        "sample": {
            "path": currentProgram.getExecutablePath(),
            "image_base": str(currentProgram.getImageBase()),
            "entry_point": str(entry) if entry else None,
            "format": currentProgram.getExecutableFormat(),
            "processor": str(currentProgram.getLanguage().getProcessor()),
            "compiler": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
        },
        "ui": {
            "default_function_id": default_fid,
            "default_function_reason": reason,
        },
        "functions": functions,
    }

    with open(analysis_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)


main()
