from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .storage import read_json


def tool_search_strings(work_dir: str, job_id: str, query: str, limit: int = 50) -> dict[str, Any]:
    base = Path(work_dir) / job_id
    ap = base / "extract" / "analysis.json"
    analysis = read_json(ap, {})
    strings = analysis.get("strings") or []

    q = (query or "").lower().strip()
    out = []
    for s in strings:
        val = str((s or {}).get("value") or "")
        addr = str((s or {}).get("addr") or "")
        if not q or (q in val.lower()) or (q in addr.lower()):
            out.append({"addr": addr, "value": val, "len": (s or {}).get("len"), "type": (s or {}).get("type")})
        if len(out) >= max(1, min(int(limit), 200)):
            break
    return {"query": query, "matches": out, "count": len(out)}


def tool_list_functions(work_dir: str, job_id: str, query: str | None = None, limit: int = 50) -> dict[str, Any]:
    base = Path(work_dir) / job_id
    ap = base / "extract" / "analysis.json"
    analysis = read_json(ap, {})
    funcs = analysis.get("functions") or []

    q = (query or "").lower().strip()
    out = []
    for f in funcs:
        fid = str((f or {}).get("id") or "")
        name = str((f or {}).get("name") or "")
        entry = str((f or {}).get("entry") or "")
        if not q or (q in fid.lower()) or (q in name.lower()) or (q in entry.lower()):
            out.append({"id": fid, "name": name, "entry": entry, "size": (f or {}).get("size")})
        if len(out) >= max(1, min(int(limit), 500)):
            break
    return {"query": query, "functions": out, "count": len(out)}


def tool_get_function_context(work_dir: str, job_id: str, function_id: str, disasm_max: int = 8000) -> dict[str, Any]:
    base = Path(work_dir) / job_id
    disasm_path = base / "extract" / "disasm" / f"{function_id}.txt"
    decomp_path = base / "extract" / "decomp" / f"{function_id}.c"

    disasm = disasm_path.read_text(encoding="utf-8", errors="replace") if disasm_path.exists() else ""
    decomp = decomp_path.read_text(encoding="utf-8", errors="replace") if decomp_path.exists() else ""

    return {
        "function_id": function_id,
        "has_disasm": disasm_path.exists(),
        "has_decomp": decomp_path.exists(),
        "disasm": disasm[: max(0, int(disasm_max))],
        "decomp": decomp,
    }


def tool_navigate(function_id: str) -> dict[str, Any]:
    # Frontend will interpret this as a UI action.
    return {"action": "navigate", "function_id": function_id}


def available_tools_schema() -> list[dict[str, Any]]:
    # OpenAI-compatible tool schema
    return [
        {
            "type": "function",
            "function": {
                "name": "search_strings",
                "description": "Search extracted strings for a job.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "default": 50},
                    },
                    "required": ["query"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_functions",
                "description": "List functions (optionally filter by query).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "default": 50},
                    },
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_function_context",
                "description": "Get disassembly and decompiler output for a function.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "function_id": {"type": "string"},
                        "disasm_max": {"type": "integer", "default": 8000},
                    },
                    "required": ["function_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "navigate_to_function",
                "description": "Ask the UI to navigate/open a function.",
                "parameters": {
                    "type": "object",
                    "properties": {"function_id": {"type": "string"}},
                    "required": ["function_id"],
                },
            },
        },
    ]


def dispatch_tool(work_dir: str, job_id: str, name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "search_strings":
        return tool_search_strings(work_dir, job_id, args.get("query", ""), int(args.get("limit", 50) or 50))
    if name == "list_functions":
        return tool_list_functions(work_dir, job_id, args.get("query"), int(args.get("limit", 50) or 50))
    if name == "get_function_context":
        return tool_get_function_context(work_dir, job_id, args.get("function_id", ""), int(args.get("disasm_max", 8000) or 8000))
    if name == "navigate_to_function":
        return tool_navigate(args.get("function_id", ""))
    raise ValueError(f"unknown tool: {name}")
