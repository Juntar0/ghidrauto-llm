from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .storage import read_json


def tool_search_strings(work_dir: str, job_id: str, query: str, limit: int = 50) -> dict[str, Any]:
    """Search all strings (data + inline) and format nicely for LLM"""
    from chat_tools_v2 import search_strings
    
    # Use the improved search_strings that includes inline strings
    result = search_strings(work_dir, job_id, query, max(1, min(int(limit), 500)))
    
    # Format response for chat display
    strings = result.get("strings", [])
    
    # Group by source
    data_strings = [s for s in strings if s.get("source") == "data"]
    inline_strings = [s for s in strings if s.get("source") == "inline"]
    
    # Build compact markdown output
    markdown_lines = []
    markdown_lines.append(f"**Found {result.get('count', 0)} matches for `{query}`**")
    
    if data_strings:
        markdown_lines.append(f"\n📦 **Data section** ({len(data_strings)}):")
        for s in data_strings:
            addr = s.get("address", "")
            markdown_lines.append(f"  - `{s.get('value', '')}` @ {addr}")
    
    if inline_strings:
        markdown_lines.append(f"\n💻 **Inline (code)** ({len(inline_strings)}):")
        for s in inline_strings:
            func = s.get("in_function", "")
            markdown_lines.append(f"  - `{s.get('value', '')}` in {func}")
    
    markdown_text = "\n".join(markdown_lines)
    
    return {
        "result": markdown_text,
        "query": query,
        "count": result.get("count", 0),
        "matches": strings  # Keep raw data for advanced usage
    }


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
                "description": "Search ALL strings (both data section and inline code strings). Returns strings with source type and function location. Case-insensitive substring match.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "String to search for (case-insensitive substring match)"},
                        "limit": {"type": "integer", "default": 50, "description": "Max results (default 50, max 500)"},
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


def available_tools_anthropic() -> list[dict[str, Any]]:
    # Anthropic tool schema
    out: list[dict[str, Any]] = []
    for t in available_tools_schema():
        fn = (t.get("function") or {})
        out.append(
            {
                "name": fn.get("name"),
                "description": fn.get("description"),
                "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
            }
        )
    return out


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
