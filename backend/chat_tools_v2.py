"""Chat tools v2: Simplified RE assistant tools."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .memory_peek import memory_view
from .pe_exports import parse_pe_exports


def get_job_summary(work_dir: str, job_id: str) -> dict[str, Any]:
    """Get high-level job summary (file name, arch, function count, etc.)."""
    job_path = Path(work_dir) / job_id
    analysis_file = job_path / "extract" / "analysis.json"
    meta_file = job_path / "meta.json"
    
    result: dict[str, Any] = {"job_id": job_id}
    
    # Load meta.json if exists
    if meta_file.exists():
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
                result["meta"] = meta
        except Exception as e:
            result["meta_error"] = str(e)
    
    # Load analysis.json
    if analysis_file.exists():
        try:
            with open(analysis_file, "r", encoding="utf-8") as f:
                analysis = json.load(f)
                result["function_count"] = len(analysis.get("functions", []))
                result["string_count"] = len(analysis.get("strings", []))
                
                sample = analysis.get("sample", {})
                if sample:
                    result["sample"] = {
                        "path": sample.get("path"),
                        "arch": sample.get("arch"),
                        "size": sample.get("size"),
                        "md5": sample.get("md5"),
                        "sha256": sample.get("sha256"),
                    }
        except Exception as e:
            result["analysis_error"] = str(e)
    
    return result


def search_functions(work_dir: str, job_id: str, query: str = "", filters: dict[str, Any] | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """Search functions by name/tag/score. Returns list of matching functions (max 50)."""
    job_path = Path(work_dir) / job_id
    analysis_file = job_path / "extract" / "analysis.json"
    
    if not analysis_file.exists():
        return []
    
    try:
        with open(analysis_file, "r", encoding="utf-8") as f:
            analysis = json.load(f)
            functions = analysis.get("functions", [])
    except Exception:
        return []
    
    results = []
    query_lower = query.lower()
    
    for fn in functions:
        fn_id = fn.get("id", "")
        fn_name = fn.get("name", "")
        
        # Simple query match
        if query:
            searchable = f"{fn_id} {fn_name}".lower()
            if query_lower not in searchable:
                continue
        
        results.append({
            "id": fn_id,
            "name": fn_name,
            "entry": fn.get("entry", ""),
            "size": fn.get("size", 0),
            "is_entry": fn.get("entry") in ("entry", "true", "True", "1"),
            "is_external": fn.get("is_external", False),
            "is_winapi": fn.get("is_winapi", False),
        })
    
    # Enforce limit (max 50)
    if limit > 50:
        limit = 50
    return results[:limit]


def get_function_overview(work_dir: str, job_id: str, function_id: str) -> dict[str, Any]:
    """Get function overview (addr, size, calls, strings, AI status)."""
    job_path = Path(work_dir) / job_id
    analysis_file = job_path / "extract" / "analysis.json"
    ai_result_file = job_path / "ai" / "results" / f"{function_id}.json"
    ai_summary_file = job_path / "ai" / "summaries" / f"{function_id}.json"
    index_file = job_path / "ai" / "index.json"
    
    result: dict[str, Any] = {"function_id": function_id}
    
    # Find function in analysis.json
    if analysis_file.exists():
        try:
            with open(analysis_file, "r", encoding="utf-8") as f:
                analysis = json.load(f)
                functions = analysis.get("functions", [])
                for fn in functions:
                    if fn.get("id") == function_id or fn.get("name") == function_id:
                        result["name"] = fn.get("name", "")
                        result["id"] = fn.get("id", "")
                        result["entry"] = fn.get("entry", "")
                        result["size"] = fn.get("size", 0)
                        result["is_external"] = fn.get("is_external", False)
                        result["is_winapi"] = fn.get("is_winapi", False)
                        result["calls_out"] = fn.get("calls_out", [])
                        result["called_by"] = fn.get("called_by", [])
                        break
        except Exception:
            pass
    
    # Check AI decompile status from index.json
    if index_file.exists():
        try:
            with open(index_file, "r", encoding="utf-8") as f:
                index = json.load(f)
                entry = index.get(function_id, {})
                result["ai_status"] = entry.get("status", "not_started")
                result["proposed_name"] = entry.get("proposed_name")
        except Exception:
            pass
    
    # Load AI result if available
    if ai_result_file.exists():
        try:
            with open(ai_result_file, "r", encoding="utf-8") as f:
                ai_data = json.load(f)
                result["has_pseudocode"] = bool(ai_data.get("pseudocode"))
                result["confidence"] = ai_data.get("confidence")
        except Exception:
            pass
    elif ai_summary_file.exists():
        try:
            with open(ai_summary_file, "r", encoding="utf-8") as f:
                summary_data = json.load(f)
                result["has_summary"] = True
                result["summary_ja"] = summary_data.get("summary_ja")
        except Exception:
            pass
    
    return result


def get_function_code(work_dir: str, job_id: str, function_id: str, view: str = "decompiler") -> dict[str, Any]:
    """Get function code (disasm/decompiler/ai_pseudocode)."""
    job_path = Path(work_dir) / job_id
    disasm_file = job_path / "extract" / "disasm" / f"{function_id}.txt"
    ghidra_decomp_file = job_path / "extract" / "decomp" / f"{function_id}.txt"
    ai_result_file = job_path / "ai" / "results" / f"{function_id}.json"
    
    result: dict[str, Any] = {"function_id": function_id, "view": view}
    
    if view == "disasm" and disasm_file.exists():
        try:
            result["code"] = disasm_file.read_text(encoding="utf-8")
        except Exception as e:
            result["error"] = str(e)
    elif view == "ghidra" and ghidra_decomp_file.exists():
        try:
            result["code"] = ghidra_decomp_file.read_text(encoding="utf-8")
        except Exception as e:
            result["error"] = str(e)
    elif view in ("decompiler", "ai", "pseudocode") and ai_result_file.exists():
        try:
            with open(ai_result_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                result["pseudocode"] = data.get("pseudocode", "")
                result["proposed_name"] = data.get("proposed_name")
                result["signature"] = data.get("signature")
                result["confidence"] = data.get("confidence")
        except Exception as e:
            result["error"] = str(e)
    else:
        result["error"] = f"View '{view}' not found for function {function_id}"
    
    return result


def get_xrefs(work_dir: str, job_id: str, target: str, direction: str = "to", limit: int = 50) -> dict[str, Any]:
    """Get cross-references (to/from target). Limited to top 50."""
    # Placeholder: would need xrefs.json or similar
    # Enforce limit
    if limit > 50:
        limit = 50
    return {"target": target, "direction": direction, "xrefs": [], "limit": limit, "note": "xrefs not implemented"}


def get_callgraph(work_dir: str, job_id: str, function_id: str, depth: int = 1, direction: str = "callee") -> dict[str, Any]:
    """Get call graph (caller/callee). Max depth=2."""
    # Enforce depth limit
    if depth > 2:
        depth = 2
    
    job_path = Path(work_dir) / job_id
    analysis_file = job_path / "extract" / "analysis.json"
    
    if not analysis_file.exists():
        return {"function_id": function_id, "depth": depth, "direction": direction, "nodes": [], "error": "analysis.json not found"}
    
    try:
        with open(analysis_file, "r", encoding="utf-8") as f:
            analysis = json.load(f)
            functions = analysis.get("functions", [])
    except Exception as e:
        return {"function_id": function_id, "error": str(e)}
    
    # Build lookup map
    fn_map = {fn.get("id"): fn for fn in functions}
    
    # BFS traversal
    visited = set()
    result_nodes = []
    queue = [(function_id, 0)]
    
    while queue:
        current_id, current_depth = queue.pop(0)
        
        if current_id in visited or current_depth > depth:
            continue
        
        visited.add(current_id)
        fn = fn_map.get(current_id)
        
        if fn:
            result_nodes.append({
                "id": fn.get("id"),
                "name": fn.get("name"),
                "depth": current_depth,
            })
            
            # Add children based on direction
            if direction == "callee":
                children = fn.get("calls_out", [])
            else:  # caller
                children = fn.get("called_by", [])
            
            for child in children:
                if child not in visited:
                    queue.append((child, current_depth + 1))
    
    return {"function_id": function_id, "depth": depth, "direction": direction, "nodes": result_nodes}


def get_pe_map(work_dir: str, job_id: str, range_or_section: str = "") -> dict[str, Any]:
    """Get PE map (FOA/RVA/VA conversion + range items)."""
    # Placeholder: would need PE analysis data
    return {"range": range_or_section, "note": "pe_map not implemented"}


def get_artifacts(work_dir: str, job_id: str, artifact_type: str = "all") -> dict[str, Any]:
    """Get artifacts (capa/FLOSS results)."""
    job_path = Path(work_dir) / job_id
    capa_file = job_path / "extract" / "capa.json"
    
    result: dict[str, Any] = {"type": artifact_type, "artifacts": {}}
    
    if artifact_type in ("all", "capa") and capa_file.exists():
        try:
            with open(capa_file, "r", encoding="utf-8") as f:
                capa_data = json.load(f)
                result["artifacts"]["capa"] = {
                    "rules": capa_data.get("rules", {}),
                    "meta": capa_data.get("meta", {}),
                }
        except Exception as e:
            result["artifacts"]["capa"] = {"error": str(e)}
    
    return result


def peek_memory(work_dir: str, job_id: str, addr: str, length: int = 0x200) -> dict[str, Any]:
    """Peek memory by Virtual Address (VA) via Ghidra headless."""
    return memory_view(job_id=job_id, addr=addr, length=length)


def get_entrypoint_candidate(work_dir: str, job_id: str) -> dict[str, Any]:
    """Get entrypoint-based candidate function (EXE: main/EP, DLL: DllMain candidate).

    Returns ui.default_function_id + entrypoint address if available.
    """
    job_path = Path(work_dir) / job_id
    analysis_file = job_path / "extract" / "analysis.json"
    if not analysis_file.exists():
        return {"job_id": job_id, "error": "analysis.json not found"}

    try:
        analysis = json.loads(analysis_file.read_text(encoding="utf-8"))
    except Exception as e:
        return {"job_id": job_id, "error": str(e)}

    sample = analysis.get("sample", {})
    ui = analysis.get("ui", {})
    return {
        "job_id": job_id,
        "entry_point": sample.get("entry_point"),
        "image_base": sample.get("image_base"),
        "default_function_id": ui.get("default_function_id"),
        "default_function_reason": ui.get("default_function_reason"),
    }


def get_exports(work_dir: str, job_id: str, limit: int = 200) -> dict[str, Any]:
    """List PE exports for the uploaded binary (DLL entrypoints).

    Uses a lightweight PE export parser (no external deps).
    """
    job_path = Path(work_dir) / job_id
    inp = job_path / "input"
    if not inp.exists():
        return {"job_id": job_id, "error": "input directory not found"}

    # pick first file in input directory
    files = [p for p in inp.iterdir() if p.is_file()]
    if not files:
        return {"job_id": job_id, "error": "no input file"}

    pe_path = files[0]
    try:
        data = parse_pe_exports(pe_path, limit=int(limit))
        data["job_id"] = job_id
        data["path"] = str(pe_path)
        return data
    except Exception as e:
        return {"job_id": job_id, "error": str(e), "path": str(pe_path)}


def run_ai_decompile(work_dir: str, job_id: str, function_id: str, mode: str = "default") -> dict[str, Any]:
    """Queue AI decompile job (async). Returns job status."""
    # This would trigger the actual worker job
    # For now, return a placeholder
    return {
        "function_id": function_id,
        "mode": mode,
        "status": "queued",
        "note": "AI decompile would be queued here (not implemented in this prototype)"
    }


def save_annotation(work_dir: str, job_id: str, target: str, content: str) -> dict[str, Any]:
    """Save annotation/note/hypothesis."""
    job_path = Path(work_dir) / job_id
    annotations_dir = job_path / "annotations"
    annotations_dir.mkdir(parents=True, exist_ok=True)
    
    annotation_file = annotations_dir / f"{target}.txt"
    try:
        with open(annotation_file, "a", encoding="utf-8") as f:
            f.write(f"{content}\n")
        return {"target": target, "status": "saved"}
    except Exception as e:
        return {"target": target, "status": "error", "error": str(e)}


TOOL_REGISTRY = {
    "get_job_summary": get_job_summary,
    "search_functions": search_functions,
    "get_function_overview": get_function_overview,
    "get_function_code": get_function_code,
    "get_xrefs": get_xrefs,
    "get_callgraph": get_callgraph,
    "peek_memory": peek_memory,
    "get_entrypoint_candidate": get_entrypoint_candidate,
    "get_exports": get_exports,
    "get_pe_map": get_pe_map,
    "get_artifacts": get_artifacts,
    "run_ai_decompile": run_ai_decompile,
    "save_annotation": save_annotation,
}


TOOL_DESCRIPTIONS = """
## Available Tools

### DLL / Entry Tools (重要)

0. **get_entrypoint_candidate**
   - Purpose: Get entrypoint-based candidate function (EXE entrypoint / DLL DllMain candidate)
   - Args: `{}`
   - Returns: `{ "entry_point": "...", "default_function_id": "...", "default_function_reason": "..." }`
   - Use when: Start analysis; for DLL, this is the DllMain *candidate*

0. **get_exports**
   - Purpose: List exports from the uploaded PE (especially important for DLL)
   - Args: `{ "limit": 200 }`
   - Returns: `{ "dll_name": "...", "exports": [{"name":"...","ordinal":1,"rva":"0x..."}, ...] }`
   - Use when: DLL analysis; exported functions are real entrypoints

### Core Tools (Information Retrieval)

1. **search_functions**
   - Purpose: Find functions by name (partial match)
   - Args: `{"query": "main", "limit": 50}` (query is case-insensitive partial match)
   - Returns: `[{"name": "FUN_00401000", "address": "0x401000", "size": 256, "entry": false}, ...]`
   - GUARD: Max 50 results returned
   - Use when: User asks to "find" or "search" functions

2. **get_function_overview**
   - Purpose: Get metadata about a specific function
   - Args: `{"function_id": "FUN_00401000"}` (function name or address)
   - Returns: `{"name": "...", "address": "...", "size": 123, "ai_status": "ok"|"not_run"|"error", "has_pseudocode": true}`
   - Use when: Need to check if function exists or has AI decompile result

3. **get_function_code**
   - Purpose: Get decompiled pseudocode for a function
   - Args: `{"function_id": "FUN_00401000", "view": "decompiler"}`
   - Returns: `{"pseudocode": "int main() {...}", "proposed_name": "main", "signature": "int(int, char**)"}`
   - Use when: User asks to "see code" or "show" function content

4. **get_job_summary**
   - Purpose: Get high-level binary info
   - Args: `{}` (no args needed)
   - Returns: `{"function_count": 150, "string_count": 500, "meta": {...}}`
   - Use when: User asks "what is this binary?" or needs overview

5. **get_xrefs** (placeholder)
   - Purpose: Get cross-references to/from a target
   - Args: `{"target": "address", "direction": "to", "limit": 50}`
   - Returns: `{"xrefs": [...], "limit": 50}`
   - GUARD: Max 50 xrefs returned

6. **get_callgraph** (placeholder)
   - Purpose: Get call graph (caller/callee tree)
   - Args: `{"function_id": "FUN_00401000", "depth": 1, "direction": "callee"}`
   - Returns: `{"nodes": [...], "depth": 2}`
   - GUARD: Max depth=2 enforced

7. **peek_memory**
   - Purpose: Read raw bytes at a Virtual Address (VA) using Ghidra headless (Memory View)
   - Args: `{"addr": "0x140003000", "length": 256}` (length: 1..0x4000)
   - Returns: `{ "va": "0x...", "len": 256, "bytes_b64": "...", "arch": "...", "ptr_size": 8, "annotations": {...} }`
   - Use when: Need to verify pointers/structures/strings referenced by VA in decompiler output
   - GUARD: addr must be hex VA; length max 0x4000

8-9. **get_pe_map / get_artifacts** (placeholders, not yet implemented)

### Action Tools

10. **run_ai_decompile**
   - Purpose: Queue AI decompilation for a function
   - Args: `{"function_id": "FUN_00401000", "mode": "default"}`
   - Returns: `{"status": "queued", "function_id": "..."}`
   - Use when: User asks to "run AI" or "analyze with AI"

11. **save_annotation**
    - Purpose: Save user notes/hypotheses
    - Args: `{"target": "FUN_00401000", "content": "This looks like WinMain"}`
    - Returns: `{"status": "saved", "target": "..."}`
    - Use when: User wants to save observations

## CRITICAL: ID Management Rules

**NEVER fabricate function_id or address!**
- If user mentions a function by name (e.g., "main"), use `search_functions` first to find its function_id
- Only use function_ids that appear in tool results
- Example flow: search_functions → get function_id from result → use in get_function_code

## Usage Examples

**User: "mainっぽい関数を探して"**
→ `{"tool_calls": [{"tool": "search_functions", "args": {"query": "main"}}]}`
(Do NOT assume function_id - search first!)

**User: "FUN_00401000のコードを見せて"**
→ `{"tool_calls": [{"tool": "get_function_code", "args": {"function_id": "FUN_00401000", "view": "decompiler"}}]}`
(User provided exact function_id - OK to use directly)

**User: "main関数のコードを見せて"**
→ Step 1: `{"tool_calls": [{"tool": "search_functions", "args": {"query": "main"}}]}`
→ Step 2 (after getting result): Use function_id from search result

**User: "このバイナリは何？"**
→ `{"tool_calls": [{"tool": "get_job_summary", "args": {}}]}`
"""


def dispatch_tool_v2(work_dir: str, job_id: str, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Dispatch tool call to appropriate handler."""
    if tool_name not in TOOL_REGISTRY:
        return {"error": f"Unknown tool: {tool_name}"}
    
    handler = TOOL_REGISTRY[tool_name]
    
    try:
        # Inject work_dir and job_id into args
        full_args = {"work_dir": work_dir, "job_id": job_id, **args}
        return handler(**full_args)
    except Exception as e:
        return {"error": str(e), "tool": tool_name, "args": args}
