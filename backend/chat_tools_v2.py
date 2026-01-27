"""Chat tools v2: Simplified RE assistant tools."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def get_job_summary(work_dir: str, job_id: str) -> dict[str, Any]:
    """Get high-level job summary (file name, arch, function count, etc.)."""
    job_path = Path(work_dir) / job_id
    meta_file = job_path / "meta.json"
    functions_file = job_path / "functions.json"
    strings_file = job_path / "strings.json"
    
    result: dict[str, Any] = {"job_id": job_id}
    
    if meta_file.exists():
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                result["meta"] = json.load(f)
        except Exception as e:
            result["meta_error"] = str(e)
    
    if functions_file.exists():
        try:
            with open(functions_file, "r", encoding="utf-8") as f:
                functions = json.load(f)
                result["function_count"] = len(functions)
        except Exception:
            result["function_count"] = 0
    
    if strings_file.exists():
        try:
            with open(strings_file, "r", encoding="utf-8") as f:
                strings = json.load(f)
                result["string_count"] = len(strings)
        except Exception:
            result["string_count"] = 0
    
    return result


def search_functions(work_dir: str, job_id: str, query: str = "", filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Search functions by name/tag/score. Returns list of matching functions."""
    job_path = Path(work_dir) / job_id
    functions_file = job_path / "functions.json"
    
    if not functions_file.exists():
        return []
    
    try:
        with open(functions_file, "r", encoding="utf-8") as f:
            functions = json.load(f)
    except Exception:
        return []
    
    results = []
    query_lower = query.lower()
    
    for fn in functions:
        name = (fn.get("name") or "").lower()
        
        # Simple query match
        if query and query_lower not in name:
            continue
        
        results.append({
            "name": fn.get("name"),
            "address": fn.get("address"),
            "size": fn.get("size"),
            "entry": fn.get("entry", False),
        })
    
    # Limit to 50 results
    return results[:50]


def get_function_overview(work_dir: str, job_id: str, function_id: str) -> dict[str, Any]:
    """Get function overview (addr, size, calls, strings, AI status)."""
    job_path = Path(work_dir) / job_id
    functions_file = job_path / "functions.json"
    decomp_file = job_path / "decomp" / f"{function_id}.json"
    
    result: dict[str, Any] = {"function_id": function_id}
    
    # Find function in functions.json
    if functions_file.exists():
        try:
            with open(functions_file, "r", encoding="utf-8") as f:
                functions = json.load(f)
                for fn in functions:
                    if fn.get("name") == function_id or fn.get("address") == function_id:
                        result["name"] = fn.get("name")
                        result["address"] = fn.get("address")
                        result["size"] = fn.get("size")
                        result["entry"] = fn.get("entry", False)
                        break
        except Exception:
            pass
    
    # Check AI decompile status
    if decomp_file.exists():
        try:
            with open(decomp_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                result["ai_status"] = data.get("status", "ok")
                result["has_pseudocode"] = bool(data.get("pseudocode"))
                result["proposed_name"] = data.get("proposed_name")
        except Exception:
            result["ai_status"] = "error"
    else:
        result["ai_status"] = "not_run"
    
    return result


def get_function_code(work_dir: str, job_id: str, function_id: str, view: str = "decompiler") -> dict[str, Any]:
    """Get function code (disasm/decompiler/pcode)."""
    job_path = Path(work_dir) / job_id
    decomp_file = job_path / "decomp" / f"{function_id}.json"
    
    result: dict[str, Any] = {"function_id": function_id, "view": view}
    
    if view == "decompiler" and decomp_file.exists():
        try:
            with open(decomp_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                result["pseudocode"] = data.get("pseudocode", "")
                result["proposed_name"] = data.get("proposed_name")
                result["signature"] = data.get("signature")
        except Exception as e:
            result["error"] = str(e)
    else:
        result["error"] = f"View '{view}' not supported or file not found"
    
    return result


def get_xrefs(work_dir: str, job_id: str, target: str, direction: str = "to") -> dict[str, Any]:
    """Get cross-references (to/from target)."""
    # Placeholder: would need xrefs.json or similar
    return {"target": target, "direction": direction, "xrefs": [], "note": "xrefs not implemented"}


def get_callgraph(work_dir: str, job_id: str, function_id: str, depth: int = 1, direction: str = "callee") -> dict[str, Any]:
    """Get call graph (caller/callee)."""
    # Placeholder: would need call graph data
    return {"function_id": function_id, "depth": depth, "direction": direction, "nodes": [], "note": "callgraph not implemented"}


def get_pe_map(work_dir: str, job_id: str, range_or_section: str = "") -> dict[str, Any]:
    """Get PE map (FOA/RVA/VA conversion + range items)."""
    # Placeholder: would need PE analysis data
    return {"range": range_or_section, "note": "pe_map not implemented"}


def get_artifacts(work_dir: str, job_id: str, artifact_type: str = "all") -> dict[str, Any]:
    """Get artifacts (capa/FLOSS results)."""
    # Placeholder: would need artifacts directory
    return {"type": artifact_type, "artifacts": [], "note": "artifacts not implemented"}


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
    "get_pe_map": get_pe_map,
    "get_artifacts": get_artifacts,
    "run_ai_decompile": run_ai_decompile,
    "save_annotation": save_annotation,
}


TOOL_DESCRIPTIONS = """
Available tools:

**Core tools (読み取り)**
1. get_job_summary(job_id) - Get job overview (file, arch, function count)
2. search_functions(job_id, query, filters) - Search functions by name/tag
3. get_function_overview(job_id, function_id) - Get function metadata (addr/size/AI status)
4. get_function_code(job_id, function_id, view) - Get decompiled code
5. get_xrefs(job_id, target, direction) - Get cross-references
6. get_callgraph(job_id, function_id, depth, direction) - Get call graph
7. get_pe_map(job_id, range_or_section) - Get PE map info
8. get_artifacts(job_id, type) - Get capa/FLOSS artifacts

**Action tools (書き込み)**
9. run_ai_decompile(job_id, function_id, mode) - Queue AI decompile
10. save_annotation(job_id, target, content) - Save note/hypothesis
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
