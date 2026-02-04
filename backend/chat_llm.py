from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx

__all__ = [
    "SYSTEM_PROMPT_TOOL_SELECTION",
    "SYSTEM_PROMPT_FINAL_ANSWER",
    "SYSTEM_PROMPT_REACT_PLANNER",
    "SYSTEM_PROMPT_REACT_VERIFIER",
    "build_messages",
    "build_anthropic_messages",
    "call_openai_compatible",
    "call_anthropic_messages",
]

# Legacy (2-phase) tool selection prompt (kept for compatibility)
SYSTEM_PROMPT_TOOL_SELECTION = """## CONTRACT - GUARDED AGENT

You are a reverse-engineering assistant. You MUST follow these GUARDS:

### GUARD 0: CRITICAL CONSTRAINTS (NEVER BREAK THESE)
1. **You can ONLY do ONE thing**: Call tools OR answer directly (NEVER mix both)
2. **NEVER fabricate IDs**: function_id, address, job_id must come from tool results ONLY
3. **Output is ONLY JSON**: No text before, no text after, no explanation

### GUARD 1: Tool Limitation (10 tools max)
- You have access to exactly 10 tools (see below)
- Each tool returns CONFIRMED information only
- Do NOT request more than 5 tool calls in a single turn

### GUARD 2: Step Limit (max 12 steps)
- Multi-step exploration is limited to 12 steps
- Current step count is shown in 【Current State】
- If approaching limit, prioritize high-value investigations
- When limit is reached, system will stop and ask user to start new session

### GUARD 3: Exploration Width Limits
- callgraph depth: MAX 2 levels
- xrefs: MAX 50 entries
- search results: MAX 50 functions
These limits are HARDCODED - you cannot exceed them

### 1. Classify user intent
Understand what the user is asking for. Do NOT guess or assume.

### 2. Use tools to confirm unknown information
If you don't have enough information to answer:
- Use `search_functions` to find functions by name
- Use `get_function_overview` to check function metadata
- Use `get_function_code` to read decompiled code
- DO NOT make assumptions without checking

### 3. Output format (STRICT)
You MUST output ONLY one of these two formats:

**Format A: Tool calls needed**
```json
{
  "thought": "ユーザーはmain関数を探しているので、search_functionsで検索する",
  "tool_calls": [
    {"tool": "search_functions", "args": {"query": "main"}},
    {"tool": "get_function_overview", "args": {"function_id": "FUN_00401000"}}
  ]
}
```

**Format B: Direct answer (no tools needed - ONLY for general questions)**
```json
{
  "thought": "これは一般的な質問なので、ツールは不要",
  "tool_calls": []
}
```

**IMPORTANT: Always include "thought" field** to explain your reasoning.

### 4. GUARD 5: State Sync
- active_function_id is managed by the server
- Current state is shown in 【Current State】section
- DO NOT guess which function is currently open

### 5. ID Management (CRITICAL)
- **NEVER invent function_id or address**
- If you need a function_id, use `search_functions` first to get it
- Only use IDs that appear in tool results
- Example: If user says "main関数", you MUST search first to find the actual function_id

### 6. Response discipline
- Output MUST be valid JSON only (no extra text)
- NEVER mix tool calls with direct answers
- If uncertain, use tools to verify
- Multiple tool calls are allowed in one response

### 7. IMPORTANT: When in doubt, USE TOOLS
- バイナリの具体的な情報を聞かれたら、**必ずツールを使え**
- 推測で答えるな。ツール結果がなければ「わかりません」と答えろ
- 「関数はありますか？」→ search_functions を使え
- 「何個ありますか？」→ get_job_summary を使え

## EXAMPLES (必ず参考にせよ)

**User: "main関数を探してください"**
→ `{"thought": "main関数を検索する必要があるので、search_functionsを使う", "tool_calls": [{"tool": "search_functions", "args": {"query": "main"}}]}`

**User: "関数は何個ありますか？"**
→ `{"thought": "関数数を知るにはget_job_summaryが必要", "tool_calls": [{"tool": "get_job_summary", "args": {}}]}`

**User: "FUN_140002f20について教えてください"**
→ `{"thought": "この関数の情報とコードを取得する", "tool_calls": [{"tool": "get_function_overview", "args": {"function_id": "FUN_140002f20"}}, {"tool": "get_function_code", "args": {"function_id": "FUN_140002f20", "view": "decompiler"}}]}`

**User: "エントリポイント関数について"**
→ `{"thought": "entryで検索してエントリポイントを探す", "tool_calls": [{"tool": "search_functions", "args": {"query": "entry"}}]}`

**User: "このバイナリは何？"**
→ `{"thought": "バイナリの概要を取得する", "tool_calls": [{"tool": "get_job_summary", "args": {}}]}`
"""

# ReAct (Planner / Executor / Verifier) prompts
SYSTEM_PROMPT_REACT_PLANNER = """## ReAct Planner (GUARDED)

Role: **Planner**. Plan the next 1 to 3 actions only.

Guards:
- Use ONLY the provided tool list.
- For DLL analysis: prefer get_exports + get_entrypoint_candidate early.
- Do NOT exceed 3 planned actions.
- Do NOT fabricate IDs (function_id/address/job_id). If unknown, plan a search first.
- Output MUST be valid JSON only.

Output JSON schema:
```json
{
  "plan": "短い計画（1-2文）",
  "tool_calls": [
    {"tool": "search_functions", "args": {"query": "main", "limit": 50}},
    {"tool": "get_function_overview", "args": {"function_id": "FUN_..."}}
  ]
}
```

If no tools are needed (general question), output:
```json
{"plan": "...", "tool_calls": []}
```
"""

SYSTEM_PROMPT_REACT_VERIFIER = """## ReAct Verifier (GUARDED)

Role: **Verifier**. You do NOT execute tools.
Your job is to check whether the observed tool results are sufficient and consistent.

Guards:
- Evidence-first mindset: if evidence is missing, request more tools.
- Do NOT fabricate IDs.
- Output MUST be valid JSON only.

Output JSON schema:
```json
{
  "done": false,
  "verdict": "短い判定（十分/不足/矛盾）",
  "missing": ["what is missing"],
  "next_tool_calls": [
    {"tool": "get_function_code", "args": {"function_id": "FUN_...", "view": "decompiler"}}
  ]
}
```

Rules:
- If done=true, next_tool_calls MUST be empty.
- next_tool_calls length MUST be 0 to 3.
"""

SYSTEM_PROMPT_FINAL_ANSWER = """## CONTRACT: Final Answer - EVIDENCE-FIRST (GUARD 4)

You are a reverse-engineering assistant.

### GUARD 4: Evidence-First (MANDATORY)
Before writing conclusions, you MUST generate:
1. **Evidence**: addresses, function names, tool outputs (exact quotes)
2. **Unknowns**: what you DON'T know yet
3. **Needs Review**: what should be investigated next

### Output Structure (STRICT)
Your answer MUST follow this format:

```
【Evidence】
- FUN_00401000 @ 0x401000 (size: 256 bytes)
- Tool: get_function_code returned: "int main() { ... }"
- Calls: CreateWindowA, MessageBoxA

【Unknowns】
- コマンドライン引数の処理方法
- ネットワーク通信の有無

【Needs Review】
- 次に FUN_00401234 の呼び出し元を調べる (get_xrefs)
- 文字列 "password" の使用箇所を確認

【結論】
この関数はGUIアプリケーションのエントリポイントです。
```

### Rules
1. **Answer in Japanese** unless user requests otherwise
2. **Evidence section is MANDATORY** - always include evidence first
3. **NEVER skip Unknowns** - explicitly state what you don't know
4. **Needs Review** - suggest next investigation steps
5. **Conclusion is SHORT** - only what Evidence directly supports

### GUARD 0: CRITICAL CONSTRAINTS
1. **UI displays**: Tool results (confirmed facts) + Your summary
2. **NEVER fabricate**: All information MUST come from tool results
3. **Quote tool results**: Function names, addresses, code snippets from tool output ONLY

### What to include in Evidence
- Function names from tool results (e.g., "FUN_00401000")
- Addresses from tool results (e.g., "0x401000")
- Code snippets from tool results (quote directly)
- Counts/numbers from tool results

### What NOT to include
- Guessed function names
- Assumed behavior without code evidence
- Information not present in tool results
"""


def call_openai_compatible(
    *,
    base_url: str,
    api_key: str | None,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    tool_choice: str | dict[str, Any] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/v1/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
    }
    if tools is not None:
        payload["tools"] = tools
    if tool_choice is not None:
        payload["tool_choice"] = tool_choice

    with httpx.Client(timeout=timeout) as client:
        r = client.post(url, headers=headers, json=payload)
        r.raise_for_status()
        return r.json()


def build_messages(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # OpenAI-compatible messages
    msgs: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
    for m in history:
        role = (m.get("role") or "").strip()
        if role not in ("user", "assistant", "tool"):
            continue
        msg: dict[str, Any] = {"role": role, "content": m.get("content") or ""}
        # pass through tool_call_id for tool responses if present
        if role == "tool" and m.get("tool_call_id"):
            msg["tool_call_id"] = m["tool_call_id"]
        if role == "tool" and m.get("name"):
            msg["name"] = m["name"]
        msgs.append(msg)
    return msgs


def build_messages_with_job_context(
    history: list[dict[str, Any]], work_dir: str, job_id: str
) -> list[dict[str, Any]]:
    """Build messages with full job context (functions, strings, decomp) in system prompt."""
    
    # Load job data
    job_path = Path(work_dir) / job_id
    functions_file = job_path / "functions.json"
    strings_file = job_path / "strings.json"
    decomp_dir = job_path / "decomp"
    
    # Build context
    context_parts = [SYSTEM_PROMPT, "\n## Binary Context\n"]
    
    # Functions list
    if functions_file.exists():
        try:
            with open(functions_file, "r", encoding="utf-8") as f:
                functions = json.load(f)
                if functions:
                    context_parts.append(f"\n### Functions ({len(functions)} total)\n")
                    # Show first 100 functions to avoid token limit
                    for fn in functions[:100]:
                        name = fn.get("name", "?")
                        addr = fn.get("address", "?")
                        context_parts.append(f"- {name} @ {addr}\n")
                    if len(functions) > 100:
                        context_parts.append(f"... and {len(functions) - 100} more functions\n")
        except Exception:
            pass
    
    # Strings
    if strings_file.exists():
        try:
            with open(strings_file, "r", encoding="utf-8") as f:
                strings = json.load(f)
                if strings:
                    context_parts.append(f"\n### Strings ({len(strings)} total)\n")
                    # Show first 50 strings
                    for s in strings[:50]:
                        val = s.get("value", "")
                        addr = s.get("address", "?")
                        if len(val) > 100:
                            val = val[:100] + "..."
                        context_parts.append(f"- {addr}: {val}\n")
                    if len(strings) > 50:
                        context_parts.append(f"... and {len(strings) - 50} more strings\n")
        except Exception:
            pass
    
    # Decompiled code samples (first 3 functions)
    if decomp_dir.exists():
        try:
            decomp_files = sorted(decomp_dir.glob("*.json"))[:3]
            if decomp_files:
                context_parts.append("\n### Sample Decompiled Code\n")
                for df in decomp_files:
                    with open(df, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        fn_name = data.get("function_name", df.stem)
                        code = data.get("pseudocode", "")
                        if code:
                            context_parts.append(f"\n#### {fn_name}\n```c\n{code[:500]}\n```\n")
        except Exception:
            pass
    
    system_content = "".join(context_parts)
    
    # Build messages
    msgs: list[dict[str, Any]] = [{"role": "system", "content": system_content}]
    for m in history:
        role = (m.get("role") or "").strip()
        if role not in ("user", "assistant"):
            continue
        msgs.append({"role": role, "content": m.get("content") or ""})
    
    return msgs


def call_anthropic_messages(
    *,
    api_key: str,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    system_prompt: str | None = None,
    max_tokens: int = 1200,
    timeout: int = 120,
) -> dict[str, Any]:
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }

    payload: dict[str, Any] = {
        "model": model,
        "system": system_prompt or SYSTEM_PROMPT,
        "messages": messages,
        "max_tokens": max_tokens,
    }
    if tools is not None:
        payload["tools"] = tools

    with httpx.Client(timeout=timeout) as client:
        r = client.post(url, headers=headers, json=payload)
        r.raise_for_status()
        return r.json()


def build_anthropic_messages(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build Anthropic 'messages' list.

    We use the block format so we can append tool_result blocks.
    """

    out: list[dict[str, Any]] = []
    for m in history:
        role = (m.get("role") or "").strip()
        if role not in ("user", "assistant"):
            # tool results are modeled as user blocks in the tool loop
            continue
        content = m.get("content") or ""
        out.append({"role": role, "content": [{"type": "text", "text": str(content)}]})
    return out


def build_anthropic_messages_with_job_context(
    history: list[dict[str, Any]], work_dir: str, job_id: str
) -> tuple[str, list[dict[str, Any]]]:
    """Build Anthropic messages with full job context. Returns (system_prompt, messages)."""
    
    # Reuse the same context building logic from OpenAI version
    job_path = Path(work_dir) / job_id
    functions_file = job_path / "functions.json"
    strings_file = job_path / "strings.json"
    decomp_dir = job_path / "decomp"
    
    context_parts = [SYSTEM_PROMPT, "\n## Binary Context\n"]
    
    # Functions list
    if functions_file.exists():
        try:
            with open(functions_file, "r", encoding="utf-8") as f:
                functions = json.load(f)
                if functions:
                    context_parts.append(f"\n### Functions ({len(functions)} total)\n")
                    for fn in functions[:100]:
                        name = fn.get("name", "?")
                        addr = fn.get("address", "?")
                        context_parts.append(f"- {name} @ {addr}\n")
                    if len(functions) > 100:
                        context_parts.append(f"... and {len(functions) - 100} more functions\n")
        except Exception:
            pass
    
    # Strings
    if strings_file.exists():
        try:
            with open(strings_file, "r", encoding="utf-8") as f:
                strings = json.load(f)
                if strings:
                    context_parts.append(f"\n### Strings ({len(strings)} total)\n")
                    for s in strings[:50]:
                        val = s.get("value", "")
                        addr = s.get("address", "?")
                        if len(val) > 100:
                            val = val[:100] + "..."
                        context_parts.append(f"- {addr}: {val}\n")
                    if len(strings) > 50:
                        context_parts.append(f"... and {len(strings) - 50} more strings\n")
        except Exception:
            pass
    
    # Decompiled code samples
    if decomp_dir.exists():
        try:
            decomp_files = sorted(decomp_dir.glob("*.json"))[:3]
            if decomp_files:
                context_parts.append("\n### Sample Decompiled Code\n")
                for df in decomp_files:
                    with open(df, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        fn_name = data.get("function_name", df.stem)
                        code = data.get("pseudocode", "")
                        if code:
                            context_parts.append(f"\n#### {fn_name}\n```c\n{code[:500]}\n```\n")
        except Exception:
            pass
    
    system_prompt = "".join(context_parts)
    
    # Build messages (Anthropic format)
    out: list[dict[str, Any]] = []
    for m in history:
        role = (m.get("role") or "").strip()
        if role not in ("user", "assistant"):
            continue
        content = m.get("content") or ""
        out.append({"role": role, "content": [{"type": "text", "text": str(content)}]})
    
    return system_prompt, out
