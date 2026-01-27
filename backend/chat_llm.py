from __future__ import annotations

import json
import os
from typing import Any

import httpx


SYSTEM_PROMPT = """You are an interactive reverse-engineering assistant.
You can ask for tools to inspect functions/strings and to navigate the UI.
When you call a tool, use it to gather evidence before making claims.
Be concise and concrete.
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
    # history entries: {role, content}
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
