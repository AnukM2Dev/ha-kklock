"""Sanitized payload summaries for KK Home debug logs."""

from __future__ import annotations

from typing import Any


def summarize_payload(payload: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "..."
    if payload is None or isinstance(payload, (bool, int, float)):
        return payload
    if isinstance(payload, str):
        return f"str:{len(payload)}"
    if isinstance(payload, list):
        if not payload:
            return []
        return [summarize_payload(payload[0], depth + 1), f"+{len(payload) - 1}"]
    if isinstance(payload, dict):
        redacted = {
            "token",
            "accesstoken",
            "access_token",
            "authorization",
            "password",
            "sign",
            "encryptdata",
            "mail",
        }
        out = {}
        for key, value in payload.items():
            if str(key).lower() in redacted and isinstance(value, str):
                out[key] = f"redacted:{len(value)}"
            else:
                out[key] = summarize_payload(value, depth + 1)
        return out
    return type(payload).__name__
