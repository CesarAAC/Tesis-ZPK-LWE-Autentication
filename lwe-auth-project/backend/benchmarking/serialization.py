from __future__ import annotations

import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON-compatible data deterministically using UTF-8."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def serialized_size_bytes(value: Any) -> int:
    return len(canonical_json_bytes(value))


def wire_message_bytes(message_type: str, protocol_name: str, payload: Any) -> bytes:
    """Canonical application-layer envelope used for bandwidth comparisons."""
    return canonical_json_bytes(
        {
            "type": message_type,
            "protocol": protocol_name,
            "payload": payload,
        }
    )
