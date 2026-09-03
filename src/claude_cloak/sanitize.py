"""Telemetry-path blocking and request-body scrubbing."""

from __future__ import annotations

import json

from . import state
from .constants import (
    _SANITIZE_FIELDS_NORMALIZED,
    _SANITIZE_OBJECTS_NORMALIZED,
    BLOCKED_PATH_REGEX,
    SANITIZE_BODY_FIELDS,
    SANITIZE_BODY_OBJECTS,
)
from .identity import generate_consistent_id


def is_blocked_path(path: str) -> bool:
    """Check if path matches any blocked telemetry pattern."""
    return any(pattern.search(path) for pattern in BLOCKED_PATH_REGEX)


def sanitize_body(body: bytes, content_type: str | None) -> bytes:
    """Strip device-identifying fields from JSON request bodies."""

    if not body:
        return body

    if not content_type or "json" not in content_type.lower():
        return body

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body

    if not isinstance(data, dict):
        return body

    changed = _sanitize_dict(data)

    if changed:
        state.runtime.sanitized_bodies_count += 1
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()

    return body


def _sanitize_dict(data: dict) -> bool:
    """Recursively sanitize a dict. Returns True if any field was modified."""
    changed = False

    for key in list(data.keys()):
        key_lower = key.lower().replace("-", "_")

        # Remove entire objects that contain device info
        if key in SANITIZE_BODY_OBJECTS or key_lower in _SANITIZE_OBJECTS_NORMALIZED:
            data[key] = {}
            changed = True
            continue

        # Replace identifying string fields with consistent fakes
        if key in SANITIZE_BODY_FIELDS or key_lower in _SANITIZE_FIELDS_NORMALIZED:
            if isinstance(data[key], str) and data[key]:
                data[key] = generate_consistent_id(key)
                changed = True
            continue

        # Recurse into nested dicts
        if isinstance(data[key], dict):
            if _sanitize_dict(data[key]):
                changed = True
        elif isinstance(data[key], list):
            for item in data[key]:
                if isinstance(item, dict) and _sanitize_dict(item):
                    changed = True

    return changed
