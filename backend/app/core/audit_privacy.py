"""Bounded, credential-redacted audit data (also applied to legacy rows on read).

Defense in depth, not permission to record arbitrary request bodies. Unlabelled
opaque secrets cannot be reliably recognized in free-form text.
"""

from __future__ import annotations

import re
from itertools import islice
from typing import Any

from app.core.logging import REDACTED, redact_event


def safe_audit_data(value: dict[str, Any]) -> dict[str, Any]:
    budget = 1000
    characters = 16384

    def bounded(item: Any, depth: int = 0) -> Any:
        nonlocal budget, characters
        budget -= 1
        if depth >= 6 or budget < 0 or characters <= 0:
            return "[truncated]"
        if isinstance(item, dict):
            result: dict[str, Any] = {}
            for key, child in islice(item.items(), 100):
                if characters <= 0:
                    result["_truncated"] = True
                    break
                label = str(key)
                # Inspect the WHOLE key before truncation; a long prefix must
                # not hide a credential suffix from the redaction classifier.
                sensitive = redact_event(None, "info", {label: None})[label] == REDACTED
                normalized = re.sub(r"[-_.\s]", "", label).lower()
                output_key = label[: min(200, characters)]
                characters -= len(output_key)
                result[output_key] = (
                    REDACTED
                    if sensitive or normalized in {"requestbody", "responsebody", "mailbody"}
                    else bounded(child, depth + 1)
                )
            if len(item) > 100:
                result["_truncated"] = True
            return result
        if isinstance(item, (tuple, list)):
            return [bounded(child, depth + 1) for child in item[:100]]
        if isinstance(item, str):
            clean = redact_event(None, "info", {"value": item})["value"]
            text = clean[: min(2000, characters)]
            characters -= len(text)
            return text if len(text) == len(clean) else text + "[truncated]"
        if item is None or isinstance(item, (bool, int, float)):
            return item
        return f"<{type(item).__name__}>"

    result = bounded(value)
    return result if isinstance(result, dict) else {"_redacted": True}
