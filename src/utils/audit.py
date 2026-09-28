"""S-4 structured audit logging.

The platform prescribes ``emit_trace_event()`` from ``shared.utils.audit_logger``
for domain side-effect operations. That module is part of the published SDK
surface but is NOT present in the local SDK stub (and may move between SDK
builds). This wrapper binds the real implementation when importable and
otherwise falls back to a stderr JSON-Lines sink (the same shape), so audit
events are never silently dropped.

Field NAMES + counts only — never raw exploit payloads or sensitive vuln detail.
"""

from __future__ import annotations

import json
import sys
from typing import Any

try:  # pragma: no cover - exercised by whichever environment provides it
    from shared.utils.audit_logger import emit_trace_event as _platform_emit
except Exception:  # ModuleNotFoundError under a local stub / older SDK builds
    _platform_emit = None


def emit_trace_event(
    event_type: str, payload: dict[str, Any] | None = None, state: dict[str, Any] | None = None
) -> None:
    """Emit one domain audit event.

    Delegates to the platform ``emit_trace_event`` when available; otherwise
    writes a JSON line to stderr (captured by the platform AuditSink in prod,
    capsys-assertable in tests). ``payload`` should carry field names + counts,
    never raw values.
    """
    if _platform_emit is not None:  # pragma: no cover - only when the platform module is present
        _platform_emit(event_type, payload or {}, state or {})
        return
    event: dict[str, Any] = {
        "template_id": "CMN-C1-343",
        "event_type": event_type,
    }
    if payload:
        event.update(payload)
    if state is not None:
        tid = state.get("trace_id")
        if tid:
            event["trace_id"] = tid
        sid = state.get("session_id")
        if sid:
            event["session_id"] = sid
    print(json.dumps(event, ensure_ascii=False), file=sys.stderr)
