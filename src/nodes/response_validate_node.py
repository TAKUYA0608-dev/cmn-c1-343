"""ResponseValidateNode — post_process slot. **S-3 gate + S-4 audit.**

The terminal node. Three S-3 responsibilities (docs/02 Step 6):
  1. Citation presence check — a grounded answer MUST carry at least one [C#]
     citation; a substantive answer without one is rejected (replaced with a safe
     refusal). Out-of-scope refusals are exempt.
  2. Sensitive vulnerability-detail / exploit redaction — concrete exploit payloads
     (shell one-liners, secret tokens, internal IPv4) are redacted out of the answer
     before it leaves the agent (this is an advisory planner, not an exploit generator).
  3. Mandatory advisory-disclaimer footer — **fail-closed**: every non-empty answer
     MUST carry the advisory / not-legal-advice footer; it is injected unconditionally.
Then S-4: emit one redacted per-invocation audit event. Always fires (even on the
error path) — silent failure is prohibited.

This is domain validation in `execute()` — distinct from the framework `@final`
credential gate (`_security_gate_output`), which still runs automatically.
"""

from __future__ import annotations

import json
import re
from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus

from src.services.service import QUERY_TERMS_MASKED, question_was_masked
from src.utils.audit import emit_trace_event
from framework.schemas.trust_level import TrustLevel

_CITATION = re.compile(r"\[C\d+\]")
# Concrete exploit / sensitive-detail signatures (redact, never emit raw).
_SECRET_TOKEN = re.compile(r"(?i)\b(?:api[_-]?key|secret|bearer|token|password)\s*[:=]\s*\S+")
_SHELL_EXEC = re.compile(r"(?i)(?:curl|wget)\s+\S+\s*\|\s*(?:sh|bash)|base64\s+-d\s*\|\s*(?:sh|bash)|eval\s*\(")
_INTERNAL_IP = re.compile(r"\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_REDACTED = "[REDACTED:sensitive]"

_DISCLAIMER = (
    "\n\n---\n*This is an automated AI-agent security advisory for pen-test planning, not "
    "an exploit toolkit or binding legal/compliance advice. Validate against the cited sources "
    "(NIST AI 100-2, OWASP, EU AI Act, NISC) and authorize testing before execution.*"
)

_REJECTED = (
    "I can't ground this plan in a cited security source, so I'm withholding it to avoid "
    "unsupported security claims. Please rephrase toward an AI-agent pen-test / vulnerability "
    "topic covered by the knowledge base."
)

_MIN_SUBSTANTIVE = 40

# Platform masking (S-2): the explanation for the `limitations` code QUERY_TERMS_MASKED.
_MASKED_NOTE = (
    "> Note: part of this question reached the agent as [MASKED] — the platform's personal-data protection "
    "replaces consecutive capitalised words such as 'Tool Misuse' or 'Agent Escape' before this agent runs. "
    "Attack vectors named only by those words were not recognised: their in_scope is null (unknown) and they "
    "are ranked on catalogue base weights, so a vector you named may be missing from the top of the list. "
    "Re-ask with category names in lower case (e.g. 'tool misuse', 'agent escape') for a question-specific "
    "ranking.\n\n"
)
_NOT_EVALUATED = (
    "Part of this question was replaced with [MASKED] by the platform's personal-data protection before "
    "analysis (it replaces consecutive capitalised words such as 'Tool Misuse' or 'Prompt Injection'), so it "
    "could not be matched against the AI-agent security knowledge base. This is not a finding that the question "
    "is out of scope. Please re-ask with attack-category names in lower case (e.g. 'tool misuse', "
    "'prompt injection'). Questions outside AI-agent pen-test planning, vulnerability prioritization or "
    "EU AI Act / NISC compliance gaps are not covered by this agent."
)


def _redact(text: str) -> tuple[str, int]:
    count = 0

    def _sub(_m: "re.Match[str]") -> str:
        nonlocal count
        count += 1
        return _REDACTED

    text = _SECRET_TOKEN.sub(_sub, text)
    text = _SHELL_EXEC.sub(_sub, text)
    text = _INTERNAL_IP.sub(_sub, text)
    return text, count


class ResponseValidateNode(FunctionNode):
    """S-3 citation/redaction/disclaimer gate + S-4 audit (terminal node)."""

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        answer = state.get("answer") or ""
        hit_count = state.get("retrieval_hit_count") or 0

        # ── S-3 (1): citation presence ──────────────────────────────────────
        exempt = state.get("error_code") or not answer or len(answer) < _MIN_SUBSTANTIVE or hit_count <= 0
        if not exempt and not _CITATION.search(answer):
            emit_trace_event("citation_gate_reject", {"reason": "no_citation"}, state)
            answer = _REJECTED
            validation_status = "rejected"
        else:
            validation_status = "passed"

        # ── S-3 (2): sensitive vuln-detail / exploit redaction ──────────────
        answer, redaction_count = _redact(answer)
        if redaction_count and validation_status == "passed":
            validation_status = "redacted"

        # ── Platform masking (S-2): part of the question never reached the agent ──
        # A masked question that retrieved nothing is "not evaluated", not out of scope; one that did retrieve
        # evidence is answered with a leading note, and `limitations` carries the stable code.
        masked = question_was_masked(state.get("validated_question") or state.get("question") or "")
        limitations = [QUERY_TERMS_MASKED] if masked else []
        if masked and not state.get("error_code") and hit_count <= 0:
            answer = _NOT_EVALUATED
            validation_status = "not_evaluated"
        elif masked and answer and not state.get("error_code"):
            answer = _MASKED_NOTE + answer

        # ── S-3 (3): mandatory advisory-disclaimer footer (fail-closed) ─────
        disclaimer_applied = False
        if answer and "not an exploit toolkit" not in answer:
            answer = answer + _DISCLAIMER
            disclaimer_applied = True
        elif answer and "not an exploit toolkit" in answer:
            disclaimer_applied = True

        # ── S-4: redacted per-invocation audit event (always fires) ─────────
        def _count(field: str) -> int:
            try:
                v = json.loads(state.get(field) or "[]")
                return len(v) if isinstance(v, (list, dict)) else 0
            except (json.JSONDecodeError, TypeError):
                return 0

        payload: dict[str, Any] = {
            "intent_namespace": state.get("intent_namespace"),
            "question_length": len(state.get("validated_question") or state.get("question") or ""),
            "answer_length": len(answer),
            "citation_count": _count("citations"),
            "retrieval_hit_count": hit_count,
            "priority_count": _count("priority_table"),
            "compliance_gap_count": _count("compliance_gaps"),
            "validation_status": validation_status,
            "redaction_count": redaction_count,
            "limitations": limitations,
        }
        if state.get("error_code"):
            payload["error_code"] = state["error_code"]
        emit_trace_event("agent_invoke_complete", payload, state)

        return {
            "answer": answer,
            "validation_status": validation_status,
            "limitations": json.dumps(limitations, ensure_ascii=False),
            "redaction_count": redaction_count,
            "disclaimer_applied": disclaimer_applied,
            "audit_logged": True,
            "status": AgentStatus.SUCCESS.value,
        }
