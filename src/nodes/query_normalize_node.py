"""QueryNormalizeNode — pre_process slot / S-1 input boundary.

Entity extraction ONLY: normalize the agent spec +
question, extract attack-surface tags (prompt-injection / rag-poison / tool-misuse /
agent-escape) + intent, and reject prompt-injection before any LLM sees the input.
Namespace *classification* is the next node's responsibility (IntentClassify).
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from src.utils.audit import emit_trace_event

_MAX_LEN = 6000

_INJECTION = re.compile(
    r"(?i)(ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|disregard\s+(?:the\s+)?(?:system|previous)\s+(?:prompt|instructions)"
    r"|reveal\s+(?:your\s+)?system\s+prompt"
    r"|you\s+are\s+now\s+(?:a|an|in)\b"
    r"|<\s*script\b|</\s*script\s*>)"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Attack-surface tag hints (entity extraction only — classification is downstream).
_ATTACK_SURFACE_HINTS = {
    "prompt-injection": (
        "prompt injection",
        "jailbreak",
        "system prompt",
        "instruction override",
        "プロンプトインジェクション",
    ),
    "rag-poison": ("rag", "retrieval", "knowledge base", "poison", "embedding", "vector store"),
    "tool-misuse": ("tool", "function call", "api", "plugin", "agency", "excessive"),
    "agent-escape": ("escape", "sandbox", "isolation", "orchestration", "topology", "container"),
}
_INTENT_HINTS = {
    "pentest-plan": ("pen-test", "pentest", "penetration", "red team", "red-team", "test plan", "runbook"),
    "priority": ("priority", "prioritize", "rank", "severity", "cvss", "risk"),
    "compliance-gap": ("compliance", "gap", "eu ai act", "nisc", "article 9", "audit"),
}


def _extract(text: str) -> dict[str, Any]:
    low = text.lower()
    tags = sorted({t for t, hints in _ATTACK_SURFACE_HINTS.items() if any(h in low for h in hints)})
    intent = next((i for i, hints in _INTENT_HINTS.items() if any(h in low for h in hints)), "pentest-plan")
    return {"tags": tags, "intent": intent}


class QueryNormalizeNode(FunctionNode):
    """S-1: validate + normalize the question/spec; extract attack-surface; reject injection."""

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code"):
            return {}

        ic = state.get("input_context") or {}
        raw = state.get("question") or state.get("user_input") or ""

        if not raw or not str(raw).strip():
            return {
                "error_code": "INPUT_EMPTY",
                "error_message": "QueryNormalizeNode: question is empty or missing",
                "status": AgentStatus.SUCCESS.value,
            }
        if len(str(raw)) > _MAX_LEN:
            return {
                "error_code": "INPUT_TOO_LONG",
                "error_message": f"QueryNormalizeNode: question exceeds {_MAX_LEN} chars",
                "status": AgentStatus.SUCCESS.value,
            }
        if _INJECTION.search(str(raw)):
            return {
                "error_code": "INJECTION_DETECTED",
                "error_message": "QueryNormalizeNode: prompt-injection pattern rejected",
                "status": AgentStatus.SUCCESS.value,
            }

        validated = unicodedata.normalize("NFKC", str(raw))
        validated = _CONTROL.sub("", validated).strip()
        validated = re.sub(r"\s+", " ", validated)

        # Fold the agent spec text into the extraction surface (attack-surface tags may
        # come from the spec, e.g. declared tools/RAG sources) without storing secrets raw.
        spec = state.get("agent_spec") or ic.get("agent_spec") or ""
        surface_text = f"{validated} {spec}"

        out: dict[str, Any] = {
            "question": validated,
            "validated_question": validated,
            "attack_surface_context": json.dumps(_extract(surface_text), ensure_ascii=False),
            "status": AgentStatus.SUCCESS.value,
        }
        if spec:
            out["agent_spec"] = str(spec)
        # S-4 (central-CI audit-trace gate): record that this
        # boundary node completed. Field NAMES only — never values.
        emit_trace_event("query_normalize_completed", {}, state)
        return out
