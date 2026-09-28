"""IntentClassifyNode — main slot sub-node.

Standalone L1 node (separate prompt + state from QueryNormalize). Classifies the
query namespace (pentest / vulnerability /
eu-ai-act / nisc) from the question + attack-surface context, via heuristic keyword
scoring + LLM disambiguation. The namespace decides the retrieval routing.
"""

from __future__ import annotations
from typing import Any


from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus

from src.services.service import LLM_NOT_CONFIGURED, NAMESPACES, LLMClient
from src.utils.audit import emit_trace_event
from framework.schemas.trust_level import TrustLevel

_KEYWORDS = {
    "pentest": ("pen-test", "pentest", "penetration", "red team", "red-team", "runbook", "test plan"),
    "vulnerability": ("vulnerability", "vuln", "cve", "exploit", "owasp", "attack", "severity", "cvss"),
    "eu-ai-act": ("eu ai act", "article 9", "high-risk", "conformity", "ce mark"),
    "nisc": ("nisc", "japan", "監視", "運用", "security operations"),
}


def _heuristic(text: str) -> str | None:
    low = text.lower()
    scores = {ns: sum(1 for kw in kws if kw in low) for ns, kws in _KEYWORDS.items()}
    ranked = sorted(((ns, n) for ns, n in scores.items() if n > 0), key=lambda kv: kv[1], reverse=True)
    return ranked[0][0] if ranked else None


class IntentClassifyNode(FunctionNode):
    """Classify the query namespace (heuristic + LLM)."""

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, llm_client: LLMClient | None = None) -> None:
        super().__init__()
        # None = no LLM bound. Resolved by the graph (explicit kw > config["llm"]);
        # a bare node stays unbound and falls back to the default namespace.
        self._llm: LLMClient | None = llm_client

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code"):
            return {}

        question = state.get("validated_question") or state.get("question") or ""

        ns = _heuristic(question)
        if ns:
            rationale = "heuristic keyword scoring"
        elif self._llm is None:
            # No LLM to disambiguate: take the default namespace and record why.
            emit_trace_event("llm_not_configured", {"reason_code": LLM_NOT_CONFIGURED}, state)
            ns, rationale = "pentest", f"default namespace (no signal; {LLM_NOT_CONFIGURED})"
        else:
            prompt = (
                "Classify the security query namespace into exactly one of: "
                f"{', '.join(NAMESPACES)}. Reply with the single label only.\n\nQuestion: {question}"
            )
            raw = (self._llm.generate(prompt) or "").strip().lower()
            ns = next((n for n in NAMESPACES if n in raw), None)
            if ns:
                rationale = "LLM namespace disambiguation"
            else:
                ns, rationale = "pentest", "default namespace (no signal)"

        emit_trace_event("intent_classified", {"namespace": ns}, state)
        return {
            "intent_namespace": ns,
            "classification_rationale": rationale,
            "status": AgentStatus.SUCCESS.value,
        }
