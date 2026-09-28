"""HybridRetrieveNode — main slot sub-node.

Namespace-scoped hybrid vector + keyword retrieval over the security KB (NIST AI 100-2,
NISC 2026, EU AI Act Art.9, OWASP LLM/Agentic Top 10). The retrieval backend is
dependency-injected (Protocol) so the node is offline-testable; production binds the
real hybrid index, tests bind the in-memory seed KB.

A zero-hit result is not an error — it flows downstream as an out-of-scope answer.
"""

from __future__ import annotations
from typing import Any

import json

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus

from src.services.service import EvidenceRetrievalBackend, InMemoryEvidenceBackend, seed_security_kb
from src.utils.audit import emit_trace_event
from framework.schemas.trust_level import TrustLevel

_TOP_K = 6


class HybridRetrieveNode(FunctionNode):
    """Retrieve namespace-scoped security evidence for the question."""

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, retrieval_backend: EvidenceRetrievalBackend | None = None) -> None:
        super().__init__()
        self._backend: EvidenceRetrievalBackend = retrieval_backend or seed_security_kb()

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code"):
            return {}

        query = state.get("validated_question") or state.get("question") or ""
        namespace = state.get("intent_namespace")

        evidence = self._backend.search(query, top_k=_TOP_K, namespace=namespace) or []
        emit_trace_event("evidence_retrieved", {"hit_count": len(evidence), "namespace": namespace}, state)

        return {
            "retrieved_evidence": json.dumps(evidence, ensure_ascii=False),
            "retrieval_hit_count": len(evidence),
            "status": AgentStatus.SUCCESS.value,
        }


__all__ = ["HybridRetrieveNode", "InMemoryEvidenceBackend", "seed_security_kb"]
