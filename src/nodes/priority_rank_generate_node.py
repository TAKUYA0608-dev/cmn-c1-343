"""PriorityRankGenerateNode — main slot sub-node.

Applies the **deterministic CVSS-AI rubric** (severity × exploitability × AI-vector
weighting) over the candidate attack vectors and ranks them. Deterministic (no LLM):
the priority scores are derived from the static `AI_ATTACK_VECTORS` catalog + the
QueryNormalize attack-surface tags, so the ranking is auditable and stable — a
security engineer can defend it. The LLM is only used for the rationale narrative in
AnswerGenerate, never for scoring.

Vectors whose `attack_surface` matches a tag extracted from the query/spec get an
AI-vector relevance boost; otherwise the catalog base weighting applies.
"""

from __future__ import annotations
from typing import Any

import json

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus

from src.services.service import AI_ATTACK_VECTORS, cvss_ai_score, question_was_masked
from src.utils.audit import emit_trace_event
from framework.schemas.trust_level import TrustLevel


class PriorityRankGenerateNode(FunctionNode):
    """Deterministic CVSS-AI severity × exploitability ranking of attack vectors."""

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code"):
            return {}

        # Zero retrieval → nothing to ground a ranking on; downstream emits out-of-scope.
        if (state.get("retrieval_hit_count") or 0) <= 0:
            return {
                "priority_table": json.dumps([], ensure_ascii=False),
                "priority_rationale": "no evidence retrieved",
                "status": AgentStatus.SUCCESS.value,
            }

        try:
            ctx = json.loads(state.get("attack_surface_context") or "{}")
        except (json.JSONDecodeError, TypeError):
            ctx = {}
        tags = set(ctx.get("tags") or [])
        # The platform's S-2 pass masks Title-Case runs ("Tool Misuse", "Agent Escape", "Prompt Injection")
        # before this template sees the question, so a vector the caller named may be invisible here: its
        # relevance is unknown (None), never "out of scope" (False).
        masked = question_was_masked(state.get("validated_question") or state.get("question") or "")

        rows = []
        for v in AI_ATTACK_VECTORS:
            # AI-vector weight: relevance-boosted when the vector's attack surface was
            # detected in the query/spec; baseline 0.7 otherwise.
            ai_weight = 1.0 if v["attack_surface"] in tags else 0.7
            score = cvss_ai_score(v["severity"], v["exploitability"], ai_weight)
            rows.append(
                {
                    "vector": v["vector"],
                    "owasp_ref": v["owasp_ref"],
                    "severity": v["severity"],
                    "exploitability": v["exploitability"],
                    "score": score,
                    "in_scope": True if v["attack_surface"] in tags else (None if masked else False),
                }
            )

        rows.sort(key=lambda r: r["score"], reverse=True)
        for i, r in enumerate(rows, start=1):
            r["rank"] = i

        top = rows[0]["vector"] if rows else None
        emit_trace_event("priority_ranked", {"vector_count": len(rows), "top_vector": top}, state)
        return {
            "priority_table": json.dumps(rows, ensure_ascii=False),
            "priority_rationale": "deterministic CVSS-AI rubric (severity × exploitability × AI-vector weight)"
            + (
                "; part of the question was masked by the platform, so vectors named only by the masked words"
                " received no relevance boost and their in_scope is null (unknown)"
                if masked
                else ""
            ),
            "status": AgentStatus.SUCCESS.value,
        }
