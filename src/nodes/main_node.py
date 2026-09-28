"""PenTestMainNode (main slot) — composes the 4 core reasoning steps.

    IntentClassify → HybridRetrieve → PriorityRankGenerate → AnswerGenerate

Sub-node composition: sub-nodes are instantiated in
`__init__()` (`self._seq`) and called via `sub_node.execute(state)` **directly —
not `__call__()`**. The composite therefore owns the single S-2/S-3/S-4 boundary and the
framework hooks are not re-invoked per sub-node. Each sub-node returns only its changed
fields and self-skips on `error_code`. Retrieval + LLM backends are dependency-injected
into the sub-nodes that need them.
"""

from __future__ import annotations

from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus

from src.services.service import EvidenceRetrievalBackend, LLMClient
from src.nodes.intent_classify_node import IntentClassifyNode
from src.nodes.hybrid_retrieve_node import HybridRetrieveNode
from src.nodes.priority_rank_generate_node import PriorityRankGenerateNode
from src.nodes.answer_generate_node import AnswerGenerateNode
from framework.schemas.trust_level import TrustLevel
from src.utils.audit import emit_trace_event


class PenTestMainNode(FunctionNode):
    """main slot — IntentClassify → HybridRetrieve → PriorityRankGenerate → AnswerGenerate."""

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def __init__(
        self,
        retrieval_backend: EvidenceRetrievalBackend | None = None,
        llm_client: LLMClient | None = None,
    ) -> None:
        super().__init__()
        self._seq: list[FunctionNode] = [
            IntentClassifyNode(llm_client=llm_client),
            HybridRetrieveNode(retrieval_backend=retrieval_backend),
            PriorityRankGenerateNode(),
            AnswerGenerateNode(llm_client=llm_client),
        ]

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        working = dict(state)
        deltas: dict[str, Any] = {}
        for node in self._seq:
            updates = node.execute(working) or {}
            working.update(updates)
            deltas.update(updates)
        # Intentional: the composite reports SUCCESS so the framework router always
        # advances to post_process. A sub-node failure is carried in the `error_code`
        # delta (set by the failing sub-node), which ResponseValidate inspects and
        # surfaces in the S-4 audit + error response. (Reporting ERROR here would
        # short-circuit before the terminal audit/redaction gate runs.)
        # Design ref: docs/02 "Composition Pattern"; same pattern as its sibling templates.
        deltas["status"] = AgentStatus.SUCCESS.value
        # S-4 (central-CI audit-trace gate): record that this
        # boundary node completed. Field NAMES only — never values.
        emit_trace_event("pen_test_main_completed", {}, state)
        return deltas
