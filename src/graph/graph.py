"""CMN-C1-343 PenTestSecurityQAAgent — graph composition.

L1-direct inheritance from AgentBaseGraph (Cat 1). The 6-step SoT workflow is composed
into the framework's three writable slots; the framework owns initialize/finalize, edge
wiring, and routing (START → initialize → pre_process → main → post_process → finalize →
END, with the RETRY edge back to pre_process).

    pre_process  = QueryNormalizeNode    (S-1 input boundary + attack-surface extraction)
    main         = PenTestMainNode       (IntentClassify → HybridRetrieve
                                          → PriorityRankGenerate → AnswerGenerate)
    post_process = ResponseValidateNode  (S-3 citation/redaction/disclaimer + S-4 audit)

Cat 1 shape: `main` is a composite FunctionNode (single graph slot, single execute()
boundary) — NOT a Cat 2 GraphNode-in-main. Retrieval + LLM backends are dependency-
injected so the agent is offline-testable; production binds the real hybrid security KB
index.

LLM binding: explicit `llm_client` kw > `config["llm"]` (the Marketplace entry point
places a lazy Azure client there; adapted by `resolve_llm_client`) > none. With none,
the rationale narrative is replaced by a named `LLM_NOT_CONFIGURED` notice and the
deterministic plan / priorities / gaps / citations are still delivered — no stub is bound.
"""

from __future__ import annotations
from typing import Any

import json

from framework.graph.agent_base_graph import AgentBaseGraph

from src.schemas.state import PenTestState
from src.services.service import EvidenceRetrievalBackend, LLMClient, resolve_llm_client
from src.nodes.query_normalize_node import QueryNormalizeNode
from src.nodes.main_node import PenTestMainNode
from src.nodes.response_validate_node import ResponseValidateNode


class PenTestSecurityQAAgent(AgentBaseGraph):
    """AI-agent penetration-test & vulnerability-prioritization Q&A agent (Cat 1)."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        retrieval_backend: EvidenceRetrievalBackend | None = None,
        llm_client: LLMClient | None = None,
    ) -> None:
        self._retrieval_backend = retrieval_backend
        self._llm_client = resolve_llm_client(llm_client, config)
        super().__init__(config)

    @property
    def name(self) -> str:
        return "PenTestSecurityQAAgent"

    @property
    def state_schema(self) -> type:
        """Domain State so per-node fields survive node merges (LangGraph drops
        keys not declared in the schema)."""
        return PenTestState

    def register_nodes(self) -> None:
        super().register_nodes()  # framework injects InitializeNode + FinalizeNode
        self._nodes["pre_process"] = QueryNormalizeNode()
        self._nodes["main"] = PenTestMainNode(
            retrieval_backend=self._retrieval_backend,
            llm_client=self._llm_client,
        )
        self._nodes["post_process"] = ResponseValidateNode()

    def get_output(self, state: dict[str, Any]) -> dict[str, Any]:
        """Surface the pen-test plan payload (this agent writes answer/citations/
        priority_table/compliance_gaps, not the framework-default output)."""
        # The Marketplace runner rejects a successful invocation whose output
        # is missing (verified on a deployed Pod), and a degraded run
        # (SUCCESS + error_code) leaves "answer" unset. Report the degradation —
        # this states what happened, it does not invent an answer.
        #
        # Only on SUCCESS: a request refused by the S-2 gate (status ERROR) must
        # keep publishing nothing, or the refusal is undone.
        _output = state.get("answer")
        if not _output and str(state.get("status", "")).lower().endswith("success"):
            _code = state.get("error_code") or "NO_CONTENT"
            _output = (
                "This request could not be completed "
                f"(error_code={_code}). No content was produced; "
                "see error_code and error_log for the degradation cause."
            )
        return {
            "output": _output,
            "answer": state.get("answer"),
            "intent_namespace": state.get("intent_namespace"),
            "citations": state.get("citations"),
            "priority_table": state.get("priority_table"),
            "priority_rationale": state.get("priority_rationale"),
            "compliance_gaps": state.get("compliance_gaps"),
            "retrieved_evidence": state.get("retrieved_evidence"),
            "retrieval_hit_count": state.get("retrieval_hit_count"),
            "validation_status": state.get("validation_status"),
            # Stable limitation codes as a list ([] when none) — e.g. QUERY_TERMS_MASKED.
            "limitations": json.loads(state.get("limitations") or "[]"),
            "redaction_count": state.get("redaction_count"),
            "disclaimer_applied": state.get("disclaimer_applied"),
            "audit_logged": state.get("audit_logged"),
            "status": state.get("status"),
            "error_code": state.get("error_code"),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
            "error_log": state.get("error_log", []),
        }


# Backward-compat alias — the scaffold (api/server.py) imports `Graph`.
Graph = PenTestSecurityQAAgent
