"""CMN-C1-343 AI Agent Penetration Test & Vulnerability Assessment Q&A — State.

Flat TypedDict per the platform's node and state-safety contracts:
every field is an Optional primitive or a JSON-serialized string (msgpack
round-trips cleanly). No Pydantic, no dataclass, no arbitrary Python objects,
and never JWT / API keys / credentials / raw exploit payloads.

Pipeline (docs/02_design.md §Architecture Overview):
    QueryNormalize (S-1 input) → IntentClassify → HybridRetrieve
    → PriorityRankGenerate → AnswerGenerate
    → ResponseValidate (S-3 citation/redaction/disclaimer + S-4 audit)
"""

from __future__ import annotations

from typing import Optional

from framework.schemas.agent_state import AgentState


class PenTestState(AgentState):
    """State for the AI-agent pen-test / vulnerability-prioritization Q&A pipeline.

    Shared fields (user_input, status, session_id, node_history, error_log,
    caller_trust_level, trace_id, correlation_id, …) are inherited from
    AgentState. Only domain fields are declared here; LangGraph drops keys not
    declared in the schema, so every field the pipeline writes MUST appear below.
    """

    # ─── Input (caller supplies via user_input + input_context) ───
    question: Optional[str]  # NL pen-test / vuln / compliance question
    agent_spec: Optional[str]  # JSON: target agent spec (prompt outline / tools / RAG / topology)
    known_vulns: Optional[str]  # JSON/text: known vuln info / past incident logs (optional)

    # ─── QueryNormalizeNode (pre_process, S-1 input boundary) ───
    validated_question: Optional[str]  # sanitized / normalized question
    attack_surface_context: Optional[
        str
    ]  # JSON: {tags[], intent} (prompt-injection/rag-poison/tool-misuse/agent-escape)

    # ─── IntentClassifyNode ───
    intent_namespace: Optional[str]  # "pentest" | "vulnerability" | "eu-ai-act" | "nisc"
    classification_rationale: Optional[str]

    # ─── HybridRetrieveNode (namespace-scoped over security KB) ───
    retrieved_evidence: Optional[str]  # JSON: [{evidence_id, source, namespace, title, text, score}]
    retrieval_hit_count: Optional[int]

    # ─── PriorityRankGenerateNode (deterministic CVSS-AI rubric) ───
    priority_table: Optional[str]  # JSON: [{vector, owasp_ref, severity, exploitability, score, rank}]
    priority_rationale: Optional[str]

    # ─── AnswerGenerateNode (cited Markdown pen-test plan) ───
    answer: Optional[str]  # Markdown plan with inline [C#] citations
    citations: Optional[str]  # JSON: [{marker, evidence_id, source, title, official_ref}]
    compliance_gaps: Optional[str]  # JSON: [{regulation, gap, severity}]

    # ─── ResponseValidateNode (S-3 citation/redaction/disclaimer gate + S-4 audit) ───
    validation_status: Optional[str]  # "passed" | "redacted" | "rejected" | "not_evaluated"
    limitations: Optional[str]  # JSON: [code] — e.g. QUERY_TERMS_MASKED (platform masked part of the question)
    redaction_count: Optional[int]  # sensitive vuln-detail values redacted out of the answer
    disclaimer_applied: Optional[bool]  # mandatory advisory disclaimer footer injected
    audit_logged: Optional[bool]  # True once the S-4 audit event is emitted

    # ─── Error propagation (any node; downstream nodes self-skip) ───
    error_code: Optional[str]
    error_message: Optional[str]


# Backward-compat alias: the scaffold (graph.py / server.py) references `State`.
State = PenTestState
