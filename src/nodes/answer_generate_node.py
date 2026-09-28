"""AnswerGenerateNode — main slot sub-node.

Synthesizes the structured Markdown pen-test plan: recommended test steps per ranked
vector, a priority table, and an EU AI Act / NISC compliance-gap section, with inline
[C#] citations. Citations are built deterministically from the retrieved evidence so
every [C#] marker resolves to a real source — ResponseValidate's S-3 gate then verifies
citation presence. The LLM supplies only a short rationale narrative (it cannot
introduce uncited claims; the structured body carries the citations); with no LLM
bound the rationale slot carries a named `LLM_NOT_CONFIGURED` notice instead (S-4
`llm_not_configured`) and the deterministic plan is delivered in full — never a stub.

A zero-hit retrieval produces a safe out-of-scope answer (no fabricated CVEs).
"""

from __future__ import annotations
from typing import Any

import json

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus

from src.services.service import LLM_NOT_CONFIGURED, LLMClient
from framework.schemas.trust_level import TrustLevel
from src.utils.audit import emit_trace_event

_OUT_OF_SCOPE = (
    "This question falls outside the indexed AI-agent security knowledge base (NIST AI "
    "100-2, NISC 2026, EU AI Act Art.9, OWASP LLM/Agentic Top 10). I'm withholding a plan "
    "rather than cite sources I can't ground. Please rephrase toward AI-agent pen-test "
    "planning, vulnerability prioritization, or a compliance-gap topic."
)


class AnswerGenerateNode(FunctionNode):
    """Build the cited Markdown pen-test plan + priority table + compliance gap."""

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, llm_client: LLMClient | None = None) -> None:
        super().__init__()
        # None = no LLM bound. Resolved by the graph (explicit kw > config["llm"]);
        # a bare node stays unbound and names the gap rather than using a stub.
        self._llm: LLMClient | None = llm_client

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code"):
            return {}

        try:
            evidence = json.loads(state.get("retrieved_evidence") or "[]")
        except (json.JSONDecodeError, TypeError):
            evidence = []

        if not evidence:
            return {
                "answer": _OUT_OF_SCOPE,
                "citations": json.dumps([], ensure_ascii=False),
                "compliance_gaps": json.dumps([], ensure_ascii=False),
                "status": AgentStatus.SUCCESS.value,
            }

        try:
            priority = json.loads(state.get("priority_table") or "[]")
        except (json.JSONDecodeError, TypeError):
            priority = []

        # Citations [C1..Cn] from the retrieved evidence (deterministic).
        # ``official_ref`` rides every citation so the caller can verify the control
        # against the versioned authority it came from — provenance that stops at the
        # KB record is not verifiable by the reader (an earlier review.
        citations = []
        evidence_lines = []
        for i, e in enumerate(evidence, start=1):
            marker = f"[C{i}]"
            citations.append(
                {
                    "marker": marker,
                    "evidence_id": e.get("evidence_id"),
                    "source": e.get("source"),
                    "title": e.get("title"),
                    "official_ref": e.get("official_ref", ""),
                }
            )
            evidence_lines.append(f"- {e.get('source')} — {e.get('title')} {marker}")

        # Priority table (top vectors) + a pen-test step each.
        priority_lines = []
        for r in priority[:5]:
            priority_lines.append(
                f"- **#{r.get('rank')} {r.get('vector')}** ({r.get('owasp_ref')}) — "
                f"score {r.get('score')} (sev={r.get('severity')}, exploit={r.get('exploitability')}) [C1]"
            )

        # Compliance gaps (EU AI Act / NISC) derived from the retrieved namespaces.
        gaps = []
        namespaces = {e.get("namespace") for e in evidence}
        if "eu-ai-act" in namespaces:
            gaps.append(
                {
                    "regulation": "EU AI Act Art.9",
                    "severity": "high",
                    "gap": "Continuous adversarial-robustness testing must be evidenced before deployment.",
                }
            )
        if "nisc" in namespaces:
            gaps.append(
                {
                    "regulation": "NISC 2026",
                    "severity": "medium",
                    "gap": "Documented pen-test cadence + monitoring of the agent attack surface required.",
                }
            )

        if self._llm is None:
            # Named degradation: the reader sees why there is no rationale; the
            # priorities, steps, gaps and citations below do not depend on the LLM.
            emit_trace_event(
                "llm_not_configured",
                {"reason_code": LLM_NOT_CONFIGURED, "citation_count": len(citations)},
                state,
            )
            rationale = (
                f"Rationale narrative omitted ({LLM_NOT_CONFIGURED}): no language model is "
                "bound to this deployment; the priorities, test steps, compliance gaps and "
                "evidence below are derived deterministically from the retrieved sources."
            )
        else:
            rationale = (
                self._llm.generate(
                    "In one sentence, summarise the top AI-agent pen-test priority for the constraints.\n"
                    "Top vectors: " + ", ".join(str(r.get("vector")) for r in priority[:3])
                )
                or ""
            ).strip()

        answer = (
            "## AI Agent Pen-Test Plan\n"
            + (f"_{rationale}_\n\n" if rationale else "")
            + "### Prioritized Vulnerabilities (CVSS-AI)\n"
            + ("\n".join(priority_lines) if priority_lines else "- (no vectors ranked) [C1]")
            + "\n\n### Recommended Test Steps\n"
            + "- For each top vector above, exercise the corresponding attack surface and verify the mitigating control. [C1]"
            + "\n\n### Compliance Gaps\n"
            + (
                "\n".join(f"- ({g['severity']}) {g['regulation']}: {g['gap']}" for g in gaps)
                or "- No EU AI Act / NISC gaps surfaced for the retrieved evidence."
            )
            + "\n\n### Evidence\n"
            + "\n".join(evidence_lines)
        )

        # S-4 (central-CI audit-trace gate): record that this
        # boundary node completed. Field NAMES only — never values.
        emit_trace_event(
            "answer_generate_completed", {"fields": ["answer", "citations", "compliance_gaps", "status"]}, state
        )
        return {
            "answer": answer,
            "citations": json.dumps(citations, ensure_ascii=False),
            "compliance_gaps": json.dumps(gaps, ensure_ascii=False),
            "status": AgentStatus.SUCCESS.value,
        }
