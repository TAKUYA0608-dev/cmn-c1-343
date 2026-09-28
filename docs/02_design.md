# Template Design Specification — CMN-C1-343

**Template ID:** CMN-C1-343
**Agent Class:** PenTestSecurityQAAgent
**Category:** Cat 1 (single technical capability — AI-agent pen-test & vulnerability prioritization Q&A)
**Industry:** CMN (cross-industry)
**SoT:** scaffold/#1247, SoT note #940681 (JP) / #940686 (EN)

> **Clarifications carried from evaluation:**
> - **(F-01)** L1 base is `AgentBaseGraph` (L1-direct). `VectorRAGAgent` is a *pattern reference
>   only* (concept), **not** an L2 inheritance. 6-node flow per the issue description.
> - **(F-03)** Query-routing boundary vs siblings: OWASP-Agentic *policy validate / gap report* →
>   a sibling template; *runtime safety testing (RAMPART)* → a sibling template; *vuln-scan report* →
>   a sibling template. **This template** = AI-agent **pen-test planning + vulnerability
>   prioritization + multi-source compliance gap** Q&A.
> - **Out of scope** (SoT §4): live exploit execution / automated PoC generation / live probing
>   (a future Cat 3 autonomous agent). Advisory only; no legal advice.

## Position in AgentCore Architecture

- **L1 Base: `AgentBaseGraph`** (Cat 1, L1-direct per the graph contract; `agents/base/*` not used; VectorRAG is a pattern, not an L2 class)
- **Three-Layer Separation:**
  - State: flat TypedDict composition (`PenTestState(AgentState)`) — no Pydantic
  - Node: L1 inheritance (`FunctionNode`, `execute(self, state, config=None) -> dict` override only)
  - Graph: composition (`register_nodes()` fills the 3 writable slots)

## Architecture Overview

### Node Configuration

The SoT 6-step workflow is composed into the framework's three writable slots. The domain
nodes map as:

| Slot | Node | Responsibility | Inherits |
|------|------|---------------|----------|
| initialize | InitializeNode | schema_version, session_id, trust_level | default (framework) |
| **pre_process** | **QueryNormalizeNode** | S-1 input boundary: NFKC normalize, injection reject, size cap; **extraction only** — normalize agent spec + question, extract attack-surface tags (prompt-injection / rag-poison / tool-misuse / agent-escape) + intent. No classification here. | FunctionNode |
| **main** | **PenTestMainNode** composing → | composite of the 4 reasoning sub-nodes below | FunctionNode |
| ↳ | IntentClassifyNode | classify the query namespace (pentest / vulnerability / eu-ai-act / nisc) via heuristic keyword scoring + LLM disambiguation; decides the retrieval plan | FunctionNode |
| ↳ | HybridRetrieveNode | namespace-scoped hybrid vector+keyword retrieval over the security KB (NIST AI 100-2, NISC 2026, EU AI Act Art.9, OWASP LLM/Agentic Top 10) | FunctionNode |
| ↳ | PriorityRankGenerateNode | **deterministic CVSS-AI rubric** (severity × exploitability × AI-vector weighting) over candidate vulnerabilities → ranked priority table + per-item rationale | FunctionNode |
| ↳ | AnswerGenerateNode | structured Markdown pen-test plan + priority table + EU AI Act compliance gap, with inline [C#] citations; out-of-scope deflection on 0 hits | FunctionNode |
| **post_process** | **ResponseValidateNode** | **S-3 gate**: citation presence check, **sensitive vulnerability-detail / exploit redaction**, **mandatory advisory disclaimer fail-closed**; **S-4 audit** (always fires) | FunctionNode |
| finalize | FinalizeNode | response_metadata, total_time_ms | default (framework) |

### Data Flow

```
START → initialize → pre_process(QueryNormalize) → main(PenTestMain) → {route}
        → post_process(ResponseValidate) → finalize → END
                                            ↓ (retry, max 3)
                                          pre_process
```

Error propagation: any node sets `error_code`; downstream sub-nodes self-skip (`return {}`).
A zero-hit retrieval flows to a safe out-of-scope answer (no fabricated CVEs / priorities).
ResponseValidate's S-4 audit fires on every path, including errors.

LLM binding (ADR-7): explicit `llm_client` > `config["llm"]` (adapted by
`service.resolve_llm_client`) > none. With none, IntentClassify takes the default namespace
when the heuristic has no signal, and AnswerGenerate puts a named `LLM_NOT_CONFIGURED`
notice in the rationale slot; the deterministic priority table, test steps, compliance gaps
and citations are delivered unchanged and `error_code` stays unset. No stub LLM is ever
bound by default (the stub is test-only, explicit injection).

### Error / degradation codes (`status=success` + non-empty `output`)

| code | Set by | Meaning | Output text |
|------|--------|---------|-------------|
| `LLM_NOT_CONFIGURED` (S-4 `llm_not_configured` + rationale notice; **not** an `error_code`) | IntentClassify / AnswerGenerate | no LLM bound (`llm_client` / `config["llm"]`) | the full deterministic plan with the notice where the rationale would be |
| node error (`status=error`) | framework `__call__` | a sub-node raised (backend failure, **a bound LLM that raised** — the adapter never swallows it) | nothing published; the exception is named in `error_log` |
| `QUERY_TERMS_MASKED` (in `limitations`; **not** an `error_code`) | PriorityRankGenerate / ResponseValidate | the platform masked part of the question (see below) | plan with a leading note, or the `not_evaluated` notice on zero hits |

**Platform masking of the question (S-2).** The platform's personal-data pass runs before this template and
replaces any run of two or more Title-Case words in the question with `[MASKED]` — OWASP category names such as
"Tool Misuse", "Agent Escape" and "Prompt Injection" included; the template cannot switch it off. Measured on
AgentCore 1.0.3: "…for Tool Misuse and Agent Escape…" reached the agent as "…for [MASKED] and [MASKED]…", every
vector was reported `in_scope: false` and prompt_injection was ranked first. Rule: when `validated_question`
contains the token, a vector whose attack surface was not recognised gets `in_scope: null` (unknown) — never
`false`, because it may be the one the caller named — while a recognised one stays `true`; scores and order are
unchanged (catalogue base weights). `limitations` (JSON in State, a list in the output) carries the stable code
`QUERY_TERMS_MASKED` (`[]` otherwise), the answer starts with a note, and `priority_rationale` says why. A masked
question that retrieves nothing gets `validation_status: not_evaluated` and a notice that this is not an
out-of-scope finding — including when an unmasked word matched nothing and another word was masked. The
trade-off is that an off-topic question containing a masked name is also `not_evaluated`.

### State Definition (`src/schemas/state.py`)

| Field | Type | Purpose | Written by |
|-------|------|---------|-----------|
| question / agent_spec / known_vulns | Optional[str] | caller input (agent_spec = JSON of system-prompt outline / tool surface / RAG sources / topology) | caller |
| validated_question / attack_surface_context | Optional[str] | normalized question + extracted attack-surface JSON {tags[], intent} | QueryNormalize |
| intent_namespace / classification_rationale | Optional[str] | pentest \| vulnerability \| eu-ai-act \| nisc + rationale | IntentClassify |
| retrieved_evidence / retrieval_hit_count | Optional[str] / Optional[int] | namespace-scoped cited evidence JSON + count | HybridRetrieve |
| priority_table / priority_rationale | Optional[str] | ranked vulnerability priority JSON [{vector, severity, exploitability, score, rank}] + rationale | PriorityRankGenerate |
| answer / citations / compliance_gaps | Optional[str] | cited Markdown pen-test plan + citation/compliance-gap JSON | AnswerGenerate |
| validation_status / redaction_count / disclaimer_applied / audit_logged | Optional[str/int/bool] | S-3/S-4 outcome (`validation_status` also `not_evaluated`, see masking) | ResponseValidate |
| limitations | Optional[str] | JSON list of stable limitation codes (`QUERY_TERMS_MASKED`); surfaced as a list by `get_output` | ResponseValidate |
| error_code / error_message | Optional[str] | error propagation | any node |

**State Constraints (mandatory):**
- Flat TypedDict only (primitives + JSON-serialized strings); no Pydantic / dataclass (msgpack)
- No JWT, API keys, credentials, or raw exploit payloads / live target secrets in State (checkpoint DB leakage)
- Sensitive vulnerability detail is redacted *out of the answer* by ResponseValidate; never persisted raw
- InvocationContext via `config["configurable"]` only (not in State)

## Framework Utilization

### Shared Components Used
- [x] InvocationContext (caller_trust_level, session_id) — via `config["configurable"]`
- [x] S-2: framework `@final` `_security_gate_input()` runs automatically (FunctionNode). No domain `_extra_security_gate_input()` needed — QueryNormalize already does NFKC + injection reject + size cap in `execute()`.
- [x] S-3: framework `@final` `_security_gate_output()` (credential scan) runs automatically; **domain S-3 logic** (citation gate, sensitive vuln-detail redaction, advisory-disclaimer fail-close) lives in ResponseValidateNode.`execute()` — a deliberate domain output validation, not an override.
- [x] S-4: `emit_trace_event()` (`src/utils/audit.py` wrapper → `shared.utils.audit_logger`) called inside `execute()` of IntentClassify, HybridRetrieve, PriorityRankGenerate, AnswerGenerate, ResponseValidate. `node_start`/`node_complete`/`node_error` are NOT emitted by templates (framework owns them).

### Composition Pattern
- **Pattern:** Standalone (Cat 1) — single-agent, no GraphNode/RemoteAgentNode subgraph
- **Sub-node invocation:** `PenTestMainNode` instantiates its 4 sub-nodes in `__init__()` (`self._seq = [...]`) and calls each via `sub_node.execute(state, config)` **directly — not `__call__()`**; the composite owns the single S-2/S-3/S-4 boundary (no duplicate gate/audit). Same composite pattern as its sibling templates.
- **Error propagation strategy:** propagate via `error_code`; terminal audit always fires

## Import Isolation Confirmation
- [x] Template does not import `agenticstar` (Level 0) — PB-4 AST scan
- [x] Import targets: `framework/` (FunctionNode, AgentBaseGraph, AgentState, AgentStatus, InvocationContext) + `shared/` (audit_logger via wrapper) only

## Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| L1 base type | AgentBaseGraph | AutonomousBaseGraph | **AgentBaseGraph** | Fixed 6-step pipeline, no autonomous loop (Cat 1); exploit execution is out of scope (future Cat 3) |
| QueryNormalize scope | normalize + classify | normalize / extract only | **extract only** | keep prompt + state separate from IntentClassify |
| Vulnerability prioritization | LLM-generated scores | deterministic CVSS-AI rubric | **deterministic rubric** | auditability + stability of severity/exploitability ranking; LLM only for rationale narrative |
| Retrieval routing | single index | namespace-scoped (pentest/vuln/eu-ai-act/nisc) | **namespace-scoped** | precise multi-source compliance synthesis (NIST/NISC/EU AI Act/OWASP) |
| Sensitive output | best-effort | S-3 redaction + disclaimer fail-closed | **fail-closed** | exploit/PoC detail must be redacted; advisory disclaimer non-negotiable |
| Retrieval backend | committed index | DI Protocol + seed KB | **DI Protocol** | offline-testable; prod binds the real hybrid security KB index |
| ADR-7 LLM binding (2026-09-03) | silent `StubLLMClient` default | explicit kw > `config["llm"]` > none, named `LLM_NOT_CONFIGURED` | **Option B** | the Marketplace runner constructs `Graph(config=config.yaml)` and the fleet entry point can only place the Azure client under `config["llm"]`; a silent stub ran on the Pod even with keys registered and hid the gap. The LLM is advisory (namespace disambiguation + rationale), so the deterministic plan is kept in full and the missing LLM is named rather than faked. Stub = tests only |

## Cat 1 Genericity & Parameterization

This template is a *single technical capability* — **security-evidence-grounded vulnerability
prioritization + plan Q&A** — that happens to be demonstrated on the AI-agent pen-test domain.
The pipeline carries no hard-coded use case; every domain-specific element is injected or
catalog-driven, so the same capability ports to adjacent security domains without code changes:

| Genericity lever | How it is parameterized | To re-target |
|------------------|-------------------------|--------------|
| Knowledge base | `EvidenceRetrievalBackend` Protocol injected at the registry boundary (`__init__`) | bind a different curated KB (e.g. cloud-security, OT/ICS) — clause shape identical |
| LLM | `LLMClient` Protocol injected | swap the platform model; no node change |
| Attack-vector catalog | `AI_ATTACK_VECTORS` data table in `service.py` (not code) | edit/extend the catalog; the CVSS-AI rubric is data-driven |
| Scoring rubric | `cvss_ai_score(severity, exploitability, weight)` pure function + ordinal→weight maps | tune the weight maps via the table; rubric stays deterministic/auditable |
| Retrieval namespaces | `NAMESPACES` tuple + `IntentClassify` keyword map | redefine the namespace set for the target corpus |
| Thresholds / top-k | `_TOP_K`, `_MIN_SUBSTANTIVE`, confidence cutoffs are module constants | adjust per deployment |

Because the State schema (`PenTestState`) is a flat TypedDict of generic security artifacts
(evidence / priority_table / compliance_gaps) rather than pen-test-only fields, a Cat 2
industry-specialized sibling (e.g. a finance- or healthcare-specific pen-test workflow) can
inherit this capability as its `main`-slot building block. The Cat 1 contract — "one injectable
capability, no embedded use case" — is therefore preserved.

