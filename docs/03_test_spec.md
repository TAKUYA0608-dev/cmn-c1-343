# Test Specification — CMN-C1-343 PenTestSecurityQAAgent

## Test Strategy
- Coverage target: **≥ 80%** (achieved **90%** across `src/`, excl. FastAPI entrypoint)
- Test types: Unit (per-node + agent) / Integration (3-slot pipeline) / Proof-of-Boundary
- Backends are dependency-injected: tests bind `seed_security_kb()` + `StubLLMClient` — no network, deterministic.

## Framework Compliance Tests (Mandatory)

| TC-ID | Test | Expected Result | Result |
|-------|------|----------------|--------|
| TC-01 | State contract: flat TypedDict (`PenTestState`) | No Pydantic/dataclass; PB-2 scan | ✅ pass |
| TC-02 | Input rejection fires | QueryNormalize rejects empty / oversized / injection | ✅ pass |
| TC-03 | No JWT/Credential in `src/` | CI `gate-credential-scan` | ✅ CI |
| TC-04 | InvocationContext via `config["configurable"]` only | not in State | ✅ pass |
| TC-05 | S-4: no duplicate lifecycle events in `execute()` | absent from bodies | ✅ pass |
| TC-06/07 | S-2/S-3 `@final` gates not overridden | domain checks in QueryNormalize / ResponseValidate `execute()` | ✅ pass |
| TC-08 | `required_trust_level` = `VERIFIED_EXTERNAL` (valid enum) | agent.yaml; CI #13 | ✅ valid |
| TC-11 | S-4: ≥1 domain `emit_trace_event()` per side-effect node | IntentClassify / HybridRetrieve / PriorityRank / AnswerGenerate / ResponseValidate | ✅ ≥1 each |

> **Note:** `_extra_security_gate_input()` / `_extra_security_gate_output()` are **not used** —
> domain input checks (NFKC / injection / size) live in `QueryNormalizeNode.execute()` and domain S-3
> (citation gate / exploit redaction / disclaimer) lives in `ResponseValidateNode.execute()`; the
> framework `@final` gates run automatically. Hence TC-09/TC-10 (`_extra` hooks non-trivial) are N/A.

## Proof-of-Boundary Tests (Mandatory)

| PB-ID | Boundary | Result |
|-------|----------|--------|
| PB-2 | State serialization (primitives + JSON strings only) | ✅ pass |
| PB-4 | Import isolation (no Level 0 `agenticstar`) — AST scan | ✅ pass |
| PB-1/5/6 | Audit / checkpoint / invoke order via agent e2e | ✅ via e2e |

## Business Logic Tests (domain)

| Area | Coverage |
|------|----------|
| QueryNormalize | injection/empty rejection, attack-surface tag extraction from spec, error self-skip |
| IntentClassify | keyword namespace, LLM fallback |
| HybridRetrieve | namespace-scoped hits, zero-hit off-topic |
| PriorityRankGenerate | **CVSS-AI formula** (severity × exploitability × weight), in-scope vector ranks higher, zero-hit empty |
| AnswerGenerate | cited [C#] plan + EU AI Act gap, out-of-scope refusal |
| ResponseValidate | citation gate reject, **exploit/token/internal-IP redaction**, mandatory advisory disclaimer, audit on error path |
| main composite | 4-step run, deltas-only, node contract |
| agent e2e | invoke: cited plan, priority table, node order, injection, out-of-scope |

## Test Execution Summary
- Total tests: **30** — Pass: **30** / Fail: 0 / Skip: 0
- Coverage: **90%** (`--cov=src`); domain nodes 90–100%
