# CMN-C1-343 — Enterprise AI Agent Penetration Testing & Security Vulnerability Q&A Agent

> **Category**: Cat 1 (single technical capability, use-case-agnostic)
> **Industry**: Common (industry-agnostic)

## Overview

Question-answering about penetration-test planning and vulnerability prioritisation for AI agents. Given a question such as "Pen-test plan and CVSS priority for our AI agent with tool use and RAG, OWASP Agentic + EU AI Act?", the agent extracts attack-surface tags (prompt injection, RAG poisoning, tool misuse, agent escape), retrieves matching entries from a security knowledge base, ranks candidate vulnerabilities with a deterministic CVSS-style rubric and assembles a Markdown pen-test plan with a priority table, EU AI Act gap notes and inline [C#] citations. An LLM step, when configured, adds intent disambiguation and per-item rationale; without one the plan is delivered unchanged with a not-configured notice. It executes no exploits and probes no live system: unmatched questions are deflected as out of scope rather than answered with invented CVEs, exploit-level detail is redacted and every answer carries an advisory disclaimer. The knowledge base shipped here is a small sample citing OWASP, NIST AI 100-2, EU AI Act Article 9 and NISC guidance — replace it with your own corpus.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | 3.11 or later (`requires-python = ">=3.11"`) |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the SDK version does not match, the agent raises
`PlatformRequired` during graph compile / start-up preflight rather than starting in a partially
working state. This is intentional — a half-running agent is worse than one that refuses to start.

## Known limitations

**Attack-category names can be masked by the platform before analysis.** AGENTIC STAR's
personal-data protection runs before this template's code and replaces any run of two or more
Title-Case words with `[MASKED]` — OWASP names such as "Tool Misuse", "Agent Escape" and
"Prompt Injection" included — and the template cannot switch it off. Measured on AgentCore 1.0.3:

| Question contains | Reaches the agent as | Result |
|---|---|---|
| `Tool Misuse and Agent Escape` | `[MASKED] and [MASKED]` | catalogue base ranking; every vector `in_scope: null`; `limitations: ["QUERY_TERMS_MASKED"]` and a note at the top of the plan |
| `tool misuse and agent escape` | unchanged | tool_misuse ranked first; tool_misuse and agent_escape `in_scope: true`; `limitations: []` |
| `prompt injection and Agent Escape` | `prompt injection and [MASKED]` | prompt_injection `in_scope: true`; agent_escape and the rest `null`, not `false` |
| `Explain Tool Misuse.` | `[MASKED].` | `validation_status: not_evaluated`, not "outside the knowledge base" |
| `Explain quantum annealing and Tool Misuse.` | `Explain quantum annealing and [MASKED].` | `not_evaluated` — the unmasked words matching nothing is not treated as out of scope |
| `What does Taro Yamada recommend for ramen in Osaka?` | `What does [MASKED] recommend for ramen in Osaka?` | `not_evaluated` (an off-topic question that contains a masked name is not called out of scope either) |

A vector the question may have named is never reported `in_scope: false`: `limitations` holds
the code `QUERY_TERMS_MASKED`, and the answer and `priority_rationale` say what could not be read.
Scores and order use the catalogue base weights, so a vector you named can still be missing from
the top of the list. Write category names in lower case ("tool misuse", "prompt injection") for a
question-specific ranking.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit, integration and boundary tests
config/       agent configuration
docs/         design and operational documentation
```

See `docs/02_design.md` for the design and `docs/03_test_spec.md` for the test specification.

## Customising

1. Adjust `config/` for your own environment and policies.
2. Replace the knowledge sources and sample data with your own.
3. Review the node implementations under `src/nodes/` for domain-specific logic.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
