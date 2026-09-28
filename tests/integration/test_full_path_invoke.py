# CMN-C1-343 — Integration: the production path, on the real SDK.
#
# Every test here builds the agent the way the Marketplace runner does —
# `Graph(config=<config/config.yaml dict>)`, no `llm_client` keyword — or adds one
# dependency at a time to prove a specific seam, then goes through the framework's
# own `invoke()` with a runner-shaped InvocationContext. Node-by-node tests cannot
# see what these pin: the `config["llm"]` seam, the kw > config precedence, and
# the named no-LLM degradation (deterministic plan kept, no stub rationale).

import json
import pathlib

import pytest
import yaml

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph.graph import Graph
from src.services.service import (
    LLM_NOT_CONFIGURED,
    ConfigLLMAdapter,
    StubLLMClient,
    resolve_llm_client,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_QUESTION = "How should I prioritize prompt injection and tool abuse in a pen test of an LLM agent?"


def _runner_config() -> dict:
    """The dict the runner passes: config/config.yaml as loaded, nothing added."""
    cfg = yaml.safe_load((_REPO_ROOT / "config" / "config.yaml").read_text(encoding="utf-8"))
    assert isinstance(cfg, dict) and cfg, "config/config.yaml must load to a non-empty dict"
    return cfg


def _ctx() -> InvocationContext:
    return InvocationContext(caller_id="marketplace-user", caller_trust_level=TrustLevel.VERIFIED_EXTERNAL)


def _invoke(agent, message: str = _QUESTION) -> dict:
    agent.compile()
    return agent.invoke(message, ctx=_ctx(), input_context={"conversation_history": []})


def _is_success(out: dict) -> bool:
    return str(out.get("status", "")).lower().endswith("success")


class _ScriptedLLM:
    """A config["llm"]-shaped client: `invoke(prompt) -> str`, no `generate`."""

    def __init__(self, reply: str = "SCRIPTED RATIONALE: start with prompt injection.") -> None:
        self.prompts: list[str] = []
        self.reply = reply

    def invoke(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.reply


class _RaisingLLM:
    def invoke(self, prompt: str) -> str:
        raise RuntimeError("upstream LLM failure (simulated)")


class TestBareRunnerConstruction:
    """`Graph(config=...)` alone — exactly what the Marketplace runner does."""

    def test_deterministic_plan_is_kept_and_the_missing_llm_is_named(self):
        out = _invoke(Graph(config=_runner_config()))
        assert _is_success(out), out.get("status")
        assert out.get("output"), "a runner-shaped invocation produced no output"
        # The deterministic path is complete without an LLM: priorities, steps,
        # gaps and cited evidence are all delivered ...
        assert "Prioritized Vulnerabilities" in out["output"]
        cits = json.loads(out.get("citations") or "[]")
        assert cits and all(c.get("official_ref") for c in cits), "citations did not reach the caller"
        assert out.get("error_code") is None, out.get("error_code")
        # ... and the gap is named where the rationale would be.
        assert LLM_NOT_CONFIGURED in out["output"]
        assert "Per the cited security guidance" not in out["output"], "a stub rationale leaked through"

    def test_bare_graph_binds_no_llm(self):
        assert Graph(config=_runner_config())._llm_client is None
        assert Graph()._llm_client is None


class TestConfigLlmSeam:
    """`config["llm"]` reaches the answer node; explicit kw wins over it."""

    def test_scripted_config_llm_shapes_the_rationale(self):
        llm = _ScriptedLLM()
        out = _invoke(Graph(config={**_runner_config(), "llm": llm}))
        assert _is_success(out) and out.get("error_code") is None, out
        assert llm.prompts, "the config['llm'] client was never called"
        rationale_prompt = llm.prompts[-1]
        assert "pen-test priority" in rationale_prompt
        assert "Top vectors:" in rationale_prompt, "the ranked vectors did not reach the prompt"
        assert llm.reply in out["output"], "the rationale does not derive from the client's reply"
        assert LLM_NOT_CONFIGURED not in out["output"]

    def test_explicit_llm_client_wins_over_config_llm(self):
        config_llm = _ScriptedLLM(reply="FROM CONFIG")
        out = _invoke(
            Graph(config={**_runner_config(), "llm": config_llm}, llm_client=StubLLMClient(canned="FROM EXPLICIT KW"))
        )
        assert "FROM EXPLICIT KW" in out["output"]
        assert config_llm.prompts == [], "config['llm'] was called although an explicit client was given"

    def test_adapter_prefers_invoke_then_complete_and_coerces_message_content(self):
        class _Msg:
            content = "reply text"

        class _CompleteOnly:
            def complete(self, prompt, **kw):
                return _Msg()

        assert ConfigLLMAdapter(_ScriptedLLM(reply="x")).generate("p") == "x"
        assert ConfigLLMAdapter(_CompleteOnly()).generate("p") == "reply text"
        with pytest.raises(TypeError):
            ConfigLLMAdapter(object())
        assert resolve_llm_client(None, {"llm": None}) is None
        assert resolve_llm_client(None, None) is None
        stub = StubLLMClient()
        assert resolve_llm_client(None, {"llm": stub}) is stub  # already speaks generate()

    def test_a_raising_client_surfaces_as_a_named_error_not_a_guess(self):
        # The adapter never swallows the client's exception. This template's
        # composite main node carries no degrade guard, so the framework marks the
        # node as failed: status=error, the exception named in error_log, nothing
        # published — a visible failure, never a guessed or stub answer.
        out = _invoke(Graph(config={**_runner_config(), "llm": _RaisingLLM()}))
        assert not _is_success(out), out.get("status")
        assert not out.get("answer") and not out.get("output"), "an answer was published although the LLM failed"
        log = " ".join(str(e) for e in (out.get("error_log") or []))
        assert "upstream LLM failure (simulated)" in log, "the LLM failure was not named in error_log"


# ─── Platform masking (S-2) ─────────────────────────────────────────────────────
# The framework input gate (final, runs before every node of this template) replaces any run of two or
# more Title-Case words in `user_input` with "[MASKED]" — OWASP category names such as "Tool Misuse",
# "Agent Escape" and "Prompt Injection" included. Measured 2026-09-24 on AgentCore 1.0.3: a question about
# Tool Misuse and Agent Escape was ranked with prompt_injection first and every vector marked
# in_scope=false; "Explain Tool Misuse." was answered "outside the indexed knowledge base". These tests go
# through the runner-shaped invoke above, so the gate runs exactly as in production.

_MASKED_NOTE_START = "> Note: part of this question reached the agent as [MASKED]"
_OUT_OF_SCOPE_TEXT = "falls outside the indexed"
_BASE_RATIONALE = "deterministic CVSS-AI rubric (severity × exploitability × AI-vector weight)"


def _platform_view(text: str) -> str:
    """What the platform's input gate turns `text` into before this template sees it."""
    from framework.nodes.function_node import detect_pii, mask_pii

    return str(mask_pii(text, detect_pii(text)))


def _ask(question: str) -> dict:
    out = _invoke(Graph(config=_runner_config()), question)
    assert _is_success(out), out.get("status")
    return out


def _in_scope(out: dict) -> dict:
    return {r["vector"]: r["in_scope"] for r in json.loads(out.get("priority_table") or "[]")}


class TestPlatformMaskedQuestion:
    _Q = "How should we pen-test our agent for Tool Misuse and Agent Escape from the OWASP Agentic Top 10?"

    def test_masked_vector_names_are_unknown_not_out_of_scope(self):
        assert "for [MASKED] and [MASKED] from" in _platform_view(self._Q), "precondition: both names masked"
        control = _in_scope(_ask(self._Q.lower()))
        assert control["tool_misuse"] is True and control["agent_escape"] is True, "precondition: lower case"
        out = _ask(self._Q)
        scope = _in_scope(out)
        assert scope and all(v is None for v in scope.values()), scope  # never False for a named vector
        assert out["answer"].startswith(_MASKED_NOTE_START), out["answer"][:120]
        assert out["limitations"] == ["QUERY_TERMS_MASKED"], out["limitations"]
        assert "in_scope is null" in out["priority_rationale"], out["priority_rationale"]
        assert out["validation_status"] == "passed"

    def test_an_unmasked_vector_plus_a_masked_one_does_not_mark_the_masked_one_out_of_scope(self):
        # The primary vector reaches the agent unmasked and matches; the second one the caller named was
        # masked. Only the unmasked one may be confirmed; the rest are unknown, not "not in scope".
        question = "Prioritize prompt injection and Agent Escape risks for our agent."
        assert (
            _platform_view(question) == "Prioritize prompt injection and [MASKED] risks for our agent."
        ), "precondition"
        out = _ask(question)
        scope = _in_scope(out)
        assert scope["prompt_injection"] is True, scope
        assert scope["agent_escape"] is None, scope
        assert out["limitations"] == ["QUERY_TERMS_MASKED"], out["limitations"]

    def test_an_unmasked_non_matching_term_plus_a_masked_vector_is_not_a_confident_out_of_scope(self):
        # The unmasked words name no attack surface; the masked words are the vector the caller asked about.
        question = "How should we pen-test our agent's billing module for Agent Escape?"
        assert _platform_view(question).endswith("billing module for [MASKED]?"), "precondition"
        control = _in_scope(_ask("How should we pen-test our agent's billing module?"))
        assert control and all(v is False for v in control.values()), "precondition: unmasked words name nothing"
        out = _ask(question)
        scope = _in_scope(out)
        assert scope and all(v is None for v in scope.values()), scope
        assert out["limitations"] == ["QUERY_TERMS_MASKED"], out["limitations"]

    def test_an_unmasked_non_matching_term_plus_a_masked_term_is_not_evaluated_on_zero_hits(self):
        question = "Explain quantum annealing and Tool Misuse."
        assert _platform_view(question) == "Explain quantum annealing and [MASKED].", "precondition"
        assert (
            _OUT_OF_SCOPE_TEXT in _ask("Explain quantum annealing.")["answer"]
        ), "precondition: the unmasked words alone match nothing"
        out = _ask(question)
        assert out["validation_status"] == "not_evaluated", out["answer"][:200]
        assert _OUT_OF_SCOPE_TEXT not in out["answer"]
        assert out["limitations"] == ["QUERY_TERMS_MASKED"], out["limitations"]

    def test_a_fully_masked_question_is_not_evaluated_rather_than_out_of_scope(self):
        question = "Explain Tool Misuse."
        assert _platform_view(question) == "[MASKED].", "precondition: the whole question is masked"
        assert (_ask(question.lower()).get("retrieval_hit_count") or 0) > 0, "precondition: in-domain words"
        out = _ask(question)
        assert out["validation_status"] == "not_evaluated", out["answer"][:200]
        assert "not a finding that the question is out of scope" in out["answer"]
        assert out["limitations"] == ["QUERY_TERMS_MASKED"], out["limitations"]

    def test_lowercase_vector_names_are_unchanged(self):
        out = _ask(self._Q.lower())
        rows = json.loads(out["priority_table"])
        assert rows[0]["vector"] == "tool_misuse" and rows[0]["in_scope"] is True
        assert all(isinstance(r["in_scope"], bool) for r in rows), rows
        assert out["limitations"] == []
        assert out["priority_rationale"] == _BASE_RATIONALE
        assert out["answer"].startswith("## AI Agent Pen-Test Plan")

    def test_an_unmasked_off_topic_question_stays_out_of_scope(self):
        out = _ask("What is the best ramen shop in Tokyo near the office?")
        assert _OUT_OF_SCOPE_TEXT in out["answer"]
        assert out["validation_status"] == "passed"
        assert out["limitations"] == []

    def test_an_off_topic_question_with_a_masked_name_is_not_evaluated(self):
        # Documented trade-off: the template cannot tell what the masked words were, so it does not claim
        # the question is out of scope even when the rest of it is clearly off-topic.
        out = _ask("What does Taro Yamada recommend for ramen in Osaka?")
        assert out["validation_status"] == "not_evaluated"
        assert out["limitations"] == ["QUERY_TERMS_MASKED"]
