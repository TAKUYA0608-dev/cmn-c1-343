"""CMN-C1-343 — service layer: security-KB retrieval + LLM + CVSS-AI catalog (DI).

The external services (the multi-source security-KB retriever, and the LLM) are
injected so the template is offline-testable and deployment-agnostic. Production
binds the real hybrid vector+keyword index over the curated security KB + platform
LLM client (via `ctx.secrets`); tests bind the in-memory / stub implementations here.

`AI_ATTACK_VECTORS` is a static, auditable catalog used by the deterministic CVSS-AI
prioritization rubric; the production KB curation gate refreshes it from NIST/OWASP.

No `agenticstar` (Level 0) imports; no `framework.*` dependency — pure domain logic.
"""

from __future__ import annotations

import re
from typing import Any, Protocol, runtime_checkable

# IntentClassify namespaces (retrieval routing).
NAMESPACES: tuple[str, ...] = ("pentest", "vulnerability", "eu-ai-act", "nisc")

# The platform's S-2 personal-data pass runs before any template code and replaces anything its person-name
# heuristic matches (a run of two or more Title-Case words — OWASP category names such as "Tool Misuse",
# "Agent Escape" or "Prompt Injection" included) with this token. The template cannot switch that pass off (the
# input gate is final). An attack vector named only by the masked words cannot be recognised, so its relevance
# is reported as unknown and the answer carries a limitation code instead of reading as complete.
PLATFORM_MASK_TOKEN = "[MASKED]"
# Stable machine-readable limitation code (the human-readable explanation goes in `answer`).
QUERY_TERMS_MASKED = "QUERY_TERMS_MASKED"


def question_was_masked(question: str) -> bool:
    """True if any part of the question reached the agent as the platform's mask token."""
    return PLATFORM_MASK_TOKEN in (question or "")


# Severity / exploitability ordinal → numeric weight (CVSS-AI rubric).
_SEVERITY_W = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}
_EXPLOIT_W = {"high": 1.0, "medium": 0.6, "low": 0.3}


# ★ 日本語 KB × 語彙検索の構造欠陥 (本番 Pod で実証):
# str.split() は空白区切りなので日本語の文が 1 トークンに潰れ、日本語質問は
# 何も引けない (343 の旧実装の実測: 日本語 4/4 が 0 hit)。CJK 文字 bigram +
# 機能語除去で解決する。実装は 328 の service.lexical_terms を移植。
_CJK_RE = re.compile(r"[぀-ヿ一-鿿ｦ-ﾟ]+")
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9_.-]*")

# Function words carry no topical signal but are dense in prose, so they let an
# out-of-scope question score highly on any chunk. Measured on the sibling KB:
# "What is the weather in Tokyo today?" scored 0.429 on a citations chunk
# (matching only "the"/"is"/"in"), higher than a correct retry question — so no
# score threshold could separate them. Dropping function words is what makes the
# out-of-scope refusal honest.
_STOPWORDS: frozenset[str] = frozenset(
    """
a an the and or but if then than that this these those of in on at to for from by with
without about into over under as is are was were be been being do does did doing have
has had having i you he she it we they me my your his her its our their what which who
whom when where why how should would could can may might must will shall not no yes so
such only own same too very just also there here up down out off again further once
""".split()
)


# Japanese function-word bigrams. Bigram indexing makes a short, function-word
# query dangerous rather than merely imprecise: "ある" yields the single term
# {ある}, and any chunk containing it scores 1.0 — no threshold can separate that
# from a real hit, and the weak match is then cited. Dropping these before scoring
# makes such a query yield no terms at all, which is the correct answer (the query
# carries no topical content). Segmenting properly would need a morphological
# analyser; this list covers the high-frequency verb, copula, demonstrative,
# formal-noun and particle forms that reach 1.0 on their own.
_JA_FUNCTION_BIGRAMS = frozenset(
    """
する すれ すな すべ して した しな しま しょ され せる れる られ でき きる こう
ある あり あっ ない なく なし いる いた いま なる なっ なり なら れば
これ それ あれ どれ この その あの どの どう そう ああ いう
れは れを れが れに れで はこ はそ はど はな はで はと
こと もの ため とき よう ところ ばあ あい
です ます ませ まし だっ であ でし でも ても とも
から まで より ので のに には では との への とし につ いて ついて ため
がで がい がな をど をす をし にす にお おけ ける
うす うか うし うも いか いき かた たら
るこ るの るか ると るが るを るに るで るは るも るま
たこ たの たか たと たが たを たに
のこ のか のと のが のを のに のは のも
なの なか なと なが なに ので うな あな
""".split()
)


def lexical_terms(text: str) -> set[str]:
    """Topical lexical terms: content words plus CJK character bigrams.

    Punctuation is stripped so "pen-test?" and "pen-test" are the same term, and
    function words are dropped in both scripts (`_STOPWORDS`,
    `_JA_FUNCTION_BIGRAMS`). A query left with no terms retrieves nothing, which is
    the intended outcome for a query with no topical content.
    """
    terms = {t for t in _WORD_RE.findall(text.lower()) if t not in _STOPWORDS}
    for run in _CJK_RE.findall(text):
        if len(run) == 1:
            terms.add(run)
        else:
            terms |= {run[i : i + 2] for i in range(len(run) - 1)} - _JA_FUNCTION_BIGRAMS
    return terms


def _meaningful_terms(text: str) -> set[str]:
    """Topical terms — content words + CJK bigrams (328 の lexical_terms)."""
    return lexical_terms(text)


@runtime_checkable
class EvidenceRetrievalBackend(Protocol):
    """Security-KB retriever boundary.

    `search` returns a ranked list of evidence dicts, each shaped:
        {"evidence_id": str, "source": str, "namespace": str, "title": str,
         "text": str, "score": float}
    `namespace`, when given, scopes ranking to that source family.
    """

    def search(self, query: str, top_k: int = 6, namespace: str | None = None) -> list[dict[str, Any]]: ...


@runtime_checkable
class LLMClient(Protocol):
    """LLM boundary — `generate(prompt) -> str`."""

    def generate(self, prompt: str) -> str: ...


class InMemoryEvidenceBackend:
    """In-memory EvidenceRetrievalBackend for tests / local runs.

    Seed with `add([evidence, ...])`; `search` ranks by naive lexical overlap and,
    when a `namespace` is given, boosts evidence in that namespace. Production swaps
    in the real hybrid vector+keyword index over the curated security KB.
    """

    def __init__(self) -> None:
        self._items: list[dict[str, Any]] = []

    def add(self, items: list[dict[str, Any]]) -> None:
        self._items.extend(items)

    def search(self, query: str, top_k: int = 6, namespace: str | None = None) -> list[dict[str, Any]]:
        terms = _meaningful_terms(query)

        def score(e: dict[str, Any]) -> float:
            words = _meaningful_terms(str(e.get("text", ""))) | _meaningful_terms(str(e.get("title", "")))
            base = (len(terms & words) / len(terms)) if terms and words else 0.0
            # Namespace boost only re-ranks lexical matches; never creates a hit from zero.
            if base > 0.0 and namespace and e.get("namespace") == namespace:
                base += 0.15
            return round(base, 4)

        ranked = sorted(
            ({**e, "score": score(e)} for e in self._items),
            key=lambda e: e["score"],
            reverse=True,
        )
        return [e for e in ranked if e["score"] > 0.0][:top_k]


class StubLLMClient:
    """Deterministic stub LLM for tests / local runs — returns a templated answer.

    Never bound by default: with no LLM resolved (see `resolve_llm_client`) the
    LLM steps are skipped and the plan says so (`LLM_NOT_CONFIGURED`); the
    deterministic priority table / steps / gaps / citations are still produced.
    """

    def __init__(self, canned: str | None = None) -> None:
        self._canned = canned

    def generate(self, prompt: str) -> str:
        if self._canned is not None:
            return self._canned
        tail = prompt.strip().splitlines()[-1][:200] if prompt.strip() else ""
        return f"Per the cited security guidance: {tail} [C1]"


# ── LLM seam: config["llm"] → LLMClient ───────────────────────────────────────
# Reason code surfaced (S-4 event + answer text) when no LLM is bound anywhere.
LLM_NOT_CONFIGURED = "LLM_NOT_CONFIGURED"


def _as_text(result: Any) -> str:
    """Coerce a client reply to text: str as-is, message-like objects via `.content`."""
    if isinstance(result, str):
        return result
    content = getattr(result, "content", None)
    if isinstance(content, str):
        return content
    return "" if result is None else str(result)


class ConfigLLMAdapter:
    """Adapt a `config["llm"]` object to this template's `LLMClient` Protocol.

    The fleet entry point places a lazily-resolved chat client under `config["llm"]`
    that answers `invoke(prompt) -> str` (and `complete(prompt, **kw) -> str`); this
    template's nodes speak `generate(prompt) -> str`. The adapter forwards to `invoke`
    first, then `complete`, and never swallows the client's exceptions — a configured
    but failing LLM must surface, not silently degrade.
    """

    def __init__(self, client: Any) -> None:
        call = getattr(client, "invoke", None)
        if not callable(call):
            call = getattr(client, "complete", None)
        if not callable(call):
            raise TypeError(
                "config['llm'] must expose generate(prompt), invoke(prompt) or "
                f"complete(prompt); got {type(client).__name__}"
            )
        self._client = client
        self._call = call

    def generate(self, prompt: str) -> str:
        return _as_text(self._call(prompt))


def resolve_llm_client(explicit: LLMClient | None, config: Any) -> LLMClient | None:
    """Precedence: explicit `llm_client` kw > `config["llm"]` > None.

    None means "no LLM bound": IntentClassify falls back to the default namespace
    when the heuristic has no signal, and AnswerGenerate names `LLM_NOT_CONFIGURED`
    in place of the rationale while the deterministic plan (priority table, test
    steps, compliance gaps, citations) is produced as usual. An object under
    `config["llm"]` that answers none of generate/invoke/complete raises at
    construction (misconfiguration is not a reason to degrade quietly).
    """
    if explicit is not None:
        return explicit
    candidate = config.get("llm") if isinstance(config, dict) else None
    if candidate is None:
        return None
    if isinstance(candidate, LLMClient):
        return candidate
    return ConfigLLMAdapter(candidate)


# ── AI attack-vector catalog (static, auditable) for the CVSS-AI rubric ──
# `severity` / `exploitability` are ordinals mapped to weights above; `attack_surface`
# links the vector to the QueryNormalize attack-surface tags for relevance weighting.
AI_ATTACK_VECTORS: tuple[dict[str, Any], ...] = (
    {
        "vector": "prompt_injection",
        "owasp_ref": "OWASP-LLM01",
        "attack_surface": "prompt-injection",
        "severity": "high",
        "exploitability": "high",
    },
    {
        "vector": "rag_poisoning",
        "owasp_ref": "OWASP-LLM08",
        "attack_surface": "rag-poison",
        "severity": "high",
        "exploitability": "medium",
    },
    {
        "vector": "tool_misuse",
        "owasp_ref": "OWASP-Agentic-T2",
        "attack_surface": "tool-misuse",
        "severity": "critical",
        "exploitability": "medium",
    },
    {
        "vector": "agent_escape",
        "owasp_ref": "OWASP-Agentic-T6",
        "attack_surface": "agent-escape",
        "severity": "critical",
        "exploitability": "low",
    },
    {
        "vector": "excessive_agency",
        "owasp_ref": "OWASP-LLM06",
        "attack_surface": "tool-misuse",
        "severity": "high",
        "exploitability": "medium",
    },
    {
        "vector": "sensitive_info_disclosure",
        "owasp_ref": "OWASP-LLM02",
        "attack_surface": "rag-poison",
        "severity": "medium",
        "exploitability": "high",
    },
)


def cvss_ai_score(severity: str, exploitability: str, ai_weight: float = 1.0) -> float:
    """Deterministic CVSS-AI score = severity × exploitability × AI-vector weight (0–10)."""
    s = _SEVERITY_W.get(str(severity).lower(), 0.3)
    e = _EXPLOIT_W.get(str(exploitability).lower(), 0.3)
    return round(s * e * ai_weight * 10.0, 2)


def seed_security_kb() -> InMemoryEvidenceBackend:
    """Return an InMemoryEvidenceBackend seeded with representative security guidance.

    Every record carries a versioned ``official_ref`` so the caller can verify the
    control against the authority it is drawn from — a security template must not
    present a standards claim whose *version* is ambiguous. Versioning
    matters here because the numbering moves:

      * OWASP Top 10 for LLM Applications — item IDs were renumbered between 2023
        (v1.x) and 2025. This catalog uses the **2025** numbering (LLM02 =
        Sensitive Information Disclosure, LLM06 = Excessive Agency are the 2025
        assignments; in 2023 those IDs were Insecure Output Handling / Sensitive
        Info Disclosure), so ``official_ref`` pins "2025".
      * OWASP Agentic AI (Threats & Mitigations) — still evolving; threat IDs are
        provisional. ``official_ref`` says so and does **not** freeze a version.
      * NIST AI 100-2 — the Adversarial ML taxonomy. Pinned to the e2023 edition
        identifier (a 2025 revision, 100-2e2025, also exists; the production KB
        gate should pin whichever edition it actually indexes).
      * EU AI Act — Regulation (EU) 2024/1689, CELEX 32024R1689 (confirmed).
      * NISC — a real authority, but no specific document ID/version is confirmed
        here, so ``official_ref`` stays descriptive and does not invent one.

    ★ 確証のない版番号は捏造しない: where a version is not confirmed (Agentic draft,
    NISC), the ref discloses that rather than inventing an identifier.

    Each record also carries EN/JP retrieval vocabulary so Japanese and English
    questions reach the same evidence (the CJK-bigram tokenizer above). Production
    replaces this seed with the full curated/indexed KB; the shape is identical.
    """
    backend = InMemoryEvidenceBackend()
    _OWASP_LLM = "OWASP Top 10 for LLM Applications 2025"
    _OWASP_AGENTIC = "OWASP Agentic AI — Threats and Mitigations (draft; threat IDs provisional)"
    backend.add(
        [
            {
                "evidence_id": "owasp-llm01",
                "source": "OWASP LLM Top 10 (2025)",
                "namespace": "vulnerability",
                "title": "LLM01 Prompt Injection",
                "text": "prompt injection manipulates the agent via crafted input to override system instructions or exfiltrate context; mitigate with input isolation and output gating "
                "プロンプトインジェクション 対策 入力 検証 システムプロンプト 上書き",
                "official_ref": f"{_OWASP_LLM} — LLM01:2025 Prompt Injection",
            },
            {
                "evidence_id": "owasp-agentic-t2",
                "source": "OWASP Agentic Top 10 (draft)",
                "namespace": "pentest",
                "title": "Agentic T2 Tool Misuse",
                "text": "tool misuse abuses an agent's tool surface to perform unintended actions; pen-test the tool authorization boundary and least-privilege scoping "
                "ツール 誤用 ペンテスト 権限 最小権限 認可 境界",
                "official_ref": f"{_OWASP_AGENTIC} — T2 Tool Misuse",
            },
            {
                "evidence_id": "owasp-agentic-t6",
                "source": "OWASP Agentic Top 10 (draft)",
                "namespace": "pentest",
                "title": "Agentic T6 Agent Escape",
                "text": "agent escape breaks the sandbox or orchestration boundary; test isolation of the agent runtime and topology "
                "エージェント サンドボックス 脱出 隔離 分離 オーケストレーション 境界",
                "official_ref": f"{_OWASP_AGENTIC} — T6 (Agent Escape / boundary break)",
            },
            {
                "evidence_id": "nist-ai-100-2",
                "source": "NIST AI 100-2",
                "namespace": "vulnerability",
                "title": "Adversarial ML taxonomy",
                "text": "nist adversarial machine learning taxonomy covers evasion, poisoning, and abuse including rag poisoning of retrieval sources "
                "敵対的 機械学習 分類 タクソノミー ポイズニング rag 汚染 回避 悪用",
                "official_ref": "NIST AI 100-2e2023 — Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations",
            },
            {
                "evidence_id": "euaiact-art9",
                "source": "EU AI Act Article 9",
                "namespace": "eu-ai-act",
                "title": "Risk management system",
                "text": "high-risk ai systems require a risk management system with continuous testing and adversarial robustness evaluation before deployment "
                "eu ai法 高リスク リスク管理 適合性評価 敵対的 頑健性 継続的 テスト",
                "official_ref": "Regulation (EU) 2024/1689 (CELEX 32024R1689), Article 9",
            },
            {
                "evidence_id": "nisc-2026",
                "source": "NISC guidelines",
                "namespace": "nisc",
                "title": "AI security operations",
                "text": "nisc guidance requires continuous monitoring of ai agent attack surface including prompt injection and tool misuse with documented pen-test cadence "
                "nisc 内閣サイバーセキュリティ 監視 攻撃 対象領域 運用 ペンテスト 頻度",
                # ★ NISC は実在の当局だが、特定文書 ID / 版が確証できないため official_ref は
                #   記述的に留め、版番号を捏造しない (363 の PPC ガイドラインと同じ判断)。
                "official_ref": "内閣サイバーセキュリティセンター (NISC) — AI セキュリティ運用ガイダンス (文書ID/版は KB キュレーションゲートで確定)",
            },
        ]
    )
    return backend
