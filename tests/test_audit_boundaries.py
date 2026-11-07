"""Boundary, contract, and guardrail unit + integration tests for RedFlag Loop.

Strictly local and deterministic: zero network or external API calls.
"""

from __future__ import annotations

from pathlib import Path

from redflag_loop.autonomous_loop import AutonomousRedFlagLoop, cluster_failures
from redflag_loop.cli import build_dashboard_html
from redflag_loop.contracts import (
    ChatSample,
    ChatTurn,
    DetectionRule,
    EvalMetrics,
)
from redflag_loop.engine import RuleEngine, compute_metrics, load_corpus


def test_proximity_window_boundaries_and_reverse_token_order() -> None:
    """Verify proximity_pairs respects exact max_window distance in both token orders."""
    rule = DetectionRule(
        rule_id="R_PROX",
        name="Proximity Boundary Rule",
        category="phishing_link",
        description="Checks login/password character distance.",
        weight=0.35,  # Lands in REVIEW band [0.25, 0.50)
        patterns=[],
        proximity_pairs=[(r"\blogin\b", r"\bpassword\b", 10)],
    )
    engine = RuleEngine([rule], block_threshold=0.50, review_threshold=0.25)

    # Exact boundary: 10 spaces between end of 'login' and start of 'password' -> distance == 10 (MATCH)
    hit_exact = engine.evaluate_text("login" + (" " * 10) + "password")
    assert hit_exact.decision == "REVIEW"
    assert hit_exact.predicted_scam is False
    assert hit_exact.risk_score == 0.35
    assert hit_exact.triggered_rules == ["R_PROX"]
    assert len(hit_exact.spans) == 1
    assert hit_exact.spans[0].match_type == "proximity"
    assert hit_exact.spans[0].start == 0 and hit_exact.spans[0].end == 23

    # Reversed token order ('password' before 'login') within 10 chars -> symmetric MATCH
    hit_rev = engine.evaluate_text("password" + (" " * 5) + "login")
    assert hit_rev.decision == "REVIEW"
    assert len(hit_rev.spans) == 1
    assert hit_rev.spans[0].matched_text == "password     login"

    # 11 spaces -> distance == 11 > 10 (NO MATCH)
    miss = engine.evaluate_text("login" + (" " * 11) + "password")
    assert miss.decision == "ALLOW"
    assert miss.risk_score == 0.0
    assert miss.spans == []


def test_suspicious_tld_heuristic_span_deduplication_and_selective_suppression() -> None:
    """Verify domain_heuristic matching, identical-range deduplication, and per-rule suppression."""
    r_domain = DetectionRule(
        rule_id="R_DOM",
        name="Domain Heuristic",
        category="phishing_link",
        description="Matches .xyz/.click links with exact-span deduplication.",
        weight=0.60,
        patterns=[r"https://promo-hadiah\.xyz/claim"],
        suspicious_tlds=[".xyz", "click"],
    )
    r_suppressed = DetectionRule(
        rule_id="R_RESI",
        name="Courier Rule",
        category="fake_courier_apk",
        description="Suppressed when official resi context present.",
        weight=0.60,
        patterns=[r"\bcek\s+resi\b"],
        negative_patterns=[r"\bresi\s+jne\s*:\s*JNE[0-9]+\b"],
    )
    engine = RuleEngine([r_domain, r_suppressed])

    # Both regex and suspicious_tlds match the exact [0, 30) range -> deduplicated to 1 span!
    ev = engine.evaluate_text(
        "https://promo-hadiah.xyz/claim silakan cek resi JNE: JNE12345678"
    )
    assert ev.predicted_scam is True
    assert ev.decision == "BLOCK"
    assert ev.risk_score == 0.60
    assert ev.triggered_rules == ["R_DOM"]
    assert ev.suppressed_rules == ["R_RESI"]
    assert len(ev.spans) == 1
    assert ev.spans[0].matched_text == "https://promo-hadiah.xyz/claim"


def test_validation_guardrail_all_three_rejection_branches() -> None:
    """Verify _validate_candidate enforces max_fpr_guardrail, max_fpr_increase, and strict F1 gain."""
    loop = AutonomousRedFlagLoop(target_f1=0.95, max_fpr_guardrail=0.05, max_fpr_increase=0.02)

    base = EvalMetrics(
        total_samples=20, scam_samples=10, benign_samples=10,
        true_positives=8, false_positives=0, true_negatives=10, false_negatives=2,
        precision=1.0, recall=0.80, f1=0.8889, false_positive_rate=0.00, review_rate=0.0,
    )

    # Branch 1: Candidate FPR (6.0%) > max_fpr_guardrail (5.0%) -> rejected
    over_abs_fpr = EvalMetrics(
        total_samples=20, scam_samples=10, benign_samples=10,
        true_positives=10, false_positives=1, true_negatives=9, false_negatives=0,
        precision=0.909, recall=1.0, f1=0.952, false_positive_rate=0.06, review_rate=0.0,
    )
    ok1, msg1 = loop._validate_candidate(base, over_abs_fpr)
    assert ok1 is False and "exceeds max guardrail" in msg1

    # Branch 2: Candidate FPR (3.0%) <= 5.0%, BUT jumped +3.0pp (> max_fpr_increase 2.0pp) -> rejected
    over_delta_fpr = EvalMetrics(
        total_samples=20, scam_samples=10, benign_samples=10,
        true_positives=10, false_positives=1, true_negatives=9, false_negatives=0,
        precision=0.95, recall=1.0, f1=0.97, false_positive_rate=0.03, review_rate=0.0,
    )
    ok2, msg2 = loop._validate_candidate(base, over_delta_fpr)
    assert ok2 is False and "2.0 percentage points" in msg2

    # Branch 3: FPR safe (1.0%), but F1 equal/lower (0.8889 <= 0.8889) -> rejected
    stagnant_f1 = EvalMetrics(
        total_samples=20, scam_samples=10, benign_samples=10,
        true_positives=8, false_positives=0, true_negatives=10, false_negatives=2,
        precision=1.0, recall=0.80, f1=0.8889, false_positive_rate=0.01, review_rate=0.0,
    )
    ok3, msg3 = loop._validate_candidate(base, stagnant_f1)
    assert ok3 is False and "did not improve" in msg3

    # Valid candidate: FPR=0.01 (<=0.05, delta=+0.01<=0.02) and F1=0.95 (>0.8889) -> accepted
    good = EvalMetrics(
        total_samples=20, scam_samples=10, benign_samples=10,
        true_positives=9, false_positives=0, true_negatives=10, false_negatives=1,
        precision=1.0, recall=0.90, f1=0.9474, false_positive_rate=0.01, review_rate=0.0,
    )
    ok4, msg4 = loop._validate_candidate(base, good)
    assert ok4 is True and "passed" in msg4


def test_empty_corpus_metrics_contracts_roundtrip_and_custom_corpus(tmp_path: Path) -> None:
    """Verify zero-division safety on empty splits, contract serialization, and custom corpus loading."""
    empty_metrics = compute_metrics([], {})
    assert empty_metrics.total_samples == 0
    assert empty_metrics.precision == 0.0
    assert empty_metrics.recall == 0.0
    assert empty_metrics.f1 == 0.0
    assert empty_metrics.false_positive_rate == 0.0
    assert empty_metrics.review_rate == 0.0
    assert empty_metrics.per_category_recall == {}

    sample_dict = {
        "sample_id": "CUSTOM_01",
        "category": "phishing_link",
        "category_label": "Phishing Test",
        "is_scam": True,
        "split": "dev",
        "difficulty": "obfuscated",
        "notes": "Roundtrip test",
        "expected_red_flags": ["otp"],
        "turns": [
            {"sender": "impersonator", "text": "Buka sh0pee-claim.xyz masukkan kode OTP", "timestamp": "11:15"},
            {"sender": "buyer", "text": "Sebentar saya cek", "timestamp": "11:16"},
        ],
    }
    sample = ChatSample.from_dict(sample_dict)
    assert sample.to_dict() == sample_dict
    assert "[IMPERSONATOR]: Buka sh0pee-claim.xyz masukkan kode OTP" in sample.full_text

    # Verify cluster_failures groups both FP and FN cleanly on synthetic evaluation map
    benign_sample = ChatSample(
        sample_id="BEN_FP",
        category="benign_negotiation",
        category_label="Benign",
        is_scam=False,
        split="dev",
        difficulty="hard_negative",
        turns=[ChatTurn(sender="buyer", text="cek resi JNT kak")],
    )
    r_naive = DetectionRule(
        rule_id="R99_CUSTOM",
        name="Custom Naive",
        category="benign_negotiation",
        description="Naive",
        weight=0.6,
        patterns=[r"cek resi"],
    )
    eng = RuleEngine([r_naive])
    _, evals = eng.evaluate_corpus([sample, benign_sample])
    clusters = cluster_failures([sample, benign_sample], evals)
    types = {c.failure_type: c for c in clusters}
    assert set(types.keys()) == {"FP", "FN"}
    assert types["FP"].offending_or_missing_rule_id == "R99_CUSTOM"
    assert types["FN"].category == "phishing_link"

    # Verify dashboard builder embeds serialized rules & corpus cleanly without mutating disk
    real_samples = load_corpus()
    report = AutonomousRedFlagLoop().run()
    html = build_dashboard_html(report, real_samples[:5])
    assert '"suspicious_tlds": [' in html
    assert '"proximity_pairs": [' in html


def test_audit_hardening_strict_bool_xss_sealed_leak_and_rollback() -> None:
    """Verify RF-01 (rollback metrics), RF-02 (no sealed_test in failure_clusters), RF-03 (</script> escape), RF-04 (strict bool)."""
    import pytest

    base_dict = {
        "sample_id": "S_BOOL",
        "category": "benign_negotiation",
        "category_label": "Benign",
        "is_scam": "false",
        "split": "dev",
        "difficulty": "easy",
        "turns": [{"sender": "buyer", "text": "Halo kak"}],
    }
    assert ChatSample.from_dict(base_dict).is_scam is False
    assert ChatSample.from_dict({**base_dict, "is_scam": "true"}).is_scam is True
    with pytest.raises(ValueError, match="Expected strict boolean"):
        ChatSample.from_dict({**base_dict, "is_scam": "maybe"})

    loop = AutonomousRedFlagLoop()
    report = loop.run()
    sealed_ids = {s.sample_id for s in loop.sealed_test_samples}
    assert sealed_ids, "Expected non-empty sealed_test split"
    for gen in report.generations:
        leaked = {sid for c in gen.failure_clusters for sid in c.sample_ids} & sealed_ids
        assert not leaked, f"Leaked sealed_test IDs in generation {gen.generation}: {leaked}"

    xss_sample = ChatSample(
        sample_id="XSS_01",
        category="phishing_link",
        category_label="XSS",
        is_scam=True,
        split="dev",
        difficulty="easy",
        turns=[ChatTurn(sender="impersonator", text="</script><script>alert(1)</script>")],
    )
    html = build_dashboard_html(report, [xss_sample])
    assert "</script><script>alert(1)" not in html
    assert "\\u003c/script\\u003e" in html
