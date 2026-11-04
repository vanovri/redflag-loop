"""Comprehensive pytest suite for RedFlag Loop."""

from __future__ import annotations

import json
from pathlib import Path

from redflag_loop.autonomous_loop import AutonomousRedFlagLoop, get_generation_0_rules
from redflag_loop.cli import main
from redflag_loop.engine import RuleEngine, load_corpus


def test_corpus_validity_and_categories() -> None:
    """Verify corpus has >= 60 multi-turn Indonesian chat samples across all 6 categories."""
    samples = load_corpus()
    assert len(samples) >= 60

    expected_categories = {
        "benign_negotiation",
        "phishing_link",
        "fake_courier_apk",
        "qris_refund_trap",
        "off_platform_escrow_bypass",
        "fake_cs_urgency",
    }
    observed_categories = {s.category for s in samples}
    assert observed_categories == expected_categories

    for cat in expected_categories:
        cat_samples = [s for s in samples if s.category == cat]
        assert len(cat_samples) >= 10, f"Category {cat} should have at least 10 samples"

    hard_negatives = [
        s for s in samples if not s.is_scam and s.difficulty == "hard_negative"
    ]
    assert len(hard_negatives) >= 10
    assert all(len(s.turns) >= 1 and s.raw_messages_text.strip() for s in samples)


def test_autonomous_loop_f1_improvement_and_convergence() -> None:
    """Verify Gen 0 -> Gen 3 evolution reaches F1 >= 0.95 and improves over Gen 0 by >= 0.20 F1."""
    loop = AutonomousRedFlagLoop()
    report = loop.run()

    assert report.converged is True
    assert report.generations_run == 4

    gen0 = report.generations[0]
    gen1 = report.generations[1]
    gen2 = report.generations[2]
    gen3 = report.generations[3]

    # Baseline Gen 0 has mediocre F1 (~0.60 - 0.70)
    assert 0.60 <= gen0.metrics.f1 <= 0.70

    # Strict monotonic F1 progression across generations
    assert gen0.metrics.f1 < gen1.metrics.f1 < gen2.metrics.f1 < gen3.metrics.f1

    # Final generation achieves >= 0.95 F1 and beats Gen 0 by >= 0.20 F1
    assert report.final_f1 >= 0.95
    assert report.f1_improvement >= 0.20
    assert gen3.sealed_test_metrics.f1 >= 0.95


def test_zero_regression_on_legitimate_courier_and_refund_chats() -> None:
    """Verify evolved rules eliminate all false positives on legitimate courier resi & refund chats."""
    loop = AutonomousRedFlagLoop()
    report = loop.run()

    gen0 = report.generations[0]
    gen3 = report.generations[-1]

    # Naive baseline suffers from false positives on courier/refund hard negatives
    assert gen0.metrics.false_positives > 0
    assert gen0.metrics.false_positive_rate > 0.20

    # Evolved Gen 3 rules achieve 0 false positives across all benign & hard-negative chats
    assert gen3.metrics.false_positives == 0
    assert gen3.metrics.false_positive_rate == 0.0

    engine3 = RuleEngine(gen3.rules)
    # Test explicit tricky benign texts
    legit_resi = engine3.evaluate_text(
        "Ini nomor resi JNT: JP8849201193 kak, foto paket sudah saya lampirkan di chat aplikasi."
    )
    assert legit_resi.predicted_scam is False
    assert legit_resi.decision == "ALLOW"

    legit_refund = engine3.evaluate_text(
        "Silakan klik tombol komplain resmi dan ajukan pengembalian di aplikasi lewat Pusat Resolusi agar refund otomatis."
    )
    assert legit_refund.predicted_scam is False
    assert legit_refund.decision == "ALLOW"

    # Test obfuscated scam texts are caught with explainable spans
    scam_obfuscated = engine3.evaluate_text(
        "Gan lanjut ke WA O8I2-3456-789O dan kirim barang dulu sekarang, atau buka sh0pee-pay-claim.xyz dan masukkan kode OTP."
    )
    assert scam_obfuscated.predicted_scam is True
    assert scam_obfuscated.decision == "BLOCK"
    assert len(scam_obfuscated.spans) >= 2


def test_guardrail_rejects_and_rolls_back_overbroad_candidate() -> None:
    """Verify Generation 2 rejects and rolls back the overbroad candidate patch that violates FPR guardrail."""
    loop = AutonomousRedFlagLoop()
    report = loop.run()
    gen2 = report.generations[2]

    assert len(gen2.rejected_patches) == 1
    rejected = gen2.rejected_patches[0]
    assert rejected.validation_status == "REJECTED_GUARDRAIL"
    assert rejected.action == "REJECTED_ROLLBACK"
    assert "REJECTED" in rejected.validation_note


def test_cli_generates_report_and_dashboard(tmp_path: Path) -> None:
    """Verify CLI writes outputs/evolution_report.json and web/index.html cleanly."""
    report_out = tmp_path / "evolution_report.json"
    dashboard_out = tmp_path / "index.html"

    exit_code = main(
        [
            "--report-out",
            str(report_out),
            "--dashboard-out",
            str(dashboard_out),
        ]
    )
    assert exit_code == 0
    assert report_out.exists()
    assert dashboard_out.exists()

    payload = json.loads(report_out.read_text(encoding="utf-8"))
    assert payload["converged"] is True
    assert payload["final_f1"] >= 0.95
    assert len(payload["generations"]) == 4

    html = dashboard_out.read_text(encoding="utf-8")
    assert "RedFlag Loop" in html
    assert "Live Indonesian Marketplace Chat Scam Sandbox" in html
    assert "BENIGN_HN_11" in html
