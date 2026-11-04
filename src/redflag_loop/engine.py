"""Deterministic rule & pattern evaluation engine for Indonesian marketplace chats."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .contracts import (
    ChatSample,
    DetectionRule,
    EvalMetrics,
    RedFlagSpan,
    SampleEvaluation,
)

DEFAULT_CORPUS_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "scam_chat_corpus_id.json"
)


def load_corpus(path: Path | str | None = None) -> list[ChatSample]:
    """Load labeled Indonesian marketplace chat samples from JSON."""
    target = Path(path) if path is not None else DEFAULT_CORPUS_PATH
    payload = json.loads(target.read_text(encoding="utf-8"))
    return [ChatSample.from_dict(item) for item in payload["samples"]]


class RuleEngine:
    """Fast, explainable rule engine supporting regex, proximity, domain heuristics, and negative context."""

    def __init__(
        self,
        rules: list[DetectionRule],
        block_threshold: float = 0.50,
        review_threshold: float = 0.25,
    ) -> None:
        self.rules = list(rules)
        self.block_threshold = block_threshold
        self.review_threshold = review_threshold

    def evaluate_text(self, text: str, sample_id: str = "SANDBOX") -> SampleEvaluation:
        """Evaluate raw chat text and return risk score, decision, and matched red-flag spans."""
        triggered_rules: list[str] = []
        suppressed_rules: list[str] = []
        spans: list[RedFlagSpan] = []
        total_weight = 0.0

        for rule in self.rules:
            # Check negative / whitelist suppression context first
            is_suppressed = False
            for neg_pat in rule.negative_patterns:
                if re.search(neg_pat, text, flags=re.IGNORECASE):
                    is_suppressed = True
                    break

            rule_spans: list[RedFlagSpan] = []

            # 1. Regex patterns
            for pat in rule.patterns:
                for match in re.finditer(pat, text, flags=re.IGNORECASE):
                    rule_spans.append(
                        RedFlagSpan(
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            category=rule.category,
                            matched_text=match.group(0),
                            start=match.start(),
                            end=match.end(),
                            weight=rule.weight,
                            match_type="regex",
                        )
                    )

            # 2. Token-proximity pairs
            for pat_a, pat_b, max_window in rule.proximity_pairs:
                matches_a = list(re.finditer(pat_a, text, flags=re.IGNORECASE))
                matches_b = list(re.finditer(pat_b, text, flags=re.IGNORECASE))
                for ma in matches_a:
                    for mb in matches_b:
                        start_idx = min(ma.start(), mb.start())
                        end_idx = max(ma.end(), mb.end())
                        distance = max(0, max(ma.start(), mb.start()) - min(ma.end(), mb.end()))
                        if distance <= max_window:
                            rule_spans.append(
                                RedFlagSpan(
                                    rule_id=rule.rule_id,
                                    rule_name=rule.name,
                                    category=rule.category,
                                    matched_text=text[start_idx:end_idx],
                                    start=start_idx,
                                    end=end_idx,
                                    weight=rule.weight,
                                    match_type="proximity",
                                )
                            )

            # 3. Suspicious TLD / domain heuristics
            if rule.suspicious_tlds:
                tld_group = "|".join(re.escape(t.lstrip(".")) for t in rule.suspicious_tlds)
                domain_regex = rf"(?:https?://)?[a-z0-9][a-z0-9\-_.]+\.(?:{tld_group})(?:/[^\s]*)?"
                for match in re.finditer(domain_regex, text, flags=re.IGNORECASE):
                    rule_spans.append(
                        RedFlagSpan(
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            category=rule.category,
                            matched_text=match.group(0),
                            start=match.start(),
                            end=match.end(),
                            weight=rule.weight,
                            match_type="domain_heuristic",
                        )
                    )

            if rule_spans:
                if is_suppressed:
                    suppressed_rules.append(rule.rule_id)
                else:
                    triggered_rules.append(rule.rule_id)
                    total_weight += rule.weight
                    # Deduplicate overlapping spans from the same rule for clean display
                    seen_ranges: set[tuple[int, int]] = set()
                    for sp in rule_spans:
                        key = (sp.start, sp.end)
                        if key not in seen_ranges:
                            seen_ranges.add(key)
                            spans.append(sp)

        risk_score = min(1.0, round(total_weight, 4))
        predicted_scam = risk_score >= self.block_threshold
        if risk_score >= self.block_threshold:
            decision = "BLOCK"
        elif risk_score >= self.review_threshold:
            decision = "REVIEW"
        else:
            decision = "ALLOW"

        spans.sort(key=lambda s: (s.start, -s.end))
        return SampleEvaluation(
            sample_id=sample_id,
            risk_score=risk_score,
            predicted_scam=predicted_scam,
            decision=decision,
            triggered_rules=triggered_rules,
            suppressed_rules=suppressed_rules,
            spans=spans,
        )

    def evaluate_sample(self, sample: ChatSample) -> SampleEvaluation:
        """Evaluate a structured ChatSample."""
        return self.evaluate_text(sample.raw_messages_text, sample_id=sample.sample_id)

    def evaluate_corpus(
        self, samples: list[ChatSample]
    ) -> tuple[EvalMetrics, dict[str, SampleEvaluation]]:
        """Evaluate a list of samples and return aggregate metrics + per-sample evaluations."""
        evals: dict[str, SampleEvaluation] = {}
        for sample in samples:
            evals[sample.sample_id] = self.evaluate_sample(sample)
        metrics = compute_metrics(samples, evals)
        return metrics, evals


def compute_metrics(
    samples: list[ChatSample], evaluations: dict[str, SampleEvaluation]
) -> EvalMetrics:
    """Compute Precision, Recall, F1, FPR, Review Rate, and per-category recall."""
    tp = fp = tn = fn = 0
    review_count = 0
    category_totals: dict[str, int] = {}
    category_hits: dict[str, int] = {}

    for sample in samples:
        ev = evaluations[sample.sample_id]
        if ev.decision == "REVIEW":
            review_count += 1

        if sample.is_scam:
            category_totals[sample.category] = category_totals.get(sample.category, 0) + 1
            if ev.predicted_scam:
                tp += 1
                category_hits[sample.category] = category_hits.get(sample.category, 0) + 1
            else:
                fn += 1
        else:
            if ev.predicted_scam:
                fp += 1
            else:
                tn += 1

    total = len(samples)
    scam_count = tp + fn
    benign_count = tn + fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / scam_count if scam_count > 0 else 0.0
    f1 = (
        (2 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    fpr = fp / benign_count if benign_count > 0 else 0.0
    review_rate = review_count / total if total > 0 else 0.0

    per_cat_recall = {
        cat: (category_hits.get(cat, 0) / count if count > 0 else 0.0)
        for cat, count in category_totals.items()
    }

    return EvalMetrics(
        total_samples=total,
        scam_samples=scam_count,
        benign_samples=benign_count,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=fpr,
        review_rate=review_rate,
        per_category_recall=per_cat_recall,
    )
