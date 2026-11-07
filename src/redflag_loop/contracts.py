"""Data contracts for the RedFlag Loop autonomous rule evolution engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


def _parse_strict_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low == "true":
            return True
        if low == "false":
            return False
    raise ValueError(f"Expected strict boolean for is_scam, got {value!r}")


@dataclass(slots=True)
class ChatTurn:
    """Single message turn inside a marketplace conversation."""

    sender: str  # "buyer" | "seller" | "impersonator"
    text: str
    timestamp: str = "10:00"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ChatSample:
    """Labeled Indonesian e-commerce/marketplace chat conversation sample."""

    sample_id: str
    category: str
    category_label: str
    is_scam: bool
    split: str  # "dev" | "val" | "sealed_test"
    difficulty: str  # "standard" | "hard_negative" | "obfuscated"
    turns: list[ChatTurn]
    notes: str = ""
    expected_red_flags: list[str] = field(default_factory=list)

    @property
    def full_text(self) -> str:
        """Concatenated conversation text for rule evaluation."""
        return "\n".join(f"[{t.sender.upper()}]: {t.text}" for t in self.turns)

    @property
    def raw_messages_text(self) -> str:
        """Joined message text without speaker tags."""
        return " ".join(t.text for t in self.turns)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "category": self.category,
            "category_label": self.category_label,
            "is_scam": self.is_scam,
            "split": self.split,
            "difficulty": self.difficulty,
            "turns": [t.to_dict() for t in self.turns],
            "notes": self.notes,
            "expected_red_flags": list(self.expected_red_flags),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChatSample:
        turns = [
            ChatTurn(
                sender=t["sender"],
                text=t["text"],
                timestamp=t.get("timestamp", "10:00"),
            )
            for t in data.get("turns", [])
        ]
        return cls(
            sample_id=data["sample_id"],
            category=data["category"],
            category_label=data.get("category_label", data["category"]),
            is_scam=_parse_strict_bool(data["is_scam"]),
            split=data.get("split", "dev"),
            difficulty=data.get("difficulty", "standard"),
            turns=turns,
            notes=data.get("notes", ""),
            expected_red_flags=list(data.get("expected_red_flags", [])),
        )


@dataclass(slots=True)
class DetectionRule:
    """Deterministic pattern rule with regex, proximity, domain heuristics, and negative context."""

    rule_id: str
    name: str
    category: str
    description: str
    weight: float
    patterns: list[str]
    negative_patterns: list[str] = field(default_factory=list)
    proximity_pairs: list[tuple[str, str, int]] = field(default_factory=list)
    suspicious_tlds: list[str] = field(default_factory=list)
    version: int = 0
    patch_rationale: str = "Baseline naive rule"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "weight": self.weight,
            "patterns": list(self.patterns),
            "negative_patterns": list(self.negative_patterns),
            "proximity_pairs": [
                {"token_a": a, "token_b": b, "max_window_chars": w}
                for a, b, w in self.proximity_pairs
            ],
            "suspicious_tlds": list(self.suspicious_tlds),
            "version": self.version,
            "patch_rationale": self.patch_rationale,
        }


@dataclass(slots=True)
class RedFlagSpan:
    """Explainable matched evidence span in a chat message."""

    rule_id: str
    rule_name: str
    category: str
    matched_text: str
    start: int
    end: int
    weight: float
    match_type: str  # "regex" | "proximity" | "domain_heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SampleEvaluation:
    """Result of running the rule engine on a single ChatSample or raw text."""

    sample_id: str
    risk_score: float
    predicted_scam: bool
    decision: str  # "BLOCK" | "REVIEW" | "ALLOW"
    triggered_rules: list[str]
    suppressed_rules: list[str]
    spans: list[RedFlagSpan]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "risk_score": round(self.risk_score, 4),
            "predicted_scam": self.predicted_scam,
            "decision": self.decision,
            "triggered_rules": list(self.triggered_rules),
            "suppressed_rules": list(self.suppressed_rules),
            "spans": [s.to_dict() for s in self.spans],
        }


@dataclass(slots=True)
class EvalMetrics:
    """Aggregate classification & safety guardrail metrics for a rule generation."""

    total_samples: int
    scam_samples: int
    benign_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    review_rate: float
    per_category_recall: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "scam_samples": self.scam_samples,
            "benign_samples": self.benign_samples,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "review_rate": round(self.review_rate, 4),
            "per_category_recall": {
                k: round(v, 4) for k, v in self.per_category_recall.items()
            },
        }


@dataclass(slots=True)
class FailureCase:
    """Clustered False Positive (FP) or False Negative (FN) diagnosis for autonomous repair."""

    failure_type: str  # "FP" | "FN"
    cluster_id: str
    category: str
    sample_ids: list[str]
    root_cause: str
    offending_or_missing_rule_id: str
    example_snippet: str
    proposed_remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PatchDiff:
    """Readable rule diff produced during an autonomous repair step."""

    rule_id: str
    rule_name: str
    action: str  # "PATCHED" | "ADDED" | "REJECTED_ROLLBACK"
    rationale: str
    added_patterns: list[str] = field(default_factory=list)
    removed_patterns: list[str] = field(default_factory=list)
    added_negative_patterns: list[str] = field(default_factory=list)
    validation_status: str = "ACCEPTED"  # "ACCEPTED" | "REJECTED_GUARDRAIL"
    validation_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class GenerationSnapshot:
    """State, metrics, failure clusters, and rule patches at a single evolution generation."""

    generation: int
    title: str
    summary: str
    elapsed_ms: float
    metrics: EvalMetrics
    validation_metrics: EvalMetrics
    sealed_test_metrics: EvalMetrics
    rules: list[DetectionRule]
    failure_clusters: list[FailureCase]
    applied_patches: list[PatchDiff]
    rejected_patches: list[PatchDiff] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generation": self.generation,
            "title": self.title,
            "summary": self.summary,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "metrics": self.metrics.to_dict(),
            "validation_metrics": self.validation_metrics.to_dict(),
            "sealed_test_metrics": self.sealed_test_metrics.to_dict(),
            "rules": [r.to_dict() for r in self.rules],
            "failure_clusters": [f.to_dict() for f in self.failure_clusters],
            "applied_patches": [p.to_dict() for p in self.applied_patches],
            "rejected_patches": [p.to_dict() for p in self.rejected_patches],
        }


@dataclass(slots=True)
class LoopRunReport:
    """Complete execution report across all autonomous Write-Run-Evaluate-Repair generations."""

    project_name: str
    benchmark_name: str
    total_corpus_size: int
    target_f1: float
    max_fpr_guardrail: float
    initial_f1: float
    final_f1: float
    f1_improvement: float
    initial_fpr: float
    final_fpr: float
    converged: bool
    generations_run: int
    generations: list[GenerationSnapshot]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_name": self.project_name,
            "benchmark_name": self.benchmark_name,
            "total_corpus_size": self.total_corpus_size,
            "target_f1": round(self.target_f1, 4),
            "max_fpr_guardrail": round(self.max_fpr_guardrail, 4),
            "initial_f1": round(self.initial_f1, 4),
            "final_f1": round(self.final_f1, 4),
            "f1_improvement": round(self.f1_improvement, 4),
            "initial_fpr": round(self.initial_fpr, 4),
            "final_fpr": round(self.final_fpr, 4),
            "converged": self.converged,
            "generations_run": self.generations_run,
            "generations": [g.to_dict() for g in self.generations],
        }
