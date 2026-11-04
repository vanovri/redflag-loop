"""RedFlag Loop: Autonomous Write-Run-Evaluate-Repair rule evolution for Indonesian marketplace scam detection."""

from .autonomous_loop import AutonomousRedFlagLoop, get_generation_0_rules
from .contracts import (
    ChatSample,
    ChatTurn,
    DetectionRule,
    EvalMetrics,
    FailureCase,
    GenerationSnapshot,
    LoopRunReport,
    PatchDiff,
    RedFlagSpan,
    SampleEvaluation,
)
from .engine import RuleEngine, compute_metrics, load_corpus

__all__ = [
    "AutonomousRedFlagLoop",
    "ChatSample",
    "ChatTurn",
    "DetectionRule",
    "EvalMetrics",
    "FailureCase",
    "GenerationSnapshot",
    "LoopRunReport",
    "PatchDiff",
    "RedFlagSpan",
    "RuleEngine",
    "SampleEvaluation",
    "compute_metrics",
    "get_generation_0_rules",
    "load_corpus",
]
