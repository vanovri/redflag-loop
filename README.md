# RedFlag Loop: Indonesian Marketplace Rule Evolution Demo

**Sea × OpenAI Codex Hackathon — Direction 1: Autonomous & Adaptive AI**

**RedFlag Loop** executes three preauthored rule-repair stages and checks each candidate against validation guardrails. It demonstrates deterministic evaluation, rollback and evidence spans using an included Indonesian marketplace chat fixture. It does not generate new repair programs with an AI model or establish deployed scam-detection accuracy.

RedFlag Loop closes that loop autonomously:
1. **Run & Evaluate** active deterministic rules against the included `dev`, `val`, and labelled `sealed_test` splits.
2. **Cluster Development Failures** into False Positive (`FP`) and False Negative (`FN`) groups per rule and scam family. Validation and sealed-test examples stay out of these groups.
3. **Apply Preauthored Candidate Patches** with contextual negative patterns, regex, proximity and domain heuristics.
4. **Enforce Safety Guardrails**: Every candidate patch is scored on the validation split before activation (`False Positive Rate <= 5.0%`, `no FPR increase > 2.0 percentage points`, and strict F1 improvement). Over-broad candidates are automatically **rejected and rolled back**.

The split labelled `sealed_test` is scored at each generation for reporting. It
does not select patches, but this is not an untouched, once-only final holdout.
The following metrics describe the included fixture and fixed repair stages.
Rejected candidate diffs appear only under `rejected_patches`; applied diffs and
summaries describe the active rules. Dashboard metadata is escaped before it
enters HTML, including corpus notes, labels and failure sample identifiers.

---

## Benchmark Progression (`ID-ScamChat-72`)

Evaluated across **72 multi-turn Bahasa Indonesia marketplace conversations** spanning **6 categories** (50 scam conversations + 22 benign & hard-negative courier/refund/QRIS edge cases):

| Generation | Repair Milestone | Precision | Recall | Full F1 | Val F1 | Sealed Test F1 | False Positive Rate (FPR) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Gen 0** | Naive Baseline Keyword/Regex Rules | `0.718` | `0.560` | **`0.629`** | `0.560` | `0.690` | `50.0%` (11 FPs) |
| **Gen 1** | Courier/Refund FP Whitelist + Sideload APK & QRIS Fee Repair | `1.000` | `0.700` | **`0.824`** | `0.800` | `0.889` | `0.0%` (0 FPs) |
| **Gen 2** | Guardrail Rollback (`Candidate 2A` rejected) + Leetspeak WA/Telegram & Typosquat Phishing Repair | `1.000` | `0.880` | **`0.936`** | `0.929` | `0.966` | `0.0%` (0 FPs) |
| **Gen 3** | Fake CS Authority Header & Flash-Sale Urgency Convergence | `1.000` | `1.000` | **`1.000`** | `1.000` | `1.000` | `0.0%` (0 FPs) |

- **Net F1 Improvement**: **`+0.371`** (`0.629` → `1.000`)
- **Hard-Negative False Positive Rate**: **`50.0%` → `0.0%`**

---

## Repository Structure

```text
redflag-loop/
├── pyproject.toml                  # Package metadata, CLI script & pytest config
├── README.md                       # Architecture & benchmark documentation
├── data/
│   └── scam_chat_corpus_id.json    # 72 labeled multi-turn Indonesian marketplace chats (6 categories)
├── src/redflag_loop/
│   ├── __init__.py
│   ├── contracts.py                # ChatSample, DetectionRule, EvalMetrics, FailureCase, GenerationSnapshot, LoopRunReport
│   ├── engine.py                   # Deterministic regex, token-proximity, TLD heuristic & negative-context engine
│   ├── autonomous_loop.py          # Write -> Run -> Evaluate -> Repair autonomous evolution loop & guardrail rollback
│   └── cli.py                      # CLI runner & self-contained dark-mode HTML dashboard generator
├── outputs/
│   └── evolution_report.json       # Full generation-by-generation evolution report & rule diffs
├── web/
│   └── index.html                  # Interactive dark-mode dashboard + Live Indonesian Chat Scam Sandbox
└── tests/
    └── test_redflag_loop.py        # Pytest verification suite
```

---

## Quickstart

### 1. Run the Test Suite
```powershell
C:\Python314\python.exe -m pytest -q
```

### 2. Run the Autonomous Loop & Build Dashboard
```powershell
$env:PYTHONPATH = "src"
C:\Python314\python.exe -m redflag_loop.cli
```

This generates:
- `outputs/evolution_report.json`: Full structured telemetry across Generations `0 → 1 → 2 → 3`.
- `web/index.html`: Self-contained dark-mode interactive dashboard featuring:
  - Generation-by-generation Precision, Recall, F1, and False Positive Rate progression chart.
  - Rule diff viewer with accepted patches and guardrail-rejected rollback logs.
  - **Live Indonesian Marketplace Chat Scam Sandbox** comparing Generation 3 (Evolved) vs Generation 0 (Naive Baseline) in real time with highlighted red-flag spans.
