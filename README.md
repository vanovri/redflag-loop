# RedFlag Loop — Autonomous Indonesian Marketplace Scam Rule Evolution

**Sea × OpenAI Codex Hackathon — Direction 1: Autonomous & Adaptive AI**

**RedFlag Loop** is an autonomous **Write → Run → Evaluate → Repair** rule-synthesis and verification engine for Indonesian e-commerce/marketplace trust & safety analysts. When new text-based chat scams (obfuscated WhatsApp escrow bypass, `.apk` courier malware, QRIS advance-fee refund traps, typosquatted phishing links, or fake customer-service freeze coercion) evade baseline filters, rushed manual rule changes often trigger unacceptable false positives on legitimate buyer/seller conversations (`cek resi JNT`, `foto paket`, `Pusat Resolusi`, or official `QRIS` checkout inquiries).

RedFlag Loop closes that loop autonomously:
1. **Run & Evaluate** active deterministic rules against a labeled Indonesian marketplace chat benchmark (`dev`, `val`, and untouched `sealed_test` splits).
2. **Cluster Failures** into False Positive (`FP`) and False Negative (`FN`) root-cause clusters per rule and scam family.
3. **Synthesize Targeted Rule Patches** (adding contextual negative/whitelist patterns to suppress FPs, and obfuscation-resilient regex/proximity/domain heuristics to capture FNs).
4. **Enforce Safety Guardrails**: Every candidate patch is scored on the validation split before activation (`False Positive Rate <= 5.0%`, `no FPR increase > 2.0 percentage points`, and strict F1 improvement). Over-broad candidates are automatically **rejected and rolled back**.

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
