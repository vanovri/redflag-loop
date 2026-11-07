# RedFlag Loop Technical Debt & Performance Ledger

All findings below were verified directly against the current local repository files on disk. Line numbers are 1-based and exact. Production code was intentionally left unmodified.

---

## 1. Uncompiled Per-Sample Regex Rebuilding & Wasted Matching on Suppressed Rules

- **Location:** `src/redflag_loop/engine.py` (lines 32–41, 49–62, 99–118)
- **Category:** Algorithmic & CPU Efficiency
- **Severity:** Medium (P2)

### Technical Issue & Impact
1. **Uncompiled Patterns & Dynamic Regex Construction:** `RuleEngine.__init__()` (lines 32–41) stores raw regex strings rather than pre-compiled `re.Pattern` objects (`re.compile(..., re.IGNORECASE)`), relying on Python's small bounded `_cache` (`MAXCACHE = 512`) on every `evaluate_text()` call. In addition, lines 99–102 reconstruct `tld_group = "|".join(...)` and `domain_regex` string from scratch on every sample evaluation.
2. **Full Pattern Scan After Negative Suppression:** Lines 51–55 evaluate `rule.negative_patterns` *first* (`is_suppressed = True`), yet lines 60–115 still run `re.finditer()` across all `rule.patterns`, all `rule.proximity_pairs`, and `domain_regex` collecting every span in the conversation—only to discard all collected `rule_spans` at lines 117–118 (`if is_suppressed: suppressed_rules.append(rule.rule_id)`). When `is_suppressed` is `True`, a single boolean existence check (`any(p.search(text) ...)` short-circuiting on the first hit) suffices to populate `suppressed_rules`.

### Proposed Diff
```diff
--- a/src/redflag_loop/engine.py
+++ b/src/redflag_loop/engine.py
@@ -36,9 +36,24 @@ class RuleEngine:
         review_threshold: float = 0.25,
     ) -> None:
         self.rules = list(rules)
         self.block_threshold = block_threshold
         self.review_threshold = review_threshold
+        self._compiled = []
+        for rule in self.rules:
+            neg = [re.compile(p, re.IGNORECASE) for p in rule.negative_patterns]
+            pats = [re.compile(p, re.IGNORECASE) for p in rule.patterns]
+            prox = [(re.compile(a, re.IGNORECASE), re.compile(b, re.IGNORECASE), w) for a, b, w in rule.proximity_pairs]
+            dom = None
+            if rule.suspicious_tlds:
+                tld_group = "|".join(re.escape(t.lstrip(".")) for t in rule.suspicious_tlds)
+                dom = re.compile(rf"(?:https?://)?[a-z0-9][a-z0-9\-_.]+\.(?:{tld_group})(?:/[^\s]*)?", re.IGNORECASE)
+            self._compiled.append((rule, neg, pats, prox, dom))
 
     def evaluate_text(self, text: str, sample_id: str = "SANDBOX") -> SampleEvaluation:
         """Evaluate raw chat text and return risk score, decision, and matched red-flag spans."""
@@ -47,13 +62,20 @@ class RuleEngine:
         spans: list[RedFlagSpan] = []
         total_weight = 0.0
 
-        for rule in self.rules:
+        for rule, neg_re, pat_re, prox_re, dom_re in self._compiled:
             # Check negative / whitelist suppression context first
-            is_suppressed = False
-            for neg_pat in rule.negative_patterns:
-                if re.search(neg_pat, text, flags=re.IGNORECASE):
-                    is_suppressed = True
-                    break
+            is_suppressed = any(np.search(text) for np in neg_re)
+            if is_suppressed:
+                has_positive = (
+                    any(p.search(text) for p in pat_re)
+                    or (dom_re is not None and dom_re.search(text) is not None)
+                    or any(
+                        max(0, max(ma.start(), mb.start()) - min(ma.end(), mb.end())) <= w
+                        for ra, rb, w in prox_re for ma in ra.finditer(text) for mb in rb.finditer(text)
+                    )
+                )
+                if has_positive:
+                    suppressed_rules.append(rule.rule_id)
+                continue
```

### How to Validate
Run `C:\Python314\python.exe -m pytest -q` and benchmark `engine.evaluate_corpus(samples)` over 1,000 iterations to confirm identical `SampleEvaluation` outputs with lower evaluation latency.

---

## 2. Quadratic $O(|A| \cdot |B|)$ Token-Proximity Scan on Sorted Match Streams

- **Location:** `src/redflag_loop/engine.py` (lines 76–96)
- **Category:** Algorithmic Complexity
- **Severity:** Low (P3)

### Technical Issue & Impact
In `RuleEngine.evaluate_text()`, lines 77–80 materialize `matches_a` and `matches_b` via `re.finditer()`—which yields matches strictly sorted in ascending order of `.start()`—and then iterate over the full Cartesian product `for ma in matches_a: for mb in matches_b:`. On long multi-turn chat transcripts where common tokens repeat $M$ times, this degrades to $O(M^2)$ comparisons per proximity rule instead of advancing a monotonic lower-bound pointer `lo` and breaking early once `mb.start() - ma.end() > max_window`.

### Proposed Diff
```diff
--- a/src/redflag_loop/engine.py
+++ b/src/redflag_loop/engine.py
@@ -76,10 +76,17 @@ class RuleEngine:
             for pat_a, pat_b, max_window in rule.proximity_pairs:
                 matches_a = list(re.finditer(pat_a, text, flags=re.IGNORECASE))
                 matches_b = list(re.finditer(pat_b, text, flags=re.IGNORECASE))
+                lo = 0
                 for ma in matches_a:
-                    for mb in matches_b:
+                    while lo < len(matches_b) and ma.start() - matches_b[lo].end() > max_window:
+                        lo += 1
+                    for idx in range(lo, len(matches_b)):
+                        mb = matches_b[idx]
+                        if mb.start() - ma.end() > max_window:
+                            break
                         start_idx = min(ma.start(), mb.start())
                         end_idx = max(ma.end(), mb.end())
```

### How to Validate
Construct a synthetic 5,000-word chat message containing 200 occurrences of `login` and 200 occurrences of `password` with only the final pair within 80 characters; verify identical `RedFlagSpan` start/end offsets and sub-millisecond execution time.

---

## 3. Redundant Split Re-Evaluation & Holdout Leakage into `cluster_failures()`

- **Location:** `src/redflag_loop/autonomous_loop.py` (lines 536–540, 576–579, 628–631, 666–669)
- **Category:** Benchmark Isolation / Redundant Computation
- **Severity:** Medium (P2)

### Technical Issue & Impact
In every generation (`0`, `1`, `2`, `3`), `AutonomousRedFlagLoop.run()` executes:
```python
full_metrics, full_evals = engine.evaluate_corpus(self.samples)
val_metrics, _ = engine.evaluate_corpus(self.val_samples)        # Gen 0 (or already computed before full_metrics in Gen 1-3)
test_metrics, _ = engine.evaluate_corpus(self.sealed_test_samples)
clusters = cluster_failures(self.samples, full_evals)
```
1. **2x Evaluation Work:** `self.samples` is the union of `dev_samples`, `val_samples`, and `sealed_test_samples`. Running `evaluate_corpus(self.samples)` and also running `evaluate_corpus(self.val_samples)` + `evaluate_corpus(self.sealed_test_samples)` evaluates every validation and holdout conversation **twice per generation** instead of slicing `full_evals` via `compute_metrics(self.val_samples, full_evals)`.
2. **Holdout Contamination in Failure Diagnosis:** Passing `self.samples` (instead of `self.dev_samples`) into `cluster_failures()` exposes `sealed_test` sample IDs and snippets inside `GenerationSnapshot.failure_clusters`, violating strict holdout isolation between diagnostic clustering and `sealed_test` reporting.

### Proposed Diff
```diff
--- a/src/redflag_loop/autonomous_loop.py
+++ b/src/redflag_loop/autonomous_loop.py
@@ -17,7 +17,7 @@ from .contracts import (
     PatchDiff,
     SampleEvaluation,
 )
-from .engine import RuleEngine, load_corpus
+from .engine import RuleEngine, compute_metrics, load_corpus
 
 
 def get_generation_0_rules() -> list[DetectionRule]:
@@ -534,9 +534,9 @@ class AutonomousRedFlagLoop:
         t0 = time.perf_counter()
         engine0 = RuleEngine(current_rules)
         full_metrics0, full_evals0 = engine0.evaluate_corpus(self.samples)
-        val_metrics0, _ = engine0.evaluate_corpus(self.val_samples)
-        test_metrics0, _ = engine0.evaluate_corpus(self.sealed_test_samples)
-        clusters0 = cluster_failures(self.samples, full_evals0)
+        val_metrics0 = compute_metrics(self.val_samples, full_evals0)
+        test_metrics0 = compute_metrics(self.sealed_test_samples, full_evals0)
+        clusters0 = cluster_failures(self.dev_samples, full_evals0)
         elapsed0 = (time.perf_counter() - t0) * 1000.0
```

### How to Validate
Verify `val_metrics` and `sealed_test_metrics` remain numerically identical across all 4 generations while asserting no `sample_id` from `sealed_test_samples` appears in `gen.failure_clusters[i].sample_ids`.

---

## 4. Missing `suspicious_tlds` Evaluation & Unescaped `</script>` Embedding in Browser Sandbox

- **Location:** `src/redflag_loop/cli.py` (lines 26–27, 549–550, 699–775)
- **Category:** Boundary Safety / Python–JS Engine Parity
- **Severity:** Medium (P2)

### Technical Issue & Impact
1. **Engine Parity Drift (`cli.py:699-775`):** In Python (`engine.py:99-114`), `RuleEngine.evaluate_text()` checks `rule.patterns`, `rule.proximity_pairs`, **and** `rule.suspicious_tlds` (`["xyz", "top", "site", "online", "click"]` in Gen 2/3 `R01_PHISHING_URL`). In the generated HTML sandbox (`cli.py:699-775`), `evaluateTextJS()` implements `negative_patterns`, `patterns`, and `proximity_pairs`, **but completely omits `rule.suspicious_tlds`**. Consequently, non-brand phishing domains such as `promo-diskon-kilat.xyz/claim` are blocked (`BLOCK`, `0.65`) by Python `RuleEngine` yet falsely allowed (`ALLOW`, `0.00`) in the interactive browser sandbox!
2. **Inline `<script>` Breakout Risk (`cli.py:26-27, 549-550`):** `json.dumps(..., ensure_ascii=False)` is interpolated raw into `<script>const REPORT = {report_json}; const SAMPLES = {samples_json};`. If any corpus message or note contains `</script>`, the HTML parser prematurely closes the `<script>` tag (DOM injection / broken dashboard).

### Proposed Diff
```diff
--- a/src/redflag_loop/cli.py
+++ b/src/redflag_loop/cli.py
@@ -23,8 +23,8 @@ def build_dashboard_html(
     report_dict = report.to_dict()
     samples_list: list[dict[str, Any]] = [s.to_dict() for s in samples]
 
-    report_json = json.dumps(report_dict, ensure_ascii=False)
-    samples_json = json.dumps(samples_list, ensure_ascii=False)
+    report_json = json.dumps(report_dict, ensure_ascii=False).replace("</", "<\\/")
+    samples_json = json.dumps(samples_list, ensure_ascii=False).replace("</", "<\\/")
 
     html = f"""<!DOCTYPE html>
 <html lang="en" class="dark">
@@ -758,6 +758,25 @@ def build_dashboard_html(
           }} catch (e) {{}}
         }});
 
+        if (rule.suspicious_tlds && rule.suspicious_tlds.length > 0) {{
+          try {{
+            const tldGroup = rule.suspicious_tlds.map(t => t.replace(/^\./, "").replace(/[.*+?^${{}}()|[\]\\]/g, "\\$&")).join("|");
+            const reDom = new RegExp(`(?:https?:\\/\\/)?[a-z0-9][a-z0-9\\-_.]*\\.(?:${{tldGroup}})(?:\\/[^\\s]*)?`, "gi");
+            let md;
+            while ((md = reDom.exec(text)) !== null) {{
+              ruleSpans.push({{
+                rule_id: rule.rule_id,
+                rule_name: rule.name,
+                text: md[0],
+                start: md.index,
+                end: md.index + md[0].length,
+                weight: rule.weight
+              }});
+            }}
+          }} catch (e) {{}}
+        }}
+
         if (ruleSpans.length > 0) {{
           if (isSuppressed) {{
             suppressed.push(rule.rule_id);
```

### How to Validate
Test `build_dashboard_html()` with a `ChatSample` containing `</script>` in `turns[0].text` (confirming `<\/script>` in the emitted HTML) and verify `promo-diskon-kilat.xyz/claim` triggers `R01_PHISHING_URL` identically in both Python and JS evaluators.
