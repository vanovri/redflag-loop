# redflag-loop: performance and technical debt

Source crosscheck: 2026-11-08 WIB. Locations refer to the current production files. The unified diffs below are proposals only. Production code has not been changed. No elapsed-time improvement is claimed without measurement.

## 1. Cache assembled domain patterns by the current TLD tuple

Location: src/redflag_loop/engine.py:99-102.

Each sample rebuilds the escaped alternation and domain expression even when the TLD set is unchanged. A bounded cache avoids repeated assembly and returns compiled patterns. Keying by the current tuple preserves changes to mutable rule definitions. This targeted proposal does not claim to precompile all regex paths or skip suppressed-rule evidence work.

```diff
diff --git a/src/redflag_loop/engine.py b/src/redflag_loop/engine.py
--- a/src/redflag_loop/engine.py
+++ b/src/redflag_loop/engine.py
@@ -4,6 +4,7 @@
 
 import json
 import re
+from functools import lru_cache
 from pathlib import Path
 
 from .contracts import (
@@ -17,6 +18,12 @@
 DEFAULT_CORPUS_PATH = (
     Path(__file__).resolve().parents[2] / "data" / "scam_chat_corpus_id.json"
 )
+
+
+@lru_cache(maxsize=128)
+def _domain_pattern(tlds: tuple[str, ...]) -> re.Pattern[str]:
+    group = "|".join(re.escape(t.lstrip(".")) for t in tlds)
+    return re.compile(rf"(?:https?://)?[a-z0-9][a-z0-9\-_.]+\.(?:{group})(?:/[^\s]*)?", re.IGNORECASE)
 
 
 def load_corpus(path: Path | str | None = None) -> list[ChatSample]:
@@ -97,9 +104,7 @@
 
             # 3. Suspicious TLD / domain heuristics
             if rule.suspicious_tlds:
-                tld_group = "|".join(re.escape(t.lstrip(".")) for t in rule.suspicious_tlds)
-                domain_regex = rf"(?:https?://)?[a-z0-9][a-z0-9\-_.]+\.(?:{tld_group})(?:/[^\s]*)?"
-                for match in re.finditer(domain_regex, text, flags=re.IGNORECASE):
+                for match in _domain_pattern(tuple(rule.suspicious_tlds)).finditer(text):
                     rule_spans.append(
                         RedFlagSpan(
                             rule_id=rule.rule_id,
```

Validation: Compare spans, decisions and suppressed-rule IDs on the corpus and mutable TLD changes. Exercise an escaped metacharacter TLD and bounded-cache eviction. Measure whole-corpus latency before claiming a speedup.

## 2. Prune impossible pairs in the sorted proximity match streams

Location: src/redflag_loop/engine.py:76-96.

The current nested loops inspect every A/B match pair. Python finditer emits nonoverlapping ordered match spans, so a monotonic lower bound can skip B matches ending too far before A and the upper bound can stop once B starts too far after A. Work becomes O(A+B+K), where K includes pairs visited in the window. Dense matching output can still be quadratic.

```diff
diff --git a/src/redflag_loop/engine.py b/src/redflag_loop/engine.py
--- a/src/redflag_loop/engine.py
+++ b/src/redflag_loop/engine.py
@@ -76,8 +76,14 @@
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
                         distance = max(0, max(ma.start(), mb.start()) - min(ma.end(), mb.end()))
```

Validation: Compare exact ordered spans on overlapping, adjacent, zero-width, boundary-distance and dense patterns. Include negative-suppression behavior and repeated tokens. Measure elapsed time without an invented sub-millisecond target.

## 3. Advance zero-width proximity regex matches in the browser evaluator

Location: src/redflag_loop/cli.py:749-750.

The positive-pattern loop already advances lastIndex on an empty match. The two proximity loops omit that guard, so a zero-width custom proximity token can spin indefinitely in browser JavaScript. Apply the same progress guard to both streams. Python finditer has different automatic empty-match progression semantics, so parity needs explicit cases.

```diff
diff --git a/src/redflag_loop/cli.py b/src/redflag_loop/cli.py
--- a/src/redflag_loop/cli.py
+++ b/src/redflag_loop/cli.py
@@ -746,8 +746,14 @@
             const reB = new RegExp(pair.token_b, "gi");
             let ma, mb;
             const listA = [], listB = [];
-            while ((ma = reA.exec(text)) !== null) listA.push({{ s: ma.index, e: ma.index + ma[0].length }});
-            while ((mb = reB.exec(text)) !== null) listB.push({{ s: mb.index, e: mb.index + mb[0].length }});
+            while ((ma = reA.exec(text)) !== null) {{
+              listA.push({{ s: ma.index, e: ma.index + ma[0].length }});
+              if (ma.index === reA.lastIndex) reA.lastIndex++;
+            }}
+            while ((mb = reB.exec(text)) !== null) {{
+              listB.push({{ s: mb.index, e: mb.index + mb[0].length }});
+              if (mb.index === reB.lastIndex) reB.lastIndex++;
+            }}
             listA.forEach(a => {{
               listB.forEach(b => {{
                 const dist = Math.max(0, Math.max(a.s, b.s) - Math.min(a.e, b.e));
```

Validation: Extract the actual generated evaluator in a bounded Node process. Supply empty and lookahead proximity expressions, confirm termination and check intended spans. Keep existing generated-dashboard integrity regressions.

## Crosscheck decisions

Source drift was observed on 2026-11-08: current autonomous_loop.py uses self.dev_samples for all four failure-cluster passes and _record_patch_decision for accepted/rejected candidate provenance. Current CLI escapes metadata renderers and derives convergence messaging from report.converged. The earlier sealed-split leakage, raw script embedding and rejected-report findings are therefore withdrawn as current debts, pending a fresh suite rerun after those external changes. _safe_script_json at cli.py:26-35 escapes script-significant characters. Remaining browser parity gap: evaluateTextJS does not implement suspicious_tlds. Sealed samples are still scored for reporting each generation; they are not absent from execution. No all-tests-pass claim is made by this document.
