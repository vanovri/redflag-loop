"""Regression checks for rejected-patch provenance and generated dashboard data."""
from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from redflag_loop.autonomous_loop import AutonomousRedFlagLoop
from redflag_loop.cli import build_dashboard_html
from redflag_loop.engine import RuleEngine, load_corpus


def rejected_run(tmp_path):
    samples = [s.to_dict() for s in load_corpus()]
    for sample in samples:
        if sample["split"] == "val":
            sample["is_scam"] = not sample["is_scam"]
    path = tmp_path / "alternate-corpus.json"
    path.write_text(json.dumps({"samples": samples}), encoding="utf-8")
    loop = AutonomousRedFlagLoop(path)
    return loop, loop.run()


def test_rejected_candidates_never_appear_as_applied(tmp_path):
    loop, report = rejected_run(tmp_path)
    for generation in report.generations[1:]:
        assert not generation.applied_patches
        assert generation.rejected_patches
        assert "Candidate rejected" in generation.summary
        assert all(p.action == "REJECTED_ROLLBACK" for p in generation.rejected_patches)
        assert all(p.validation_status == "REJECTED_GUARDRAIL" for p in generation.rejected_patches)
        assert all(p.validation_note for p in generation.rejected_patches)
        actual, _ = RuleEngine(generation.rules).evaluate_corpus(loop.samples)
        assert generation.metrics.to_dict() == actual.to_dict()


def test_failure_examples_are_development_only():
    loop = AutonomousRedFlagLoop()
    report = loop.run()
    development_ids = {s.sample_id for s in loop.dev_samples}
    for generation in report.generations:
        assert all(set(cluster.sample_ids) <= development_ids for cluster in generation.failure_clusters)


def test_dashboard_does_not_claim_a_rejected_run_converged(tmp_path):
    loop, report = rejected_run(tmp_path)
    assert not report.converged
    html = build_dashboard_html(report, loop.samples)
    assert "Target not reached" in html
    assert "Converged: Gen 3 (F1 = 1.000)" not in html
    assert "100% Precision &amp; Recall" not in html
    assert "untouched sealed_test split after candidate freeze" not in html
    assert "Scored each generation for reporting; not used for patch selection" in html


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is required to execute generated dashboard renderers")
def test_generated_renderers_escape_corpus_and_cluster_metadata(tmp_path):
    samples = load_corpus()
    payload = '\"><img src=x onerror="audit_marker=1">'
    for sample in samples:
        sample.category_label = payload
        sample.notes = payload
    report = AutonomousRedFlagLoop().run()
    cluster = report.generations[0].failure_clusters[0]
    cluster.sample_ids = [payload]
    cluster.offending_or_missing_rule_id = payload
    html = build_dashboard_html(report, samples)
    script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
    # Run actual renderer functions with a string-only fake DOM, without a browser.
    script = script[:script.rfind("\n    renderProgressionChart();")]
    program = """
const vm = require('node:vm');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const nodes = new Map();
const context = { document: { getElementById(id) {
  if (!nodes.has(id)) nodes.set(id, { innerHTML: '', textContent: '', value: '' });
  return nodes.get(id);
}}};
vm.createContext(context);
vm.runInContext(input.script, context, { timeout: 2000 });
context.loadPresetSample = () => {};
vm.runInContext('populateSandboxPresets(); selectClusterGen(0);', context, { timeout: 2000 });
process.stdout.write(JSON.stringify({ presets: nodes.get('preset-select').innerHTML,
  clusters: nodes.get('clusters-container').innerHTML }));
"""
    result = subprocess.run([shutil.which("node"), "-e", program], input=json.dumps({"script": script}), capture_output=True, text=True, encoding="utf-8", timeout=10)
    assert result.returncode == 0, result.stderr
    rendered = json.loads(result.stdout)
    for fragment in rendered.values():
        assert payload not in fragment
        assert "<img" not in fragment
        assert "&lt;img" in fragment
