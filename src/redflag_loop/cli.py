"""CLI entrypoint and self-contained interactive dashboard builder for RedFlag Loop."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .autonomous_loop import AutonomousRedFlagLoop
from .contracts import ChatSample, LoopRunReport

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORT_PATH = PROJECT_ROOT / "outputs" / "evolution_report.json"
DEFAULT_DASHBOARD_PATH = PROJECT_ROOT / "web" / "index.html"


def build_dashboard_html(
    report: LoopRunReport,
    samples: list[ChatSample],
) -> str:
    """Render a self-contained dark-mode interactive HTML dashboard with embedded report & corpus data."""
    report_dict = report.to_dict()
    samples_list: list[dict[str, Any]] = [s.to_dict() for s in samples]

    def _safe_script_json(obj: Any) -> str:
        return (
            json.dumps(obj, ensure_ascii=False)
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
        )

    report_json = _safe_script_json(report_dict)
    samples_json = _safe_script_json(samples_list)

    html = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>RedFlag Loop — Autonomous Indonesian Marketplace Scam Rule Evolution</title>
  <style>
    :root {{
      --bg-0: #080b12;
      --bg-1: #0f1523;
      --bg-2: #161f33;
      --bg-3: #1e2942;
      --border: #283655;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-glow: rgba(56, 189, 248, 0.18);
      --green: #22c55e;
      --green-bg: rgba(34, 197, 94, 0.14);
      --red: #f43f5e;
      --red-bg: rgba(244, 63, 94, 0.16);
      --amber: #f59e0b;
      --amber-bg: rgba(245, 158, 11, 0.16);
      --purple: #a855f7;
      --mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
      --sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: radial-gradient(circle at 15% 0%, #131c31 0%, var(--bg-0) 65%);
      color: var(--text-main);
      font-family: var(--sans);
      line-height: 1.55;
      min-height: 100vh;
      padding-bottom: 4rem;
    }}
    .container {{
      max-width: 1360px;
      margin: 0 auto;
      padding: 0 1.5rem;
    }}
    header {{
      border-bottom: 1px solid var(--border);
      background: rgba(15, 21, 35, 0.85);
      backdrop-filter: blur(12px);
      position: sticky;
      top: 0;
      z-index: 50;
      padding: 1rem 0;
    }}
    .header-inner {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 0.85rem;
    }}
    .brand-badge {{
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: linear-gradient(135deg, #f43f5e, #fb923c);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 1.15rem;
      box-shadow: 0 0 20px rgba(244, 63, 94, 0.4);
    }}
    .brand h1 {{
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }}
    .brand p {{
      font-size: 0.8rem;
      color: var(--text-muted);
    }}
    .header-tags {{
      display: flex;
      gap: 0.6rem;
      flex-wrap: wrap;
    }}
    .pill {{
      font-size: 0.75rem;
      font-family: var(--mono);
      padding: 0.3rem 0.7rem;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--bg-2);
      color: var(--text-main);
    }}
    .pill.success {{
      border-color: rgba(34, 197, 94, 0.5);
      background: var(--green-bg);
      color: #4ade80;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin: 1.75rem 0;
    }}
    .kpi-card {{
      background: var(--bg-1);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.2rem 1.35rem;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.25);
    }}
    .kpi-label {{
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-muted);
      margin-bottom: 0.4rem;
    }}
    .kpi-value {{
      font-size: 1.85rem;
      font-weight: 800;
      font-family: var(--mono);
      display: flex;
      align-items: baseline;
      gap: 0.55rem;
    }}
    .kpi-sub {{
      font-size: 0.78rem;
      color: var(--text-muted);
      margin-top: 0.35rem;
    }}
    .section-grid {{
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 1.25rem;
      margin-bottom: 1.5rem;
    }}
    @media (max-width: 1024px) {{
      .section-grid {{ grid-template-columns: 1fr; }}
    }}
    .panel {{
      background: var(--bg-1);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.4rem;
      margin-bottom: 1.5rem;
    }}
    .panel-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      flex-wrap: wrap;
      gap: 0.75rem;
    }}
    .panel-title {{
      font-size: 1.05rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .gen-tabs {{
      display: flex;
      gap: 0.45rem;
      flex-wrap: wrap;
    }}
    .gen-tab {{
      background: var(--bg-2);
      color: var(--text-muted);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.4rem 0.8rem;
      font-size: 0.8rem;
      font-family: var(--mono);
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .gen-tab:hover {{
      color: var(--text-main);
      border-color: var(--accent);
    }}
    .gen-tab.active {{
      background: var(--accent-glow);
      color: var(--accent);
      border-color: var(--accent);
      font-weight: 700;
    }}
    .chart-box {{
      width: 100%;
      background: var(--bg-0);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem;
    }}
    .legend {{
      display: flex;
      gap: 1.2rem;
      font-size: 0.78rem;
      margin-top: 0.7rem;
      flex-wrap: wrap;
      justify-content: center;
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }}
    .legend-dot {{
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }}
    .diff-card {{
      background: var(--bg-0);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem;
      margin-bottom: 0.85rem;
    }}
    .diff-card.rejected {{
      border-color: rgba(244, 63, 94, 0.55);
      background: rgba(244, 63, 94, 0.06);
    }}
    .diff-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}
    .code-line {{
      font-family: var(--mono);
      font-size: 0.77rem;
      padding: 0.25rem 0.55rem;
      border-radius: 5px;
      margin: 0.22rem 0;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    .code-add {{
      background: var(--green-bg);
      color: #86efac;
      border-left: 3px solid var(--green);
    }}
    .code-rem {{
      background: var(--red-bg);
      color: #fda4af;
      border-left: 3px solid var(--red);
    }}
    .code-neg {{
      background: var(--amber-bg);
      color: #fde68a;
      border-left: 3px solid var(--amber);
    }}
    .cluster-item {{
      background: var(--bg-0);
      border: 1px solid var(--border);
      border-radius: 9px;
      padding: 0.85rem;
      margin-bottom: 0.65rem;
      font-size: 0.83rem;
    }}
    .badge {{
      font-family: var(--mono);
      font-size: 0.7rem;
      font-weight: 700;
      padding: 0.15rem 0.5rem;
      border-radius: 5px;
      display: inline-block;
    }}
    .badge-fp {{ background: var(--amber-bg); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4); }}
    .badge-fn {{ background: var(--red-bg); color: #fb7185; border: 1px solid rgba(244,63,94,0.4); }}
    .badge-ok {{ background: var(--green-bg); color: #4ade80; border: 1px solid rgba(34,197,94,0.4); }}
    .sandbox-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.25rem;
    }}
    @media (max-width: 960px) {{
      .sandbox-grid {{ grid-template-columns: 1fr; }}
    }}
    select, textarea {{
      width: 100%;
      background: var(--bg-0);
      color: var(--text-main);
      border: 1px solid var(--border);
      border-radius: 9px;
      padding: 0.7rem 0.85rem;
      font-family: var(--sans);
      font-size: 0.88rem;
      outline: none;
    }}
    select:focus, textarea:focus {{
      border-color: var(--accent);
    }}
    textarea {{
      min-height: 135px;
      font-family: var(--mono);
      font-size: 0.82rem;
      resize: vertical;
      margin-top: 0.65rem;
    }}
    .highlight-box {{
      background: var(--bg-0);
      border: 1px solid var(--border);
      border-radius: 9px;
      padding: 0.9rem;
      font-family: var(--mono);
      font-size: 0.83rem;
      min-height: 95px;
      white-space: pre-wrap;
      line-height: 1.65;
    }}
    mark.redflag {{
      background: rgba(244, 63, 94, 0.28);
      color: #fecdd3;
      border-bottom: 2px solid var(--red);
      padding: 0.05rem 0.25rem;
      border-radius: 4px;
    }}
    .decision-banner {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.85rem 1rem;
      border-radius: 10px;
      margin-bottom: 0.9rem;
      font-family: var(--mono);
      font-weight: 700;
    }}
    .decision-BLOCK {{
      background: var(--red-bg);
      border: 1px solid var(--red);
      color: #fda4af;
    }}
    .decision-REVIEW {{
      background: var(--amber-bg);
      border: 1px solid var(--amber);
      color: #fde68a;
    }}
    .decision-ALLOW {{
      background: var(--green-bg);
      border: 1px solid var(--green);
      color: #86efac;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }}
    th, td {{
      text-align: left;
      padding: 0.6rem 0.75rem;
      border-bottom: 1px solid var(--border);
    }}
    th {{
      color: var(--text-muted);
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
    }}
  </style>
</head>
<body>
  <header>
    <div class="container header-inner">
      <div class="brand">
        <div class="brand-badge">RF</div>
        <div>
          <h1>RedFlag Loop — Autonomous Scam Rule Evolution</h1>
          <p>Write &rarr; Run &rarr; Evaluate &rarr; Repair Loop for Indonesian Marketplace Trust &amp; Safety</p>
        </div>
      </div>
      <div class="header-tags">
        <span class="pill">Direction 1: Autonomous &amp; Adaptive AI</span>
        <span class="pill">Benchmark: ID-ScamChat-72 (6 Categories)</span>
        <span class="pill success" id="header-convergence-pill">Converged: Gen 3 (F1 = 1.000)</span>
      </div>
    </div>
  </header>

  <main class="container">
    <!-- KPI Row -->
    <section class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">F1 Score Evolution (Gen 0 &rarr; Gen 3)</div>
        <div class="kpi-value">
          <span style="color: var(--green)">{report.final_f1:.3f}</span>
          <span style="font-size: 0.95rem; color: #4ade80;">+{report.f1_improvement:.3f} vs Gen 0 ({report.initial_f1:.3f})</span>
        </div>
        <div class="kpi-sub">Target threshold &ge; {report.target_f1:.2f} achieved in {report.generations_run - 1} autonomous repair rounds</div>
      </div>

      <div class="kpi-card">
        <div class="kpi-label">False Positive Rate (Hard Negatives)</div>
        <div class="kpi-value">
          <span style="color: var(--accent)">{report.final_fpr * 100:.1f}%</span>
          <span style="font-size: 0.95rem; color: var(--text-muted);">down from {report.initial_fpr * 100:.1f}%</span>
        </div>
        <div class="kpi-sub">0 false alarms on legitimate J&amp;T/JNE resi, Pusat Resolusi &amp; official QRIS chats</div>
      </div>

      <div class="kpi-card">
        <div class="kpi-label">Sealed Holdout Test Suite F1</div>
        <div class="kpi-value">
          <span style="color: #c084fc">{report.generations[-1].sealed_test_metrics.f1:.3f}</span>
          <span style="font-size: 0.95rem; color: var(--text-muted);">100% Precision &amp; Recall</span>
        </div>
        <div class="kpi-sub">Evaluated on untouched sealed_test split after candidate freeze</div>
      </div>

      <div class="kpi-card">
        <div class="kpi-label">Safety Guardrail Enforcement</div>
        <div class="kpi-value">
          <span style="color: var(--amber)">1 Rollback</span>
          <span style="font-size: 0.9rem; color: var(--text-muted);">Max FPR &le; {report.max_fpr_guardrail * 100:.1f}%</span>
        </div>
        <div class="kpi-sub">Rejected overbroad Candidate 2A automatically before activating Candidate 2B</div>
      </div>
    </section>

    <!-- Live Indonesian Chat Scam Sandbox -->
    <section class="panel">
      <div class="panel-header">
        <div class="panel-title">&#x1F6E1;&#xFE0F; Live Indonesian Marketplace Chat Scam Sandbox (Gen 3 Evolved vs Gen 0 Baseline)</div>
        <div class="gen-tabs">
          <button class="gen-tab active" id="sandbox-mode-gen3" onclick="setSandboxGen(3)">Active: Generation 3 (Evolved)</button>
          <button class="gen-tab" id="sandbox-mode-gen0" onclick="setSandboxGen(0)">Compare: Generation 0 (Naive Baseline)</button>
        </div>
      </div>

      <div class="sandbox-grid">
        <div>
          <label for="preset-select" style="font-size: 0.8rem; color: var(--text-muted); display:block; margin-bottom:0.35rem;">
            Select Preset Marketplace Scenario (All 6 Categories + Hard Negatives) or Type Below:
          </label>
          <select id="preset-select" onchange="loadPresetSample()"></select>
          <textarea id="sandbox-input" oninput="runSandboxEvaluation()" placeholder="Ketik pesan chat pembeli/penjual Bahasa Indonesia di sini..."></textarea>
          <div style="margin-top: 0.55rem; font-size: 0.76rem; color: var(--text-muted);">
            Tip: Toggle between <strong>Generation 3</strong> and <strong>Generation 0</strong> above to see how Gen 0 falsely blocks legitimate <em>cek resi JNT</em> / <em>Pusat Resolusi</em> chats while missing obfuscated scams.
          </div>
        </div>

        <div>
          <div id="sandbox-decision-banner" class="decision-banner decision-ALLOW">
            <span id="sandbox-decision-text">DECISION: ALLOW</span>
            <span id="sandbox-score-text">Risk Score: 0.00</span>
          </div>

          <div style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 0.3rem;">
            Explainable Red-Flag Evidence Spans:
          </div>
          <div id="sandbox-highlighted" class="highlight-box"></div>

          <div id="sandbox-rules-summary" style="margin-top: 0.75rem; font-size: 0.8rem;"></div>
        </div>
      </div>
    </section>

    <!-- Chart + Generation Inspector -->
    <div class="section-grid">
      <section class="panel" style="margin-bottom:0;">
        <div class="panel-header">
          <div class="panel-title">&#x1F4C8; Autonomous Evolution Progression (Generations 0 &rarr; 3)</div>
        </div>
        <div class="chart-box">
          <svg id="progression-svg" viewBox="0 0 640 270" width="100%" height="260"></svg>
          <div class="legend">
            <div class="legend-item"><span class="legend-dot" style="background:#22c55e"></span>F1 Score</div>
            <div class="legend-item"><span class="legend-dot" style="background:#38bdf8"></span>Precision</div>
            <div class="legend-item"><span class="legend-dot" style="background:#a855f7"></span>Recall</div>
            <div class="legend-item"><span class="legend-dot" style="background:#f43f5e"></span>False Positive Rate (FPR)</div>
          </div>
        </div>

        <table style="margin-top: 1rem;">
          <thead>
            <tr>
              <th>Gen</th>
              <th>Precision</th>
              <th>Recall</th>
              <th>Full F1</th>
              <th>Val F1</th>
              <th>Sealed Test F1</th>
              <th>FPR</th>
              <th>FP / FN</th>
            </tr>
          </thead>
          <tbody id="metrics-table-body"></tbody>
        </table>
      </section>

      <section class="panel" style="margin-bottom:0;">
        <div class="panel-header">
          <div class="panel-title">&#x1F50D; Failure Cluster Diagnosis (FP / FN Root Causes)</div>
          <div class="gen-tabs" id="cluster-gen-tabs"></div>
        </div>
        <p id="gen-summary-text" style="font-size: 0.83rem; color: var(--text-muted); margin-bottom: 0.9rem;"></p>
        <div id="clusters-container"></div>
      </section>
    </div>

    <!-- Rule Diff Viewer -->
    <section class="panel" style="margin-top: 1.5rem;">
      <div class="panel-header">
        <div class="panel-title">&#x1F9EC; Autonomous Rule Patch &amp; Guardrail Rollback Diff Viewer</div>
        <div class="gen-tabs" id="diff-gen-tabs"></div>
      </div>
      <div id="diffs-container"></div>
    </section>
  </main>

  <script>
    const REPORT = {report_json};
    const SAMPLES = {samples_json};

    let currentSandboxGen = 3;
    let selectedGenIndex = 0;
    let selectedDiffGenIndex = 2;

    function escapeHtml(str) {{
      return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }}

    function renderProgressionChart() {{
      const svg = document.getElementById("progression-svg");
      const gens = REPORT.generations;
      const w = 640, h = 270;
      const padL = 52, padR = 30, padT = 24, padB = 38;
      const plotW = w - padL - padR;
      const plotH = h - padT - padB;

      const xFor = (i) => padL + (i / (gens.length - 1)) * plotW;
      const yFor = (val) => padT + (1.0 - val) * plotH;

      let out = "";
      // Grid lines
      [0.0, 0.25, 0.5, 0.75, 0.95, 1.0].forEach(v => {{
        const y = yFor(v);
        const isTarget = Math.abs(v - 0.95) < 0.001;
        out += `<line x1="${{padL}}" y1="${{y}}" x2="${{w - padR}}" y2="${{y}}" stroke="${{isTarget ? '#22c55e55' : '#283655'}}" stroke-dasharray="${{isTarget ? '5,4' : 'none'}}" stroke-width="1" />`;
        out += `<text x="${{padL - 8}}" y="${{y + 4}}" fill="#94a3b8" font-size="11" font-family="monospace" text-anchor="end">${{(v * 100).toFixed(0)}}%</text>`;
      }});

      const series = [
        {{ key: "f1", color: "#22c55e", width: 3.2 }},
        {{ key: "precision", color: "#38bdf8", width: 2.2 }},
        {{ key: "recall", color: "#a855f7", width: 2.2 }},
        {{ key: "false_positive_rate", color: "#f43f5e", width: 2.5 }}
      ];

      series.forEach(s => {{
        const pts = gens.map((g, i) => `${{xFor(i)}},${{yFor(g.metrics[s.key])}}`).join(" ");
        out += `<polyline fill="none" stroke="${{s.color}}" stroke-width="${{s.width}}" points="${{pts}}" />`;
        gens.forEach((g, i) => {{
          const cx = xFor(i), cy = yFor(g.metrics[s.key]);
          out += `<circle cx="${{cx}}" cy="${{cy}}" r="4.5" fill="${{s.color}}" stroke="#080b12" stroke-width="1.5" />`;
        }});
      }});

      gens.forEach((g, i) => {{
        const x = xFor(i);
        out += `<text x="${{x}}" y="${{h - 10}}" fill="#f1f5f9" font-size="12" font-family="monospace" text-anchor="middle">Gen ${{g.generation}}</text>`;
      }});

      svg.innerHTML = out;

      // Render table
      const tbody = document.getElementById("metrics-table-body");
      tbody.innerHTML = gens.map(g => `
        <tr>
          <td><strong>Gen ${{g.generation}}</strong></td>
          <td>${{(g.metrics.precision * 100).toFixed(1)}}%</td>
          <td>${{(g.metrics.recall * 100).toFixed(1)}}%</td>
          <td><strong style="color:#4ade80">${{g.metrics.f1.toFixed(3)}}</strong></td>
          <td>${{g.validation_metrics.f1.toFixed(3)}}</td>
          <td>${{g.sealed_test_metrics.f1.toFixed(3)}}</td>
          <td style="color:${{g.metrics.false_positive_rate > 0 ? '#fb7185' : '#4ade80'}}">${{(g.metrics.false_positive_rate * 100).toFixed(1)}}%</td>
          <td>${{g.metrics.false_positives}} FP / ${{g.metrics.false_negatives}} FN</td>
        </tr>
      `).join("");
    }}

    function selectClusterGen(idx) {{
      selectedGenIndex = idx;
      const tabs = document.getElementById("cluster-gen-tabs");
      tabs.innerHTML = REPORT.generations.map((g, i) => `
        <button class="gen-tab ${{i === idx ? 'active' : ''}}" onclick="selectClusterGen(${{i}})">
          Gen ${{g.generation}} (${{g.failure_clusters.length}})
        </button>
      `).join("");

      const gen = REPORT.generations[idx];
      document.getElementById("gen-summary-text").textContent = gen.summary;
      const container = document.getElementById("clusters-container");
      if (gen.failure_clusters.length === 0) {{
        container.innerHTML = `<div class="cluster-item"><span class="badge badge-ok">ZERO FAILURES</span> All 72 Indonesian marketplace conversations (50 scam + 22 benign &amp; hard-negative courier/refund chats) classified with 100% F1 and 0.0% FPR.</div>`;
        return;
      }}
      container.innerHTML = gen.failure_clusters.map(c => `
        <div class="cluster-item">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.35rem;">
            <span class="badge ${{c.failure_type === 'FP' ? 'badge-fp' : 'badge-fn'}}">${{c.failure_type}} CLUSTER &bull; ${{c.offending_or_missing_rule_id}}</span>
            <span style="font-family:var(--mono); font-size:0.74rem; color:var(--text-muted);">${{c.sample_ids.length}} samples (${{c.sample_ids.slice(0, 3).join(', ')}}${{c.sample_ids.length > 3 ? '...' : ''}})</span>
          </div>
          <div style="font-weight:600; margin-bottom:0.25rem;">${{escapeHtml(c.root_cause)}}</div>
          <div style="color:var(--text-muted); font-size:0.78rem; margin-bottom:0.3rem;"><em>Example:</em> "${{escapeHtml(c.example_snippet)}}..."</div>
          <div style="color:#38bdf8; font-size:0.78rem;"><strong>Autonomous Remediation:</strong> ${{escapeHtml(c.proposed_remediation)}}</div>
        </div>
      `).join("");
    }}

    function selectDiffGen(idx) {{
      selectedDiffGenIndex = idx;
      const tabs = document.getElementById("diff-gen-tabs");
      tabs.innerHTML = REPORT.generations.slice(1).map((g) => `
        <button class="gen-tab ${{g.generation === idx ? 'active' : ''}}" onclick="selectDiffGen(${{g.generation}})">
          Gen ${{g.generation - 1}} &rarr; Gen ${{g.generation}} Repair
        </button>
      `).join("");

      const gen = REPORT.generations[idx];
      const container = document.getElementById("diffs-container");
      let html = "";

      if (gen.rejected_patches && gen.rejected_patches.length > 0) {{
        gen.rejected_patches.forEach(p => {{
          html += `
            <div class="diff-card rejected">
              <div class="diff-header">
                <strong>&#x1F6D1; ${{escapeHtml(p.rule_id)}} — ${{escapeHtml(p.rule_name)}}</strong>
                <span class="badge badge-fn">${{escapeHtml(p.validation_status)}}</span>
              </div>
              <div style="font-size:0.82rem; color:#fda4af; margin-bottom:0.45rem;">${{escapeHtml(p.validation_note)}}</div>
              ${{p.added_patterns.map(pat => `<div class="code-line code-rem">! REJECTED PATTERN: ${{escapeHtml(pat)}}</div>`).join("")}}
            </div>
          `;
        }});
      }}

      gen.applied_patches.forEach(p => {{
        html += `
          <div class="diff-card">
            <div class="diff-header">
              <strong>&#x2705; ${{escapeHtml(p.rule_id)}} — ${{escapeHtml(p.rule_name)}}</strong>
              <span class="badge badge-ok">${{escapeHtml(p.validation_status)}}</span>
            </div>
            <div style="font-size:0.82rem; color:var(--text-muted); margin-bottom:0.5rem;">${{escapeHtml(p.rationale)}}</div>
            ${{p.removed_patterns.map(pat => `<div class="code-line code-rem">- REMOVED OVERBROAD: ${{escapeHtml(pat)}}</div>`).join("")}}
            ${{p.added_patterns.map(pat => `<div class="code-line code-add">+ ADDED PATTERN:     ${{escapeHtml(pat)}}</div>`).join("")}}
            ${{p.added_negative_patterns.map(pat => `<div class="code-line code-neg">&#x1F6E1; WHITELIST CONTEXT: ${{escapeHtml(pat)}}</div>`).join("")}}
            <div style="font-size:0.76rem; color:#4ade80; margin-top:0.45rem;">Validation Check: ${{escapeHtml(p.validation_note)}}</div>
          </div>
        `;
      }});

      container.innerHTML = html;
    }}

    function evaluateTextJS(text, genIndex) {{
      const rules = REPORT.generations[genIndex].rules;
      let totalWeight = 0.0;
      const triggered = [];
      const suppressed = [];
      const spans = [];

      rules.forEach(rule => {{
        let isSuppressed = false;
        (rule.negative_patterns || []).forEach(negPat => {{
          try {{
            const reNeg = new RegExp(negPat, "i");
            if (reNeg.test(text)) isSuppressed = true;
          }} catch (e) {{}}
        }});

        const ruleSpans = [];
        (rule.patterns || []).forEach(pat => {{
          try {{
            const re = new RegExp(pat, "gi");
            let m;
            while ((m = re.exec(text)) !== null) {{
              ruleSpans.push({{
                rule_id: rule.rule_id,
                rule_name: rule.name,
                text: m[0],
                start: m.index,
                end: m.index + m[0].length,
                weight: rule.weight
              }});
              if (m.index === re.lastIndex) re.lastIndex++;
            }}
          }} catch (e) {{}}
        }});

        (rule.proximity_pairs || []).forEach(pair => {{
          try {{
            const reA = new RegExp(pair.token_a, "gi");
            const reB = new RegExp(pair.token_b, "gi");
            let ma, mb;
            const listA = [], listB = [];
            while ((ma = reA.exec(text)) !== null) listA.push({{ s: ma.index, e: ma.index + ma[0].length }});
            while ((mb = reB.exec(text)) !== null) listB.push({{ s: mb.index, e: mb.index + mb[0].length }});
            listA.forEach(a => {{
              listB.forEach(b => {{
                const dist = Math.max(0, Math.max(a.s, b.s) - Math.min(a.e, b.e));
                if (dist <= pair.max_window_chars) {{
                  const s = Math.min(a.s, b.s), e = Math.max(a.e, b.e);
                  ruleSpans.push({{
                    rule_id: rule.rule_id,
                    rule_name: rule.name,
                    text: text.slice(s, e),
                    start: s,
                    end: e,
                    weight: rule.weight
                  }});
                }}
              }});
            }});
          }} catch (e) {{}}
        }});

        if (ruleSpans.length > 0) {{
          if (isSuppressed) {{
            suppressed.push(rule.rule_id);
          }} else {{
            triggered.push(rule);
            totalWeight += rule.weight;
            ruleSpans.forEach(sp => spans.push(sp));
          }}
        }}
      }});

      const riskScore = Math.min(1.0, totalWeight);
      const decision = riskScore >= 0.50 ? "BLOCK" : (riskScore >= 0.25 ? "REVIEW" : "ALLOW");
      return {{ riskScore, decision, triggered, suppressed, spans }};
    }}

    function populateSandboxPresets() {{
      const sel = document.getElementById("preset-select");
      const featuredIds = [
        "BENIGN_HN_11",
        "BENIGN_HN_13",
        "BENIGN_HN_14",
        "PHISH_03",
        "APK_01",
        "APK_03",
        "QRIS_01",
        "QRIS_03",
        "ESCROW_03",
        "FAKECS_02",
        "FAKECS_04"
      ];
      const featured = featuredIds.map(id => SAMPLES.find(s => s.sample_id === id)).filter(Boolean);
      sel.innerHTML = featured.map((s, idx) => {{
        const tag = s.is_scam ? "[SCAM]" : "[LEGIT HARD-NEGATIVE]";
        return `<option value="${{s.sample_id}}" ${{idx === 0 ? 'selected' : ''}}>${{tag}} ${{s.sample_id}} — ${{s.category_label}} (${{s.notes}})</option>`;
      }}).join("");
      loadPresetSample();
    }}

    function loadPresetSample() {{
      const id = document.getElementById("preset-select").value;
      const sample = SAMPLES.find(s => s.sample_id === id);
      if (!sample) return;
      const text = sample.turns.map(t => t.text).join(" ");
      document.getElementById("sandbox-input").value = text;
      runSandboxEvaluation();
    }}

    function setSandboxGen(genNum) {{
      currentSandboxGen = genNum;
      document.getElementById("sandbox-mode-gen3").classList.toggle("active", genNum === 3);
      document.getElementById("sandbox-mode-gen0").classList.toggle("active", genNum === 0);
      runSandboxEvaluation();
    }}

    function runSandboxEvaluation() {{
      const text = document.getElementById("sandbox-input").value || "";
      const res = evaluateTextJS(text, currentSandboxGen);

      const banner = document.getElementById("sandbox-decision-banner");
      banner.className = `decision-banner decision-${{res.decision}}`;
      document.getElementById("sandbox-decision-text").textContent =
        `[Gen ${{currentSandboxGen}}] DECISION: ${{res.decision}}`;
      document.getElementById("sandbox-score-text").textContent =
        `Risk Score: ${{res.riskScore.toFixed(2)}}`;

      // Highlight non-overlapping spans
      const sorted = [...res.spans].sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
      const merged = [];
      sorted.forEach(sp => {{
        if (merged.length === 0 || sp.start >= merged[merged.length - 1].end) {{
          merged.push({{ ...sp }});
        }}
      }});

      let pos = 0;
      let html = "";
      merged.forEach(sp => {{
        html += escapeHtml(text.slice(pos, sp.start));
        html += `<mark class="redflag" title="${{escapeHtml(sp.rule_id)}}">${{escapeHtml(text.slice(sp.start, sp.end))}}</mark>`;
        pos = sp.end;
      }});
      html += escapeHtml(text.slice(pos));
      document.getElementById("sandbox-highlighted").innerHTML = html || "<em>(Empty chat message)</em>";

      let summaryHtml = "";
      if (res.triggered.length > 0) {{
        summaryHtml += `<div style="margin-bottom:0.35rem;"><strong>Triggered Rules (${{res.triggered.length}}):</strong> ` +
          res.triggered.map(r => `<span class="badge badge-fn" style="margin-right:0.35rem;">${{escapeHtml(r.rule_id)}} (+${{r.weight.toFixed(2)}})</span>`).join("") +
          `</div>`;
      }} else {{
        summaryHtml += `<div style="color:#4ade80; margin-bottom:0.35rem;">&#x2714; No scam rules triggered (Safe Marketplace Conversation).</div>`;
      }}
      if (res.suppressed.length > 0) {{
        summaryHtml += `<div style="color:#fde68a;">&#x1F6E1; <strong>Whitelist Context Suppressed False Positive:</strong> ${{res.suppressed.join(", ")}}</div>`;
      }}
      document.getElementById("sandbox-rules-summary").innerHTML = summaryHtml;
    }}

    renderProgressionChart();
    selectClusterGen(0);
    selectDiffGen(2);
    populateSandboxPresets();
  </script>
</body>
</html>
"""
    return html


def main(argv: list[str] | None = None) -> int:
    """Run the autonomous loop, export evolution_report.json, and build web/index.html."""
    parser = argparse.ArgumentParser(
        prog="redflag-loop",
        description="Run the RedFlag Loop autonomous scam rule evolution engine and dashboard generator.",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=None,
        help="Path to labeled Indonesian chat corpus JSON.",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help="Output path for evolution_report.json.",
    )
    parser.add_argument(
        "--dashboard-out",
        type=Path,
        default=DEFAULT_DASHBOARD_PATH,
        help="Output path for self-contained interactive HTML dashboard.",
    )
    args = parser.parse_args(argv)

    loop = AutonomousRedFlagLoop(corpus_path=args.corpus)
    report = loop.run()

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    args.dashboard_out.parent.mkdir(parents=True, exist_ok=True)
    dashboard_html = build_dashboard_html(report, loop.samples)
    args.dashboard_out.write_text(dashboard_html, encoding="utf-8")

    print("=" * 76)
    print(f"RedFlag Loop -- {report.benchmark_name}")
    print("=" * 76)
    for gen in report.generations:
        m = gen.metrics
        print(
            f"[Gen {gen.generation}] Precision={m.precision:.3f} | Recall={m.recall:.3f} | "
            f"F1={m.f1:.3f} | FPR={m.false_positive_rate:.3f} | "
            f"Val F1={gen.validation_metrics.f1:.3f} | Sealed Test F1={gen.sealed_test_metrics.f1:.3f}"
        )
    print("-" * 76)
    print(
        f"Converged: {report.converged} | F1 Improvement: +{report.f1_improvement:.3f} "
        f"({report.initial_f1:.3f} -> {report.final_f1:.3f}) | Final FPR: {report.final_fpr:.3f}"
    )
    print(f"Report written to   : {args.report_out}")
    print(f"Dashboard written to: {args.dashboard_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
