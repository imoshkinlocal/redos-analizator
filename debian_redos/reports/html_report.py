"""Self-contained HTML report (no external assets, works offline)."""

from __future__ import annotations

import html
import json
import os
from typing import List

from ..models import Finding, ScanResult

_STYLE = """
:root{--bg:#0f1520;--panel:#161f2e;--line:#26344a;--fg:#dbe4f0;--muted:#8ea0b8;
--crit:#ff5d6c;--high:#ff8a4c;--med:#ffd166;--low:#6ec6ff;--info:#9aa7b8;--ok:#4ade80}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{padding:24px 32px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0 0 6px;font-size:20px;letter-spacing:.5px}
.sub{color:var(--muted);font-size:12px}
main{padding:24px 32px 64px;max-width:1500px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
gap:12px;margin-bottom:24px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}
.card .n{font-size:24px;font-weight:700}
.card .l{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.8px}
.card.crit .n{color:var(--crit)}.card.high .n{color:var(--high)}
.card.med .n{color:var(--med)}.card.low .n{color:var(--low)}
.card.ok .n{color:var(--ok)}
.controls{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 18px}
input,select{background:var(--panel);border:1px solid var(--line);color:var(--fg);
padding:8px 10px;border-radius:6px;font:inherit;font-size:13px}
input{min-width:320px}
table{width:100%;border-collapse:collapse;background:var(--panel);
border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);
vertical-align:top;font-size:13px}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.8px;
position:sticky;top:0;background:var(--panel)}
tr:hover td{background:#1a2536}
.badge{display:inline-block;padding:1px 7px;border-radius:999px;
font-size:11px;border:1px solid currentColor;white-space:nowrap}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}
.low{color:var(--low)}.info{color:var(--info)}
.verdict-exploitable{color:var(--crit);font-weight:700}
.verdict-confirmed{color:var(--high);font-weight:700}
.verdict-needs_review{color:var(--med)}
.verdict-potential{color:var(--low)}
.verdict-informational{color:var(--info)}
code{background:#0b111b;border:1px solid var(--line);padding:2px 6px;border-radius:4px;
font-size:12px;word-break:break-all}
.loc{color:var(--muted);font-size:12px}
.why{color:var(--muted);font-size:12px;max-width:420px}
.why b{color:var(--fg);font-weight:600}
details summary{cursor:pointer;color:var(--low);font-size:12px}
.empty{padding:24px;color:var(--muted);border:1px dashed var(--line);border-radius:8px}
a{color:var(--low)}
footer{margin-top:28px;color:var(--muted);font-size:11px}
"""

_SCRIPT = """
const rows=[...document.querySelectorAll('tbody tr')];
const sev=document.getElementById('sev'),vd=document.getElementById('vd'),
      q=document.getElementById('q'),cnt=document.getElementById('cnt');
function apply(){
  const s=sev.value,v=vd.value,t=q.value.toLowerCase();let n=0;
  rows.forEach(r=>{
    const ok=(!s||r.dataset.severity===s)&&(!v||r.dataset.verdict===v)&&
             (!t||r.dataset.text.includes(t));
    r.style.display=ok?'':'none';if(ok)n++;
  });
  cnt.textContent=n+' / '+rows.length+' findings';
}
[sev,vd,q].forEach(e=>e.addEventListener('input',apply));apply();
"""


def _esc(value) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _evidence_html(finding: Finding) -> str:
    items: List[str] = []
    for evidence in finding.static.evidence[:4]:
        items.append(f"<b>{_esc(evidence.rule)}</b>: {_esc(evidence.message)}")
    if finding.dynamic.status != "skipped":
        growth = finding.dynamic.growth_class or "unknown"
        detail = f"dynamic: {finding.dynamic.status} ({growth}"
        if finding.dynamic.max_elapsed_ms is not None:
            detail += f", {finding.dynamic.max_elapsed_ms:.1f} ms"
        detail += ")"
        items.append(_esc(detail))
    if finding.input_control and finding.input_control != "unknown":
        items.append(f"input: {_esc(finding.input_control)}")
    if not items:
        return '<span class="why">-</span>'
    if len(items) <= 2:
        return '<span class="why">' + "<br>".join(items) + "</span>"
    return ('<span class="why">' + items[0] +
            "<details><summary>more</summary>" + "<br>".join(items[1:]) +
            "</details></span>")


def _known_html(finding: Finding) -> str:
    if not finding.known:
        return ""
    items: List[str] = []
    for match in finding.known[:3]:
        label = match.cve or match.id
        title = _esc(match.title)
        detail = _esc(f"{match.kind} {match.confidence} {match.score:.2f}")
        items.append(
            f'<span class="badge high" title="{title} ({detail})">'
            f'{_esc(label)}</span>'
        )
    if len(finding.known) > 3:
        items.append(f'<span class="loc">+{len(finding.known) - 3}</span>')
    return "<br>" + " ".join(items)


def build_html(result: ScanResult) -> str:
    stats = result.stats
    severity = result.counts_by_severity()
    verdicts = {}
    for finding in result.findings:
        verdicts[finding.verdict] = verdicts.get(finding.verdict, 0) + 1

    rows = []
    for finding in result.findings:
        searchable = " ".join(filter(None, [
            finding.package, finding.file, str(finding.line), finding.function,
            finding.pattern, finding.verdict, finding.severity,
            finding.static.complexity, finding.input_control,
            finding.cve,
            " ".join(match.cve or match.id for match in finding.known),
            " ".join(match.title for match in finding.known),
        ])).lower()
        cve = (f'<br><span class="badge high">{_esc(finding.cve)}</span>'
               if finding.cve else "")
        known = _known_html(finding)
        duplicates = (f'<br><span class="loc">+{finding.duplicates} duplicate site(s)</span>'
                      if finding.duplicates else "")
        pattern = _esc((finding.pattern or "<dynamic>")[:300])
        rows.append(f"""
<tr data-severity="{_esc(finding.severity)}" data-verdict="{_esc(finding.verdict)}"
    data-text="{_esc(searchable)}">
  <td><span class="badge {_esc(finding.severity)}">{_esc(finding.severity)}</span><br>
      <span class="verdict-{_esc(finding.verdict)}">{_esc(finding.verdict)}</span>{cve}{known}</td>
  <td><code>{pattern}</code><br>
      <span class="loc">{_esc(finding.static.complexity)} ReDoS &middot;
      {_esc(finding.language)} &middot; flags: {_esc(finding.flags) or '-'}</span></td>
  <td>{_esc(finding.package)}<br>
      <span class="loc">{_esc(finding.file)}:{_esc(finding.line)}<br>
      {_esc(finding.function)}</span>{duplicates}</td>
  <td>{_evidence_html(finding)}</td>
</tr>""")

    package_list = "".join(
        f"<li>{_esc(p.name)} {_esc(p.version)} &mdash; {_esc(p.directory)}</li>"
        for p in result.packages) or "<li>none</li>"
    notes = "".join(f"<li>{_esc(n)}</li>" for n in result.notes) or "<li>none</li>"

    if not rows:
        table = '<div class="empty">No findings matched the current policy.</div>'
    else:
        table = f"""
<table id="t">
<thead><tr><th>Severity / verdict</th><th>Pattern</th><th>Location</th>
<th>Why</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>"""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Debian ReDoS report {_esc(result.run_id)}</title>
<style>{_STYLE}</style></head>
<body>
<header>
  <h1>Debian ReDoS scan &mdash; {_esc(result.run_id)}</h1>
  <div class="sub">mode {_esc(result.mode)} &middot; {_esc(result.started_at)} &rarr;
    {_esc(result.finished_at)} &middot; duration {stats.duration_seconds:.2f}s</div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="n">{stats.packages}</div><div class="l">packages</div></div>
    <div class="card"><div class="n">{stats.files_scanned}</div><div class="l">files scanned</div></div>
    <div class="card"><div class="n">{stats.files_skipped_cached}</div><div class="l">cached files</div></div>
    <div class="card"><div class="n">{stats.candidates}</div><div class="l">candidates</div></div>
    <div class="card med"><div class="n">{severity.get('medium', 0)}</div><div class="l">medium</div></div>
    <div class="card high"><div class="n">{severity.get('high', 0)}</div><div class="l">high</div></div>
    <div class="card crit"><div class="n">{severity.get('critical', 0)}</div><div class="l">critical</div></div>
    <div class="card ok"><div class="n">{stats.confirmed}</div><div class="l">confirmed</div></div>
    <div class="card med"><div class="n">{stats.known_matched}</div><div class="l">known matches</div></div>
  </div>
  <div class="controls">
    <input id="q" type="search" placeholder="filter by package, file, pattern, function...">
    <select id="sev"><option value="">all severities</option>
      <option>critical</option><option>high</option><option>medium</option>
      <option>low</option><option>info</option></select>
    <select id="vd"><option value="">all verdicts</option>
      <option>exploitable</option><option>confirmed</option>
      <option>needs_review</option><option>potential</option>
      <option>informational</option></select>
    <span class="sub" id="cnt" style="align-self:center"></span>
  </div>
  {table}
  <footer>
    <p><b>Packages</b></p><ul>{package_list}</ul>
    <p><b>Notes</b></p><ul>{notes}</ul>
    <p>Generated by debian-redos. A finding is <code>confirmed</code> only when
    degradation was reproduced in the target engine; <code>exploitable</code>
    additionally requires attacker-controlled input.</p>
  </footer>
</main>
<script>{_SCRIPT}</script>
</body></html>
"""


def write_html(result: ScanResult, output_dir: str,
               filename: str = "redos-report.html") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_html(result))
    return path
