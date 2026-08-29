"""Self-contained HTML report — the front end for a scan's results.

SARIF is for machines and the terminal text is for a CI log. Neither is what you
hand a teammate who asked "is our CI safe?" This renders one static, dependency-
free, theme-aware page: the level counts up top, then each finding with its
evidence and the exact fix, sorted worst-first.

No external assets — everything is inlined so the file opens from disk, works
offline, and can be uploaded as a CI artifact with no CSP surprises.
"""

from __future__ import annotations

import html

from . import __version__
from .model import AnalysisResult, Finding
from .severity import SEVERITY_ORDER as _SEV_ORDER

__all__ = ["render_html"]

_SEV_LABEL = {"critical": "Critical", "warning": "Warning", "note": "Note"}


def _esc(text: str) -> str:
    return html.escape(text or "", quote=True)


def _cap_pill(cap: str, observed: bool) -> str:
    title = {
        "U": "Untrusted input reaches this job",
        "P": "The job holds credentials or privilege",
        "E": "The job can reach the network or change state",
    }[cap]
    cls = f"pill pill-{cap.lower()}" + ("" if observed else " pill-assumed")
    suffix = "" if observed else "?"
    return f'<span class="{cls}" title="{_esc(title)}">{cap}{suffix}</span>'


def _finding_card(finding: Finding) -> str:
    sev = finding.severity
    loc = f"{finding.primary_position.file}:{finding.primary_position.line}"
    caps = "".join(
        _cap_pill(c, any(h.observed for h in finding.hits if h.capability == c))
        for c in ("U", "P", "E")
        if any(h.capability == c for h in finding.hits)
    )

    hit_rows = []
    for cap in ("U", "P", "E"):
        for hit in [h for h in finding.hits if h.capability == cap][:3]:
            marker = hit.capability if hit.observed else f"{hit.capability}?"
            hit_rows.append(
                f'<li><span class="hit-cap hit-{cap.lower()}">{marker}</span>'
                f'<span class="hit-reason">{_esc(hit.reason)}</span>'
                f'<span class="hit-loc">{_esc(hit.position.file)}:{hit.position.line}</span></li>'
            )
    hits_html = "\n".join(hit_rows)

    fix_html = ""
    if finding.remediation is not None:
        rem = finding.remediation
        fix_html = (
            '<div class="fix">'
            f'<div class="fix-head">Cheapest fix &mdash; strip <b>{rem.strip}</b></div>'
            f'<pre class="fix-body">{_esc(rem.rendered)}</pre>'
            f'<div class="fix-breaks"><b>Breaks:</b> {_esc(rem.breaks)}</div>'
            "</div>"
        )

    return f"""
    <article class="finding sev-{sev}" id="{_esc(finding.rule_id.replace('/', '-'))}-{_esc(finding.context.job_id)}">
      <header class="finding-head">
        <span class="sev-tag sev-tag-{sev}">{_SEV_LABEL[sev]}</span>
        <span class="finding-loc">{_esc(loc)}</span>
        <span class="finding-job">job "{_esc(finding.context.job_id)}"</span>
        <span class="finding-caps">{caps}</span>
      </header>
      <div class="finding-rule"><a href="#" class="rule-id">{_esc(finding.rule_id)}</a></div>
      <p class="finding-msg">{_esc(finding.message)}</p>
      <ul class="hits">{hits_html}</ul>
      {fix_html}
    </article>"""


def render_html(
    result: AnalysisResult,
    *,
    repo_label: str,
    external_summary: str | None = None,
) -> str:
    counts = {"critical": 0, "warning": 0, "note": 0}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    ordered = sorted(
        result.findings, key=lambda f: (_SEV_ORDER[f.severity], f.sort_key)
    )
    cards = "\n".join(_finding_card(f) for f in ordered) or (
        '<div class="empty">No findings. Every job holds at most two of the three '
        "capabilities &mdash; compliant with the Agents Rule of Two.</div>"
    )

    ext = f'<div class="ext-note">{_esc(external_summary)}</div>' if external_summary else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TriDelPhi report &mdash; {_esc(repo_label)}</title>
<style>
{_CSS}
</style>
</head>
<body>
<div class="wrap">
  <header class="page-head">
    <div class="brand">TriDelPhi</div>
    <div class="tagline">Agents Rule of Two &mdash; static scan of GitHub Actions</div>
    <div class="meta">{_esc(repo_label)} &middot; {result.files_scanned} workflow(s) &middot;
      {result.contexts_scanned} job(s) &middot; tridelphi {__version__}</div>
  </header>

  <section class="scoreboard">
    <div class="score score-critical"><div class="score-n">{counts['critical']}</div><div class="score-l">Critical</div></div>
    <div class="score score-warning"><div class="score-n">{counts['warning']}</div><div class="score-l">Warning</div></div>
    <div class="score score-note"><div class="score-n">{counts['note']}</div><div class="score-l">Note</div></div>
  </section>
  {ext}

  <section class="findings">
    {cards}
  </section>

  <footer class="page-foot">
    <p>A <b>Critical</b> finding is a job that holds all three of untrusted input (U),
    privilege (P) and egress (E) at once &mdash; the shape behind agentic-CI exploits.
    A <b>Warning</b> is one small edit away from that. Holding at most two is compliant.</p>
    <p>Generated offline by TriDelPhi. No data left this machine.</p>
  </footer>
</div>
</body>
</html>
"""


_CSS = """
:root{
  --bg:#0b0e17; --panel:#131826; --panel2:#1a2032; --line:#28304a;
  --ink:#e6eaf2; --mute:#828fad;
  --crit:#ff4d6d; --warn:#ffb020; --note:#22d3ee; --ok:#3ddc97; --u:#ff4d6d; --p:#ffb020; --e:#22d3ee;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
@media (prefers-color-scheme: light){
  :root{ --bg:#f6f8fc; --panel:#fff; --panel2:#eef2f9; --line:#d9e0ee;
    --ink:#1a2032; --mute:#5a6785; }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.55}
.wrap{max-width:920px;margin:0 auto;padding:32px 20px 80px}
.page-head{border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:22px}
.brand{font-weight:800;font-size:24px;letter-spacing:-.02em}
.tagline{color:var(--mute);font-size:14px;margin-top:2px}
.meta{color:var(--mute);font-family:var(--mono);font-size:12px;margin-top:10px}
.scoreboard{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px}
.score{border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:16px;text-align:center}
.score-n{font-size:34px;font-weight:800;line-height:1}
.score-l{color:var(--mute);font-size:12px;text-transform:uppercase;letter-spacing:.08em;margin-top:6px}
.score-critical .score-n{color:var(--crit)}
.score-warning .score-n{color:var(--warn)}
.score-note .score-n{color:var(--note)}
.ext-note{border:1px solid var(--line);border-radius:10px;background:var(--panel2);
  padding:10px 14px;font-family:var(--mono);font-size:12.5px;color:var(--mute);margin-bottom:20px}
.finding{border:1px solid var(--line);border-left-width:4px;border-radius:12px;background:var(--panel);
  padding:16px 18px;margin-bottom:14px}
.finding.sev-critical{border-left-color:var(--crit)}
.finding.sev-warning{border-left-color:var(--warn)}
.finding.sev-note{border-left-color:var(--note)}
.finding-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.sev-tag{font-family:var(--mono);font-size:11px;font-weight:600;padding:3px 8px;border-radius:6px;
  text-transform:uppercase;letter-spacing:.06em}
.sev-tag-critical{background:rgba(255,77,109,.15);color:var(--crit)}
.sev-tag-warning{background:rgba(255,176,32,.15);color:var(--warn)}
.sev-tag-note{background:rgba(34,211,238,.15);color:var(--note)}
.finding-loc{font-family:var(--mono);font-size:12.5px;color:var(--ink)}
.finding-job{color:var(--mute);font-size:13px}
.finding-caps{margin-left:auto;display:flex;gap:4px}
.pill{font-family:var(--mono);font-size:11px;font-weight:700;width:22px;height:22px;
  display:inline-flex;align-items:center;justify-content:center;border-radius:6px}
.pill-u{background:rgba(255,77,109,.18);color:var(--u)}
.pill-p{background:rgba(255,176,32,.18);color:var(--p)}
.pill-e{background:rgba(34,211,238,.18);color:var(--e)}
.pill-assumed{opacity:.55;border:1px dashed currentColor}
.finding-rule{margin:6px 0}
.rule-id{font-family:var(--mono);font-size:11.5px;color:var(--mute);text-decoration:none}
.finding-msg{margin:8px 0 12px;font-size:14.5px}
.hits{list-style:none;margin:0 0 12px;padding:0;display:grid;gap:6px}
.hits li{display:grid;grid-template-columns:26px 1fr;gap:8px;align-items:start;
  font-size:13px;border-left:2px solid var(--line);padding-left:10px}
.hit-cap{font-family:var(--mono);font-weight:700;font-size:12px}
.hit-u{color:var(--u)} .hit-p{color:var(--p)} .hit-e{color:var(--e)}
.hit-reason{color:var(--ink)}
.hit-loc{grid-column:2;font-family:var(--mono);font-size:11px;color:var(--mute)}
.fix{border:1px solid var(--line);border-radius:10px;background:var(--panel2);padding:12px 14px}
.fix-head{font-weight:700;font-size:13px;margin-bottom:8px;color:var(--ok)}
.fix-body{margin:0;font-family:var(--mono);font-size:12px;line-height:1.6;white-space:pre-wrap;
  color:var(--ink);background:transparent;border:0;padding:0}
.fix-breaks{margin-top:8px;font-size:12px;color:var(--mute)}
.empty{border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:28px;
  text-align:center;color:var(--ok);font-size:15px}
.page-foot{margin-top:28px;padding-top:16px;border-top:1px solid var(--line);color:var(--mute);font-size:12.5px}
.page-foot p{margin:6px 0}
"""
