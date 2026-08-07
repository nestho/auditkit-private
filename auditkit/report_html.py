import html
import json
from pathlib import Path

from .models import ScanResult

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#dc2626",
    "medium": "#ea580c",
    "low": "#ca8a04",
    "info": "#2563eb",
}


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity.lower(), "#374151")


def to_html(result: ScanResult) -> str:
    target = html.escape(result.target.value)
    target_type = html.escape(result.target.target_type)
    started = html.escape(result.started_at)
    finished = html.escape(result.finished_at)

    counts = {}
    for finding in result.findings:
        severity = finding.severity.lower()
        counts[severity] = counts.get(severity, 0) + 1

    summary_parts = []

    for severity in SEVERITY_ORDER:
        if counts.get(severity):
            summary_parts.append(
                f"<span class='badge' style='background:{severity_color(severity)}'>"
                f"{html.escape(severity.upper())}: {counts[severity]}"
                f"</span>"
            )

    for severity, count in counts.items():
        if severity not in SEVERITY_ORDER and count:
            summary_parts.append(
                f"<span class='badge' style='background:{severity_color(severity)}'>"
                f"{html.escape(severity.upper())}: {count}"
                f"</span>"
            )

    summary_html = "".join(summary_parts)

    if not summary_html:
        summary_html = "<span class='muted'>No findings.</span>"

    parts = []

    parts.append("<!doctype html>")
    parts.append("<html lang='en'>")
    parts.append("<head>")
    parts.append("<meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append(f"<title>Security Audit Report - {target}</title>")

    parts.append("<style>")
    parts.append("body { margin:0; font-family:Arial,Helvetica,sans-serif; background:#f8fafc; color:#0f172a; line-height:1.6; }")
    parts.append("main { max-width:950px; margin:0 auto; padding:30px 20px 60px; }")
    parts.append("header { background:#0f172a; color:#fff; padding:30px 20px; }")
    parts.append("header .inner { max-width:950px; margin:0 auto; }")
    parts.append("h1 { margin:0 0 8px; font-size:32px; }")
    parts.append("h2 { margin-top:0; }")
    parts.append(".muted { color:#64748b; }")
    parts.append(".summary { margin-top:15px; display:flex; gap:8px; flex-wrap:wrap; }")
    parts.append(".badge { display:inline-block; color:#fff; border-radius:999px; padding:4px 10px; font-size:13px; }")
    parts.append(".finding { background:#fff; border:1px solid #e2e8f0; border-radius:14px; padding:22px; margin-top:22px; box-shadow:0 1px 3px rgba(15,23,42,.06); }")
    parts.append("code { background:#f1f5f9; padding:2px 6px; border-radius:6px; }")
    parts.append("details { margin-top:12px; }")
    parts.append("pre { background:#0f172a; color:#e2e8f0; padding:14px; border-radius:10px; overflow:auto; }")
    parts.append("footer { margin-top:40px; color:#64748b; font-size:14px; }")
    parts.append("</style>")

    parts.append("</head>")
    parts.append("<body>")

    parts.append("<header>")
    parts.append("<div class='inner'>")
    parts.append("<h1>Security Audit Report</h1>")
    parts.append(f"<div>Target: <strong>{target}</strong> | Type: {target_type}</div>")
    parts.append(f"<div class='muted'>Started: {started} | Finished: {finished}</div>")
    parts.append(f"<div class='summary'>{summary_html}</div>")
    parts.append("</div>")
    parts.append("</header>")

    parts.append("<main>")

    if result.findings:
        for finding in result.findings:
            score = getattr(finding, "score", 0.0)
            impact = getattr(finding, "impact", "")
            likelihood = getattr(finding, "likelihood", "")

            score_meta = [f"Score: {score}"]

            if impact:
                score_meta.append(f"Impact: {impact}")

            if likelihood:
                score_meta.append(f"Likelihood: {likelihood}")

            parts.append("<section class='finding'>")

            parts.append("<h2>")
            parts.append(
                f"<span class='badge' style='background:{severity_color(finding.severity)}'>"
                f"{html.escape(finding.severity.upper())}"
                f"</span> "
            )
            parts.append(f"{html.escape(finding.title)} ")
            parts.append(f"<code>{html.escape(finding.id)}</code>")
            parts.append("</h2>")

            parts.append(
                f"<div class='muted'>Category: {html.escape(finding.category)} | "
                f"{html.escape(' | '.join(score_meta))}</div>"
            )

            parts.append(f"<p>{html.escape(finding.detail)}</p>")

            if finding.recommendation:
                parts.append(
                    f"<p><strong>Recommendation:</strong> "
                    f"{html.escape(finding.recommendation)}</p>"
                )

            parts.append("<details><summary>Evidence</summary>")
            parts.append(
                f"<pre>{html.escape(json.dumps(finding.evidence, indent=2), quote=False)}</pre>"
            )
            parts.append("</details>")

            parts.append("</section>")
    else:
        parts.append("<section class='finding'>")
        parts.append("<h2>No findings</h2>")
        parts.append("<p>No findings were produced by this scan.</p>")
        parts.append("</section>")

    parts.append("<section class='finding'>")
    parts.append("<h2>Raw Evidence</h2>")
    parts.append(
        f"<pre>{html.escape(json.dumps(result.facts, indent=2), quote=False)}</pre>"
    )
    parts.append("</section>")

    parts.append("<footer>")
    parts.append("Generated by AuditKit. Use only for authorized security testing.")
    parts.append("</footer>")

    parts.append("</main>")
    parts.append("</body>")
    parts.append("</html>")

    return "\n".join(parts)


def write_html(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_html(result), encoding="utf-8")
    return path
