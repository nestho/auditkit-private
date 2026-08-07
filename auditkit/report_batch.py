import html
import json
from pathlib import Path

from .models import BatchReport
from .report_html import SEVERITY_ORDER, severity_color


def severity_counts(report: BatchReport) -> dict:
    counts = {}

    for finding in report.findings:
        severity = finding.severity.lower()
        counts[severity] = counts.get(severity, 0) + 1

    return counts


def batch_to_markdown(report: BatchReport) -> str:
    lines = []

    lines.append("# Batch Security Audit Report")
    lines.append("")
    lines.append(f"- Targets scanned: {len(report.targets)}")
    lines.append(f"- Started: {report.started_at}")
    lines.append(f"- Finished: {report.finished_at}")
    lines.append("")

    counts = severity_counts(report)

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total findings: {len(report.findings)}")

    for severity in SEVERITY_ORDER:
        if counts.get(severity):
            lines.append(f"- {severity.upper()}: {counts[severity]}")

    for severity, count in counts.items():
        if severity not in SEVERITY_ORDER and count:
            lines.append(f"- {severity.upper()}: {count}")

    lines.append("")

    lines.append("## Targets")
    lines.append("")

    for target in report.targets:
        lines.append(f"- {target}")

    lines.append("")

    lines.append("## Findings")
    lines.append("")

    if not report.findings:
        lines.append("No findings.")

    for finding in report.findings:
        target = ""

        if isinstance(finding.evidence, dict):
            target = finding.evidence.get("target", "")

        lines.append(
            f"### [{finding.severity.upper()}] {finding.title} (`{finding.id}`)"
        )
        lines.append("")
        lines.append(f"- Score: {finding.score}")

        if finding.impact:
            lines.append(f"- Impact: {finding.impact}")

        if finding.likelihood:
            lines.append(f"- Likelihood: {finding.likelihood}")

        if target:
            lines.append(f"- Target: {target}")

        lines.append("")
        lines.append(finding.detail)

        if finding.recommendation:
            lines.append("")
            lines.append(f"**Recommendation:** {finding.recommendation}")

        lines.append("")

    lines.append("## Target Evidence")
    lines.append("")

    for result in report.results:
        lines.append(f"### {result.target.value}")
        lines.append("")
        lines.append("~~~json")
        lines.append(json.dumps(result.facts, indent=2))
        lines.append("~~~")
        lines.append("")

    return "\n".join(lines)


def batch_to_html(report: BatchReport) -> str:
    counts = severity_counts(report)

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
    parts.append("<title>Batch Security Audit Report</title>")

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
    parts.append("<h1>Batch Security Audit Report</h1>")
    parts.append(f"<div>Targets scanned: {len(report.targets)}</div>")
    parts.append(f"<div class='muted'>Started: {html.escape(report.started_at)} | Finished: {html.escape(report.finished_at)}</div>")
    parts.append(f"<div class='summary'>{summary_html}</div>")
    parts.append("</div>")
    parts.append("</header>")

    parts.append("<main>")

    parts.append("<section class='finding'>")
    parts.append("<h2>Targets</h2>")
    parts.append("<ul>")

    for target in report.targets:
        parts.append(f"<li>{html.escape(target)}</li>")

    parts.append("</ul>")
    parts.append("</section>")

    if report.findings:
        for finding in report.findings:
            score = getattr(finding, "score", 0.0)
            impact = getattr(finding, "impact", "")
            likelihood = getattr(finding, "likelihood", "")

            target = ""

            if isinstance(finding.evidence, dict):
                target = finding.evidence.get("target", "")

            score_meta = [f"Score: {score}"]

            if target:
                score_meta.append(f"Target: {target}")

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
        parts.append("<p>No findings were produced by this batch scan.</p>")
        parts.append("</section>")

    for result in report.results:
        parts.append("<section class='finding'>")
        parts.append(f"<h2>{html.escape(result.target.value)}</h2>")
        parts.append(f"<div class='muted'>Findings: {len(result.findings)}</div>")
        parts.append("<details><summary>Evidence</summary>")
        parts.append(
            f"<pre>{html.escape(json.dumps(result.facts, indent=2), quote=False)}</pre>"
        )
        parts.append("</details>")
        parts.append("</section>")

    parts.append("<footer>")
    parts.append("Generated by AuditKit. Use only for authorized security testing.")
    parts.append("</footer>")

    parts.append("</main>")
    parts.append("</body>")
    parts.append("</html>")

    return "\n".join(parts)


def write_batch_markdown(report: BatchReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(batch_to_markdown(report), encoding="utf-8")
    return path


def write_batch_json(report: BatchReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return path


def write_batch_html(report: BatchReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(batch_to_html(report), encoding="utf-8")
    return path
