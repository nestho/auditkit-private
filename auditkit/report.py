import json
from pathlib import Path

from .models import ScanResult


def to_markdown(result: ScanResult) -> str:
    lines = []

    lines.append(f"# Security Audit Report: {result.target.value}")
    lines.append("")
    lines.append(f"- Target type: {result.target.target_type}")
    lines.append(f"- Started: {result.started_at}")
    lines.append(f"- Finished: {result.finished_at}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    if not result.findings:
        lines.append("No findings.")

    for finding in result.findings:
        lines.append(
            f"### [{finding.severity.upper()}] {finding.title} (`{finding.id}`)"
        )
        lines.append("")
        lines.append(finding.detail)

        if finding.recommendation:
            lines.append("")
            lines.append(f"**Recommendation:** {finding.recommendation}")

        lines.append("")

    lines.append("## Evidence")
    lines.append("")
    lines.append("~~~json")
    lines.append(json.dumps(result.facts, indent=2))
    lines.append("~~~")
    lines.append("")

    return "\n".join(lines)


def write_markdown(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_markdown(result), encoding="utf-8")
    return path


def write_json(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return path
