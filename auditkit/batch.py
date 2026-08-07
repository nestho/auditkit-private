from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .models import BatchReport, ScanResult
from .scanners.passive import scan_domain
from .scoring import score_scan_result


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_targets_file(path: Path) -> List[str]:
    text = Path(path).read_text(encoding="utf-8")

    targets = []
    seen = set()

    for line in text.splitlines():
        target = line.strip()

        if not target:
            continue

        if target.startswith("#"):
            continue

        if target in seen:
            continue

        seen.add(target)
        targets.append(target)

    return targets


def annotate_result_with_target(result: ScanResult) -> ScanResult:
    target_value = result.target.value

    for finding in result.findings:
        finding.evidence["target"] = target_value

        if target_value not in finding.title:
            finding.title = f"[{target_value}] {finding.title}"

        if not finding.id.startswith(f"{target_value}:"):
            finding.id = f"{target_value}:{finding.id}"

    return result


def scan_targets(targets: List[str], enable_http: bool = False) -> BatchReport:
    report = BatchReport(
        started_at=utcnow(),
        targets=list(targets),
    )

    for target in targets:
        result = scan_domain(target)

        if enable_http:
            from .scanners.http_metadata import (
                http_findings_from_metadata,
                scan_http_metadata,
            )

            metadata = scan_http_metadata(target)
            result.facts["http"] = metadata
            result.findings.extend(http_findings_from_metadata(metadata))

        result = score_scan_result(result)
        result.finished_at = utcnow()
        result = annotate_result_with_target(result)

        report.results.append(result)
        report.findings.extend(result.findings)
        report.facts[target] = result.facts

    report.findings.sort(key=lambda finding: finding.score, reverse=True)
    report.finished_at = utcnow()

    return report
