import unittest

from auditkit.models import Finding, ScanResult, ScanTarget
from auditkit.scoring import score_finding, score_scan_result, severity_from_score


class TestScoring(unittest.TestCase):
    def test_severity_from_score(self):
        self.assertEqual(severity_from_score(0), "info")
        self.assertEqual(severity_from_score(2.5), "low")
        self.assertEqual(severity_from_score(5), "medium")
        self.assertEqual(severity_from_score(8), "high")
        self.assertEqual(severity_from_score(10), "critical")

    def test_finding_rule(self):
        finding = Finding(
            id="HTTP-CLEARTEXT-SELECTED",
            category="transport-security",
            severity="low",
            title="Clear-text HTTP endpoint is reachable",
            detail="Clear-text HTTP endpoint is reachable.",
        )

        scored = score_finding(finding)

        self.assertEqual(scored.score, 6.5)
        self.assertEqual(scored.severity, "medium")
        self.assertEqual(scored.impact, "medium")
        self.assertEqual(scored.likelihood, "high")

    def test_scan_result_sorted_by_score(self):
        target = ScanTarget(value="example.com", target_type="domain")

        low_finding = Finding(
            id="DNS-100",
            category="asset-inventory",
            severity="info",
            title="Domain resolves",
            detail="Domain resolves.",
        )

        higher_finding = Finding(
            id="HTTP-CLEARTEXT-SELECTED",
            category="transport-security",
            severity="low",
            title="Clear-text HTTP endpoint is reachable",
            detail="Clear-text HTTP endpoint is reachable.",
        )

        result = ScanResult(
            target=target,
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:01+00:00",
            findings=[low_finding, higher_finding],
        )

        scored_result = score_scan_result(result)

        self.assertEqual(
            scored_result.findings[0].id,
            "HTTP-CLEARTEXT-SELECTED",
        )


if __name__ == "__main__":
    unittest.main()
