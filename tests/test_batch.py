import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from auditkit.batch import annotate_result_with_target, read_targets_file
from auditkit.models import BatchReport, Finding, ScanResult, ScanTarget
from auditkit.report_batch import batch_to_html, batch_to_markdown


class TestBatch(unittest.TestCase):
    def sample_batch(self):
        target = ScanTarget(value="example.com", target_type="domain")

        finding = Finding(
            id="example.com:DNS-100",
            category="asset-inventory",
            severity="info",
            title="[example.com] Domain resolves",
            detail="Domain example.com resolves to 1 IP address(es).",
            evidence={"target": "example.com"},
            recommendation="Confirm IP addresses.",
            impact="none",
            likelihood="none",
            score=0.0,
        )

        result = ScanResult(
            target=target,
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:01+00:00",
            facts={"dns": {"resolved": True, "ips": ["127.0.0.1"]}},
            findings=[finding],
        )

        return BatchReport(
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:02+00:00",
            targets=["example.com"],
            results=[result],
            findings=[finding],
            facts={"example.com": result.facts},
        )

    def test_read_targets_file(self):
        content = """
# comment

example.com
  test.com  
example.com
"""

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.txt"
            path.write_text(content, encoding="utf-8")

            targets = read_targets_file(path)

            self.assertEqual(targets, ["example.com", "test.com"])

    def test_annotate_result_with_target(self):
        target = ScanTarget(value="example.com", target_type="domain")

        finding = Finding(
            id="DNS-100",
            category="asset-inventory",
            severity="info",
            title="Domain resolves",
            detail="Domain resolves.",
        )

        result = ScanResult(
            target=target,
            started_at="2026-01-01T00:00:00+00:00",
            findings=[finding],
        )

        annotated = annotate_result_with_target(result)

        self.assertEqual(
            annotated.findings[0].id,
            "example.com:DNS-100",
        )
        self.assertIn("example.com", annotated.findings[0].title)
        self.assertEqual(
            annotated.findings[0].evidence["target"],
            "example.com",
        )

    def test_batch_markdown(self):
        report = self.sample_batch()
        markdown = batch_to_markdown(report)

        self.assertIn("# Batch Security Audit Report", markdown)
        self.assertIn("example.com", markdown)
        self.assertIn("Domain resolves", markdown)

    def test_batch_html(self):
        report = self.sample_batch()
        page = batch_to_html(report)

        self.assertIn("<!doctype html>", page)
        self.assertIn("Batch Security Audit Report", page)
        self.assertIn("example.com", page)


if __name__ == "__main__":
    unittest.main()
