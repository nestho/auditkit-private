import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from auditkit.models import Finding, ScanResult, ScanTarget
from auditkit.report_html import to_html, write_html


class TestReportHtml(unittest.TestCase):
    def sample_result(self):
        target = ScanTarget(value="example.com", target_type="domain")

        finding = Finding(
            id="DNS-100",
            category="asset-inventory",
            severity="info",
            title="Domain resolves",
            detail="Domain example.com resolves to 1 IP address(es).",
            evidence={"dns": {"resolved": True, "ips": ["127.0.0.1"]}},
            recommendation="Confirm IP addresses.",
        )

        return ScanResult(
            target=target,
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:01+00:00",
            facts={"dns": {"resolved": True, "ips": ["127.0.0.1"]}},
            findings=[finding],
        )

    def test_to_html(self):
        page = to_html(self.sample_result())

        self.assertIn("<!doctype html>", page)
        self.assertIn("Security Audit Report", page)
        self.assertIn("Domain resolves", page)
        self.assertIn("INFO", page)

    def test_write_html(self):
        result = self.sample_result()

        with TemporaryDirectory() as tmp:
            html_path = Path(tmp) / "report.html"

            write_html(result, html_path)

            self.assertTrue(html_path.exists())

            content = html_path.read_text(encoding="utf-8")
            self.assertIn("<!doctype html>", content)


if __name__ == "__main__":
    unittest.main()
