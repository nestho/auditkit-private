import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from auditkit.models import Finding, ScanResult, ScanTarget
from auditkit.report import to_markdown, write_json, write_markdown


class TestReport(unittest.TestCase):
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

    def test_to_markdown(self):
        md = to_markdown(self.sample_result())

        self.assertIn("# Security Audit Report", md)
        self.assertIn("Domain resolves", md)
        self.assertIn("~~~json", md)

    def test_write_files(self):
        result = self.sample_result()

        with TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "r.json"
            md_path = Path(tmp) / "r.md"

            write_json(result, json_path)
            write_markdown(result, md_path)

            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())


if __name__ == "__main__":
    unittest.main()
