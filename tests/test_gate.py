import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from auditkit.license import gate
from auditkit.license.offline import generate_keypair, issue_license_token


class TestGate(unittest.TestCase):
    def setUp(self):
        self.private_pem, self.public_pem = generate_keypair()

        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

        self.public_path = Path(self._tmp.name) / "public_key.pem"
        self.public_path.write_text(self.public_pem, encoding="utf-8")

        self.license_path = Path(self._tmp.name) / "license.key"

        self._old_env = {}

        for key in [
            "AUDITKIT_PUBLIC_KEY",
            "AUDITKIT_PUBLIC_KEY_FILE",
            "AUDITKIT_LICENSE",
            "AUDITKIT_LICENSE_FILE",
        ]:
            self._old_env[key] = os.environ.get(key)

        gate.reset_license_cache()

        os.environ["AUDITKIT_PUBLIC_KEY_FILE"] = str(self.public_path)

    def tearDown(self):
        for key, value in self._old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

        gate.reset_license_cache()

    def test_valid_license_feature(self):
        future = datetime.now(timezone.utc) + timedelta(days=30)

        payload = {
            "product": "auditkit",
            "license_id": "TEST-GATE-001",
            "customer": "Test Customer",
            "tier": "PRO",
            "expires_at": future.timestamp(),
            "features": ["html", "batch"],
        }

        token = issue_license_token(payload, self.private_pem)
        self.license_path.write_text(token, encoding="utf-8")

        os.environ["AUDITKIT_LICENSE_FILE"] = str(self.license_path)

        status = gate.get_license_status(force=True)

        self.assertTrue(status.is_valid)
        self.assertTrue(gate.can_use_feature("html"))
        self.assertTrue(gate.can_use_feature("batch"))
        self.assertFalse(gate.can_use_feature("http"))

    def test_invalid_license_token(self):
        self.license_path.write_text("invalid.token", encoding="utf-8")

        os.environ["AUDITKIT_LICENSE_FILE"] = str(self.license_path)

        status = gate.get_license_status(force=True)

        self.assertFalse(status.is_valid)
        self.assertFalse(gate.can_use_feature("html"))

    def test_missing_license(self):
        os.environ.pop("AUDITKIT_LICENSE_FILE", None)

        status = gate.get_license_status(force=True)

        self.assertFalse(status.is_valid)
        self.assertEqual(status.tier, "COMMUNITY")
        self.assertFalse(gate.can_use_feature("batch"))


if __name__ == "__main__":
    unittest.main()
