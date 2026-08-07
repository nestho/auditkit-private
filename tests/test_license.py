import base64
import json
import unittest
from datetime import datetime, timedelta, timezone

from auditkit.license.offline import (
    canonical_payload,
    generate_keypair,
    issue_license_token,
    verify_license_token,
)


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


class TestOfflineLicense(unittest.TestCase):
    def setUp(self):
        self.private_pem, self.public_pem = generate_keypair()

    def test_valid_license(self):
        future = datetime.now(timezone.utc) + timedelta(days=30)

        payload = {
            "product": "auditkit",
            "license_id": "TEST-001",
            "customer": "Test Customer",
            "tier": "PRO",
            "expires_at": future.timestamp(),
            "features": ["batch", "html"],
        }

        token = issue_license_token(payload, self.private_pem)
        result = verify_license_token(token, self.public_pem)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.tier, "PRO")
        self.assertIn("batch", result.features)
        self.assertIn("html", result.features)

    def test_expired_license(self):
        past = datetime.now(timezone.utc) - timedelta(days=1)

        payload = {
            "product": "auditkit",
            "license_id": "TEST-002",
            "customer": "Test Customer",
            "tier": "PRO",
            "expires_at": past.timestamp(),
        }

        token = issue_license_token(payload, self.private_pem)
        result = verify_license_token(token, self.public_pem)

        self.assertFalse(result.is_valid)
        self.assertIn("expired", result.reason.lower())

    def test_tampered_license(self):
        payload = {
            "product": "auditkit",
            "license_id": "TEST-003",
            "customer": "Test Customer",
            "tier": "PRO",
        }

        token = issue_license_token(payload, self.private_pem)
        payload_b64, signature_b64 = token.split(".", 1)

        decoded_payload = json.loads(_b64_decode(payload_b64).decode("utf-8"))
        decoded_payload["tier"] = "ENTERPRISE"

        tampered_payload_b64 = _b64_encode(canonical_payload(decoded_payload))
        tampered_token = f"{tampered_payload_b64}.{signature_b64}"

        result = verify_license_token(tampered_token, self.public_pem)

        self.assertFalse(result.is_valid)
        self.assertIn("signature", result.reason.lower())


if __name__ == "__main__":
    unittest.main()
