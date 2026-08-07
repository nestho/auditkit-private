import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass
class LicenseValidationResult:
    is_valid: bool
    reason: str
    tier: str = "COMMUNITY"
    features: List[str] = field(default_factory=list)
    payload: Dict = field(default_factory=dict)


def generate_keypair():
    private_key = Ed25519PrivateKey.generate()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def load_private_key(pem: str):
    return serialization.load_pem_private_key(
        pem.encode("utf-8"),
        password=None,
    )


def load_public_key(pem: str):
    return serialization.load_pem_public_key(
        pem.encode("utf-8"),
    )


def canonical_payload(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def issue_license_token(payload: dict, private_pem: str) -> str:
    private_key = load_private_key(private_pem)

    payload_bytes = canonical_payload(payload)
    signature = private_key.sign(payload_bytes)

    return f"{_b64_encode(payload_bytes)}.{_b64_encode(signature)}"


def verify_license_token(token: str, public_pem: str) -> LicenseValidationResult:
    token = token.strip()

    if "." not in token:
        return LicenseValidationResult(
            is_valid=False,
            reason="Malformed license token.",
        )

    payload_b64, signature_b64 = token.split(".", 1)

    try:
        payload_bytes = _b64_decode(payload_b64)
        signature = _b64_decode(signature_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return LicenseValidationResult(
            is_valid=False,
            reason="License token could not be decoded.",
        )

    try:
        public_key = load_public_key(public_pem)
        public_key.verify(signature, canonical_payload(payload))
    except InvalidSignature:
        return LicenseValidationResult(
            is_valid=False,
            reason="Cryptographic signature mismatch.",
        )
    except Exception:
        return LicenseValidationResult(
            is_valid=False,
            reason="License public key is invalid.",
        )

    expires_at = payload.get("expires_at")

    if expires_at is not None:
        try:
            expires_timestamp = float(expires_at)
        except (TypeError, ValueError):
            return LicenseValidationResult(
                is_valid=False,
                reason="License expiration timestamp is invalid.",
            )

        now_timestamp = datetime.now(timezone.utc).timestamp()

        if now_timestamp > expires_timestamp:
            return LicenseValidationResult(
                is_valid=False,
                reason="License expired.",
                payload=payload,
            )

    tier = str(payload.get("tier", "PRO")).upper()

    features = payload.get("features", [])

    if not isinstance(features, list):
        features = []

    features = [str(feature) for feature in features]

    return LicenseValidationResult(
        is_valid=True,
        reason="License is valid.",
        tier=tier,
        features=features,
        payload=payload,
    )


def has_feature(result: LicenseValidationResult, feature: str) -> bool:
    return result.is_valid and feature in result.features
