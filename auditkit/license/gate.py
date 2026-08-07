import os
from pathlib import Path
from typing import Optional

from .offline import LicenseValidationResult, has_feature, verify_license_token

DEFAULT_PUBLIC_PEM = ""

LOCAL_DIR = Path.home() / ".auditkit"
LICENSE_FILE = LOCAL_DIR / "license.key"
PUBLIC_KEY_FILE = LOCAL_DIR / "public_key.pem"

_LICENSE_STATUS = None


class LicenseFeatureError(Exception):
    pass


def reset_license_cache() -> None:
    global _LICENSE_STATUS
    _LICENSE_STATUS = None


def _public_pem_from_env() -> Optional[str]:
    pem = os.environ.get("AUDITKIT_PUBLIC_KEY", "").strip()

    if pem:
        return pem

    pem_file = os.environ.get("AUDITKIT_PUBLIC_KEY_FILE", "").strip()

    if pem_file:
        path = Path(pem_file)

        if path.exists():
            return path.read_text(encoding="utf-8")

    return None


def _license_token_from_env() -> Optional[str]:
    token = os.environ.get("AUDITKIT_LICENSE", "").strip()

    if token:
        return token

    token_file = os.environ.get("AUDITKIT_LICENSE_FILE", "").strip()

    if token_file:
        path = Path(token_file)

        if path.exists():
            return path.read_text(encoding="utf-8").strip()

    return None


def get_public_pem() -> Optional[str]:
    env_pem = _public_pem_from_env()

    if env_pem:
        return env_pem

    if DEFAULT_PUBLIC_PEM:
        return DEFAULT_PUBLIC_PEM

    if PUBLIC_KEY_FILE.exists():
        return PUBLIC_KEY_FILE.read_text(encoding="utf-8")

    return None


def get_license_token() -> Optional[str]:
    env_token = _license_token_from_env()

    if env_token:
        return env_token

    if LICENSE_FILE.exists():
        return LICENSE_FILE.read_text(encoding="utf-8").strip()

    return None


def get_license_status(force: bool = False) -> LicenseValidationResult:
    global _LICENSE_STATUS

    if _LICENSE_STATUS is not None and not force:
        return _LICENSE_STATUS

    public_pem = get_public_pem()

    if not public_pem:
        _LICENSE_STATUS = LicenseValidationResult(
            is_valid=False,
            reason="No license public key configured. Running in Community mode.",
            tier="COMMUNITY",
        )
        return _LICENSE_STATUS

    token = get_license_token()

    if not token:
        _LICENSE_STATUS = LicenseValidationResult(
            is_valid=False,
            reason="No license found. Running in Community mode.",
            tier="COMMUNITY",
        )
        return _LICENSE_STATUS

    _LICENSE_STATUS = verify_license_token(token, public_pem)

    return _LICENSE_STATUS


def can_use_feature(feature: str) -> bool:
    result = get_license_status()
    return has_feature(result, feature)


def ensure_feature(feature: str) -> None:
    if not can_use_feature(feature):
        raise LicenseFeatureError(
            f"Feature '{feature}' requires a valid AuditKit license. "
            f"Activate with: python3 -m auditkit license activate "
            f"--license-file <license-file> --public-key <public-key-file>"
        )
