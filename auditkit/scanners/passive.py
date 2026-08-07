import socket
from datetime import datetime, timezone
from typing import Dict

from ..models import Finding, ScanResult, ScanTarget


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolve_domain(domain: str) -> Dict:
    try:
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror as exc:
        return {
            "resolved": False,
            "error": str(exc),
            "ips": [],
            "address_families": [],
        }

    ips = sorted({info[4][0] for info in infos})
    families = sorted({info[0].name for info in infos})

    return {
        "resolved": True,
        "ips": ips,
        "address_families": families,
    }


def scan_domain(domain: str) -> ScanResult:
    target = ScanTarget(value=domain, target_type="domain")
    result = ScanResult(target=target, started_at=utcnow())

    dns = resolve_domain(domain)
    result.facts["dns"] = dns

    if not dns.get("resolved"):
        result.findings.append(
            Finding(
                id="DNS-001",
                category="availability",
                severity="low",
                title="Domain does not resolve",
                detail=f"Domain {domain} did not resolve using local DNS.",
                evidence=dns,
                recommendation=(
                    "If this target belongs to you, verify DNS configuration. "
                    "If this was a typo, correct the target name."
                ),
            )
        )
    else:
        result.findings.append(
            Finding(
                id="DNS-100",
                category="asset-inventory",
                severity="info",
                title="Domain resolves",
                detail=f"Domain {domain} resolves to {len(dns.get('ips', []))} IP address(es).",
                evidence=dns,
                recommendation=(
                    "Confirm that all resolved IP addresses are expected, known, "
                    "and owned by the organization."
                ),
            )
        )

    result.finished_at = utcnow()
    return result
