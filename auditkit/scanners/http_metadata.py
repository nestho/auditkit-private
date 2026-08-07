import urllib.request
from typing import Dict, List
from urllib.error import HTTPError, URLError

from ..models import Finding

USER_AGENT = "AuditKit/0.1 (authorized-security-testing)"
TIMEOUT_SECONDS = 8

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


def fetch_http_metadata(url: str) -> Dict:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            headers = dict(response.headers.items())

            return {
                "requested_url": url,
                "final_url": response.url,
                "ok": True,
                "status": response.status,
                "reason": getattr(response, "reason", ""),
                "headers": headers,
                "error": None,
            }

    except HTTPError as exc:
        headers = dict(exc.headers.items()) if exc.headers else {}

        return {
            "requested_url": url,
            "final_url": getattr(exc, "url", url),
            "ok": False,
            "status": exc.code,
            "reason": str(exc.reason),
            "headers": headers,
            "error": f"HTTP {exc.code}",
        }

    except URLError as exc:
        return {
            "requested_url": url,
            "final_url": url,
            "ok": False,
            "status": None,
            "reason": str(exc.reason),
            "headers": {},
            "error": str(exc.reason),
        }

    except Exception as exc:
        return {
            "requested_url": url,
            "final_url": url,
            "ok": False,
            "status": None,
            "reason": str(exc),
            "headers": {},
            "error": str(exc),
        }


def scan_http_metadata(domain: str) -> Dict:
    metadata = {
        "https": fetch_http_metadata(f"https://{domain}/"),
        "http": None,
        "chosen_scheme": None,
    }

    if metadata["https"].get("ok"):
        metadata["chosen_scheme"] = "https"
    else:
        metadata["http"] = fetch_http_metadata(f"http://{domain}/")

        if metadata["http"].get("ok"):
            metadata["chosen_scheme"] = "http"

    return metadata


def analyze_headers(headers: Dict[str, str], scheme: str) -> List[Finding]:
    findings = []

    lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}

    missing = [
        header
        for header in SECURITY_HEADERS
        if header not in lower_headers
    ]

    if missing:
        findings.append(
            Finding(
                id=f"HTTP-{scheme.upper()}-MISSING-SECURITY-HEADERS",
                category="http-headers",
                severity="low",
                title=f"Missing security headers on {scheme.upper()}",
                detail=f"The {scheme.upper()} response is missing recommended security headers.",
                evidence={
                    "scheme": scheme,
                    "missing_security_headers": missing,
                },
                recommendation=(
                    "Add HSTS, CSP, X-Content-Type-Options, X-Frame-Options, "
                    "Referrer-Policy, and Permissions-Policy where appropriate."
                ),
            )
        )

    if "server" in lower_headers:
        findings.append(
            Finding(
                id=f"HTTP-{scheme.upper()}-SERVER-HEADER",
                category="http-headers",
                severity="info",
                title=f"Server header exposed on {scheme.upper()}",
                detail="The HTTP Server header reveals server software information.",
                evidence={
                    "scheme": scheme,
                    "server": lower_headers["server"],
                },
                recommendation=(
                    "Consider removing or minimizing Server header information."
                ),
            )
        )

    return findings


def http_findings_from_metadata(metadata: Dict) -> List[Finding]:
    findings = []

    for scheme in ["https", "http"]:
        data = metadata.get(scheme)

        if not data:
            continue

        if data.get("ok"):
            findings.append(
                Finding(
                    id=f"HTTP-{scheme.upper()}-REACHABLE",
                    category="http-metadata",
                    severity="info",
                    title=f"{scheme.upper()} endpoint reachable",
                    detail=(
                        f"{scheme.upper()} endpoint responded with status "
                        f"{data.get('status')}."
                    ),
                    evidence={
                        "requested_url": data.get("requested_url"),
                        "final_url": data.get("final_url"),
                        "status": data.get("status"),
                        "reason": data.get("reason"),
                    },
                    recommendation="Confirm this endpoint is expected and authorized.",
                )
            )

        elif data.get("status") is not None:
            findings.append(
                Finding(
                    id=f"HTTP-{scheme.upper()}-HTTP-ERROR",
                    category="http-metadata",
                    severity="info",
                    title=f"{scheme.upper()} returned HTTP {data.get('status')}",
                    detail=(
                        f"{scheme.upper()} endpoint returned HTTP status "
                        f"{data.get('status')}."
                    ),
                    evidence={
                        "requested_url": data.get("requested_url"),
                        "final_url": data.get("final_url"),
                        "status": data.get("status"),
                        "reason": data.get("reason"),
                        "error": data.get("error"),
                    },
                    recommendation="Review whether this response is expected.",
                )
            )

        else:
            findings.append(
                Finding(
                    id=f"HTTP-{scheme.upper()}-UNREACHABLE",
                    category="http-metadata",
                    severity="info",
                    title=f"{scheme.upper()} endpoint not reachable",
                    detail=f"{scheme.upper()} endpoint could not be reached.",
                    evidence={
                        "requested_url": data.get("requested_url"),
                        "error": data.get("error"),
                        "reason": data.get("reason"),
                    },
                    recommendation=(
                        "If this service should be reachable, investigate DNS, "
                        "firewall, TLS, or web server configuration."
                    ),
                )
            )

        if data.get("ok") or data.get("status") is not None:
            findings.extend(
                analyze_headers(
                    data.get("headers", {}),
                    scheme,
                )
            )

    if metadata.get("chosen_scheme") == "http":
        findings.append(
            Finding(
                id="HTTP-CLEARTEXT-SELECTED",
                category="transport-security",
                severity="low",
                title="Clear-text HTTP endpoint is reachable",
                detail=(
                    "The target appears to be reachable over clear-text HTTP "
                    "after HTTPS was not usable."
                ),
                evidence={
                    "chosen_scheme": metadata.get("chosen_scheme"),
                },
                recommendation=(
                    "Prefer HTTPS everywhere. Redirect HTTP to HTTPS and enable "
                    "HSTS when appropriate."
                ),
            )
        )

    return findings
