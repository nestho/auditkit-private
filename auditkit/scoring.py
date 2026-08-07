from .models import Finding, ScanResult

FINDING_RULES = {
    "DNS-100": {
        "impact": "none",
        "likelihood": "none",
        "score": 0.0,
    },
    "DNS-001": {
        "impact": "low",
        "likelihood": "medium",
        "score": 3.0,
    },
    "HTTP-HTTPS-REACHABLE": {
        "impact": "none",
        "likelihood": "none",
        "score": 0.0,
    },
    "HTTP-HTTP-REACHABLE": {
        "impact": "low",
        "likelihood": "medium",
        "score": 2.0,
    },
    "HTTP-HTTPS-HTTP-ERROR": {
        "impact": "low",
        "likelihood": "low",
        "score": 2.0,
    },
    "HTTP-HTTP-HTTP-ERROR": {
        "impact": "low",
        "likelihood": "low",
        "score": 2.5,
    },
    "HTTP-HTTPS-UNREACHABLE": {
        "impact": "low",
        "likelihood": "low",
        "score": 2.0,
    },
    "HTTP-HTTP-UNREACHABLE": {
        "impact": "none",
        "likelihood": "none",
        "score": 0.0,
    },
    "HTTP-HTTPS-MISSING-SECURITY-HEADERS": {
        "impact": "low",
        "likelihood": "high",
        "score": 4.0,
    },
    "HTTP-HTTP-MISSING-SECURITY-HEADERS": {
        "impact": "low",
        "likelihood": "high",
        "score": 4.5,
    },
    "HTTP-HTTPS-SERVER-HEADER": {
        "impact": "low",
        "likelihood": "low",
        "score": 1.0,
    },
    "HTTP-HTTP-SERVER-HEADER": {
        "impact": "low",
        "likelihood": "low",
        "score": 1.5,
    },
    "HTTP-CLEARTEXT-SELECTED": {
        "impact": "medium",
        "likelihood": "high",
        "score": 6.5,
    },
}

CATEGORY_RULES = {
    "transport-security": {
        "impact": "medium",
        "likelihood": "high",
        "score": 6.5,
    },
    "http-headers": {
        "impact": "low",
        "likelihood": "high",
        "score": 4.0,
    },
    "http-metadata": {
        "impact": "low",
        "likelihood": "low",
        "score": 0.0,
    },
    "availability": {
        "impact": "low",
        "likelihood": "medium",
        "score": 3.0,
    },
    "asset-inventory": {
        "impact": "low",
        "likelihood": "low",
        "score": 0.0,
    },
}

SEVERITY_BASE_SCORE = {
    "info": 0.0,
    "low": 3.0,
    "medium": 5.5,
    "high": 7.5,
    "critical": 9.5,
}


def severity_from_score(score: float) -> str:
    score = float(score)

    if score <= 0:
        return "info"

    if score < 4:
        return "low"

    if score < 7:
        return "medium"

    if score < 9:
        return "high"

    return "critical"


def score_finding(finding: Finding) -> Finding:
    rule = FINDING_RULES.get(finding.id)

    if not rule:
        rule = CATEGORY_RULES.get(finding.category)

    if rule:
        score = float(rule.get("score", 0.0))
        finding.impact = str(rule.get("impact", finding.impact or "low"))
        finding.likelihood = str(rule.get("likelihood", finding.likelihood or "low"))
    else:
        score = SEVERITY_BASE_SCORE.get(finding.severity.lower(), 0.0)
        finding.impact = finding.impact or "low"
        finding.likelihood = finding.likelihood or "low"

    finding.score = round(score, 1)
    finding.severity = severity_from_score(finding.score)

    return finding


def score_scan_result(result: ScanResult) -> ScanResult:
    result.findings = [score_finding(finding) for finding in result.findings]
    result.findings.sort(key=lambda finding: finding.score, reverse=True)
    return result
