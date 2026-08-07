# AuditKit

AuditKit is an authorized attack-surface audit reporting tool.

It converts simple reconnaissance into a clean security audit report.

> Important: Use AuditKit only on systems you own or systems where you have written permission to test.

---

## MVP Features

- Domain target input.
- Safe passive DNS resolution.
- JSON output.
- Markdown audit report output.
- Simple finding model.
- Clean Python package structure.

---

## Quickstart

~~~bash
cd auditkit
PYTHONPATH=. python3 -m auditkit scan localhost --out reports/localhost.md --format md
~~~

Generate JSON:

~~~bash
PYTHONPATH=. python3 -m auditkit scan localhost --out reports/localhost.json --format json
~~~

---

## Tests

~~~bash
PYTHONPATH=. python3 -m unittest discover -s tests
~~~

---

## Roadmap

### Phase 1: MVP

- Passive DNS audit.
- Markdown report.
- JSON report.

### Phase 2: Paid Report Engine

- Executive HTML report.
- Severity scoring.
- Batch domain input.
- Evidence export.

### Phase 3: Authorized Active Checks

- HTTP header review.
- TLS expiration review.
- Security header review.
- Redirect chain review.

### Phase 4: Local AI Analysis

- Ollama integration.
- Local LLM risk summary.
- Offline operation.

### Phase 5: Commercial Distribution

- Offline licensing.
- Paid binary releases.
- Polar.sh or Gumroad storefront.
- Consulting upsell.

---

## Security Use Policy

AuditKit is intended for authorized security testing only.

Do not use it against targets where you do not have permission.

