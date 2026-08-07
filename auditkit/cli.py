import argparse
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .batch import read_targets_file, scan_targets
from .license.offline import (
    generate_keypair,
    issue_license_token,
    verify_license_token,
)
from .report import write_json, write_markdown
from .report_batch import (
    write_batch_html,
    write_batch_json,
    write_batch_markdown,
)
from .report_html import write_html
from .scanners.passive import scan_domain
from .scoring import score_scan_result


def default_batch_out(report_format: str) -> Path:
    extension = {
        "md": "md",
        "json": "json",
        "html": "html",
    }[report_format]

    return Path(f"reports/batch.{extension}")


def cmd_scan(args):
    result = scan_domain(args.target)

    if args.http:
        from .scanners.http_metadata import (
            http_findings_from_metadata,
            scan_http_metadata,
        )

        metadata = scan_http_metadata(args.target)
        result.facts["http"] = metadata
        result.findings.extend(http_findings_from_metadata(metadata))
        result.finished_at = datetime.now(timezone.utc).isoformat()

    result = score_scan_result(result)

    out = Path(args.out)

    if args.format == "json":
        write_json(result, out)
    elif args.format == "html":
        write_html(result, out)
    else:
        write_markdown(result, out)

    print(f"Report written to {out}")
    return 0


def cmd_batch(args):
    targets_path = Path(args.targets_file)

    if not targets_path.exists():
        print(f"Targets file not found: {targets_path}")
        return 1

    targets = read_targets_file(targets_path)

    if not targets:
        print(f"No valid targets found in: {targets_path}")
        return 1

    report = scan_targets(targets, enable_http=args.http)

    if args.out:
        out = Path(args.out)
    else:
        out = default_batch_out(args.format)

    if args.format == "json":
        write_batch_json(report, out)
    elif args.format == "html":
        write_batch_html(report, out)
    else:
        write_batch_markdown(report, out)

    print(f"Batch report written to {out}")
    return 0


def cmd_license_generate_keys(args):
    private_pem, public_pem = generate_keypair()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_path = out_dir / "private_key.pem"
    public_path = out_dir / "public_key.pem"

    private_path.write_text(private_pem, encoding="utf-8")
    public_path.write_text(public_pem, encoding="utf-8")

    os.chmod(private_path, 0o600)

    print(f"Private key written to: {private_path}")
    print(f"Public key written to: {public_path}")
    print("")
    print("Keep the private key secret.")
    print("The public key can be embedded in the product.")

    return 0


def cmd_license_issue(args):
    private_path = Path(args.private_key)

    if not private_path.exists():
        print(f"Private key not found: {private_path}")
        return 1

    private_pem = private_path.read_text(encoding="utf-8")

    now = datetime.now(timezone.utc)

    payload = {
        "product": "auditkit",
        "license_id": args.license_id or str(uuid.uuid4()),
        "customer": args.customer,
        "tier": args.tier.upper(),
        "issued_at": now.timestamp(),
    }

    if args.days > 0:
        expires_at = now + timedelta(days=args.days)
        payload["expires_at"] = expires_at.timestamp()

    features = args.feature

    if not features:
        features = [
            "batch",
            "html",
            "http",
            "scoring",
        ]

    payload["features"] = features

    token = issue_license_token(payload, private_pem)

    print(token)

    return 0


def cmd_license_verify(args):
    public_path = Path(args.public_key)

    if not public_path.exists():
        print(f"Public key not found: {public_path}")
        return 1

    public_pem = public_path.read_text(encoding="utf-8")

    if args.license_token:
        token = args.license_token.strip()
    elif args.license_file:
        license_path = Path(args.license_file)

        if not license_path.exists():
            print(f"License file not found: {license_path}")
            return 1

        token = license_path.read_text(encoding="utf-8").strip()
    else:
        print("Provide --license-token or --license-file")
        return 1

    result = verify_license_token(token, public_pem)

    print(f"Valid: {result.is_valid}")
    print(f"Reason: {result.reason}")
    print(f"Tier: {result.tier}")

    if result.features:
        print(f"Features: {', '.join(result.features)}")
    else:
        print("Features: none")

    return 0 if result.is_valid else 1


def main():
    parser = argparse.ArgumentParser(
        prog="auditkit",
        description="Authorized attack-surface audit toolkit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="Run a safe, authorized scan against one domain",
    )
    scan.add_argument(
        "target",
        help="Domain to scan. Use only domains you own or are authorized to test.",
    )
    scan.add_argument(
        "--out",
        default="reports/report.md",
        help="Output file path",
    )
    scan.add_argument(
        "--format",
        choices=["md", "json", "html"],
        default="md",
        help="Report format",
    )
    scan.add_argument(
        "--http",
        action="store_true",
        help="Enable authorized HTTP metadata checks",
    )
    scan.set_defaults(func=cmd_scan)

    batch = subparsers.add_parser(
        "batch",
        help="Scan multiple domains from a targets file",
    )
    batch.add_argument(
        "targets_file",
        help="Text file with one domain per line",
    )
    batch.add_argument(
        "--out",
        default="",
        help="Output file path",
    )
    batch.add_argument(
        "--format",
        choices=["md", "json", "html"],
        default="html",
        help="Report format",
    )
    batch.add_argument(
        "--http",
        action="store_true",
        help="Enable authorized HTTP metadata checks",
    )
    batch.set_defaults(func=cmd_batch)

    license_parser = subparsers.add_parser(
        "license",
        help="Manage offline licenses",
    )
    license_subparsers = license_parser.add_subparsers(
        dest="license_command",
        required=True,
    )

    generate_keys = license_subparsers.add_parser(
        "generate-keys",
        help="Generate an Ed25519 license signing key pair",
    )
    generate_keys.add_argument(
        "--out-dir",
        default="keys",
        help="Directory where keys will be written",
    )
    generate_keys.set_defaults(func=cmd_license_generate_keys)

    issue = license_subparsers.add_parser(
        "issue",
        help="Issue a signed license token",
    )
    issue.add_argument(
        "--private-key",
        required=True,
        help="Path to private key PEM file",
    )
    issue.add_argument(
        "--tier",
        default="PRO",
        help="License tier",
    )
    issue.add_argument(
        "--customer",
        default="customer",
        help="Customer name",
    )
    issue.add_argument(
        "--license-id",
        default="",
        help="License ID",
    )
    issue.add_argument(
        "--days",
        type=int,
        default=365,
        help="Validity period in days. Use 0 for no expiration.",
    )
    issue.add_argument(
        "--feature",
        action="append",
        help="Feature name to include in the license",
    )
    issue.set_defaults(func=cmd_license_issue)

    verify = license_subparsers.add_parser(
        "verify",
        help="Verify a signed license token",
    )
    verify.add_argument(
        "--public-key",
        required=True,
        help="Path to public key PEM file",
    )
    verify.add_argument(
        "--license-token",
        default="",
        help="License token string",
    )
    verify.add_argument(
        "--license-file",
        default="",
        help="Path to license token file",
    )
    verify.set_defaults(func=cmd_license_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
