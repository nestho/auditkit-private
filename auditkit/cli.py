import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .batch import read_targets_file, scan_targets
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

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
