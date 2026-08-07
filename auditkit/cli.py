import argparse
import sys
from pathlib import Path

from . import __version__
from .report import write_json, write_markdown
from .scanners.passive import scan_domain


def cmd_scan(args):
    result = scan_domain(args.target)
    out = Path(args.out)

    if args.format == "json":
        write_json(result, out)
    else:
        write_markdown(result, out)

    print(f"Report written to {out}")
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
        help="Run a safe, authorized scan against a domain",
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
        choices=["md", "json"],
        default="md",
        help="Report format",
    )
    scan.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
