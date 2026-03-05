"""Command-line interface for AxiomTrace."""

from __future__ import annotations

import argparse
import ctypes
import logging
import sys
from pathlib import Path

from axiomtrace import __version__
from axiomtrace.core.engine import AxiomEngine
from axiomtrace.core.registry import PROFILES
from axiomtrace.output.report import to_json
from axiomtrace.utils.logging import setup_logging

BANNER = rf"""
    _          _                 _____
   / \   __  _(_) ___  _ __ ___|_   _| __ __ _  ___ ___
  / _ \  \ \/ / |/ _ \| '_ ` _ \ | || '__/ _` |/ __/ _ \
 / ___ \  >  <| | (_) | | | | | || || | | (_| | (_|  __/
/_/   \_\/_/\_\_|\___/|_| |_| |_||_||_|  \__,_|\___\___|
                                              v{__version__}
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="axiomtrace",
        description="AxiomTrace - Forensic System Integrity Verification",
    )
    parser.add_argument(
        "--version", action="version", version=f"AxiomTrace {__version__}"
    )
    parser.add_argument(
        "-p",
        "--profile",
        choices=list(PROFILES.keys()),
        default="full",
        help="Scan profile to run (default: full)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write JSON report to file instead of stdout",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress banner and status output"
    )
    parser.add_argument(
        "--list-collectors",
        action="store_true",
        help="List available collectors and exit",
    )
    return parser


def list_collectors() -> None:
    for profile_name, collector_classes in PROFILES.items():
        print(f"\n[{profile_name}]")
        for cls in collector_classes:
            instance = cls()
            print(f"  {instance.name:<35} {instance.description}")


def _is_admin() -> bool:
    """Check if the process is running with administrator privileges."""
    try:
        return ctypes.windll.kernel32.IsUserAnAdmin() != 0  # type: ignore[union-attr]
    except AttributeError:
        # Non-Windows fallback: check for root (uid 0)
        import os
        return os.getuid() == 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_collectors:
        list_collectors()
        return 0

    if not _is_admin():
        print("ERROR: AxiomTrace requires administrator privileges.")
        print("Please re-run this program as Administrator.")
        return 1

    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)

    if not args.quiet:
        print(BANNER)

    # Build engine
    engine = AxiomEngine()
    collector_classes = PROFILES[args.profile]

    for cls in collector_classes:
        engine.register_collector(cls())

    if not args.quiet:
        print(f"Profile: {args.profile} ({len(collector_classes)} collectors)")
        print("Running scan...\n")

    # Run
    report = engine.run()

    # Output
    json_report = to_json(report)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json_report, encoding="utf-8")
        if not args.quiet:
            print(f"\nReport written to {args.output}")
    else:
        print(json_report)

    # Summary
    if not args.quiet:
        n_findings = len(report.results)
        n_errors = len(report.errors)
        print(f"\nScan complete: {n_findings} finding(s), {n_errors} error(s)")

    return 1 if report.results else 0


if __name__ == "__main__":
    sys.exit(main())
