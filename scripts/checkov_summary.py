#!/usr/bin/env python3
"""Reduce a Checkov JSON report to sorted "CHECK_ID resource" lines, optionally gated.

With --expect FILE the run fails unless the failed checks match FILE exactly, so the
report's evidence cannot drift from what Checkov really says about the Terraform.

Exit codes: 0 match (or no --expect), 1 mismatch, 2 bad input.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def failed_checks(report) -> list[str]:
    """Checkov writes one object per framework, or a list when several frameworks ran."""
    reports = report if isinstance(report, list) else [report]
    lines = set()
    for entry in reports:
        for failure in entry.get("results", {}).get("failed_checks", []):
            lines.add(f"{failure['check_id']} {failure['resource']}")
    return sorted(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=Path, help="checkov -o json output")
    parser.add_argument("--expect", type=Path, help="file of expected lines to compare with")
    args = parser.parse_args(argv)

    try:
        lines = failed_checks(json.loads(args.report.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, KeyError) as err:
        print(f"error: cannot read Checkov report {args.report}: {err}", file=sys.stderr)
        return 2

    if args.expect is None:
        print("\n".join(lines))
        return 0

    try:
        expected_text = args.expect.read_text(encoding="utf-8")
    except OSError as err:
        print(f"error: cannot read expected lines {args.expect}: {err}", file=sys.stderr)
        return 2
    expected = [line for line in expected_text.splitlines() if line]
    missing = sorted(set(expected) - set(lines))
    unexpected = sorted(set(lines) - set(expected))
    for line in missing:
        print(f"expected but not reported: {line}", file=sys.stderr)
    for line in unexpected:
        print(f"reported but not expected: {line}", file=sys.stderr)
    if missing or unexpected:
        return 1
    print(f"Checkov reported the {len(lines)} expected failures.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
