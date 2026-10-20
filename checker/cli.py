"""Command line entry point. Run it with: python -m checker"""

import argparse
import os
import sys
from pathlib import Path

from .checks import ERROR, FAIL, SystemReader, run_checks
from .report import build_report, format_text, write_json
from .rules import RULES


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m checker",
        description="Check a Linux system's config files against 12 rules based loosely on a CIS benchmark.",
    )
    parser.add_argument(
        "--target",
        default="/",
        metavar="PATH",
        help="root directory to read from (default: /). Point it at a sample "
        "directory to run without touching the real system.",
    )
    parser.add_argument(
        "--json-out",
        metavar="FILE",
        help="also write the full report to FILE as JSON",
    )
    parser.add_argument(
        "--rules",
        metavar="ID[,ID...]",
        help="only run these rule ids, for example SSH-1,FW-1",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="plain output with no color codes",
    )
    return parser


def exit_code(results):
    # An ERROR means a check could not be done, so the run is incomplete.
    # I let that win over FAIL.
    if any(r.status == ERROR for r in results):
        return 2
    if any(r.status == FAIL for r in results):
        return 1
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)

    target = Path(args.target)
    if not target.is_dir():
        print(f"error: target {args.target} is not a directory", file=sys.stderr)
        return 2

    rule_ids = None
    if args.rules:
        rule_ids = {part.strip().upper() for part in args.rules.split(",") if part.strip()}
        known = [rule.id for rule in RULES]
        unknown = sorted(rule_ids - set(known))
        if not rule_ids or unknown:
            bad = ", ".join(unknown) if unknown else args.rules
            print(f"error: unknown rule id(s): {bad}. Known ids: {', '.join(known)}", file=sys.stderr)
            return 2

    results = run_checks(SystemReader(target), rule_ids)

    use_color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    print(format_text(results, args.target, use_color))

    if args.json_out:
        try:
            write_json(args.json_out, build_report(results, args.target))
        except OSError as exc:
            print(f"error: could not write {args.json_out}: {exc}", file=sys.stderr)
            return 2

    return exit_code(results)
