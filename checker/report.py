"""Turns a list of Results into terminal text or a JSON report."""

import json
from datetime import datetime, timezone

from . import __version__
from .checks import ERROR, FAIL, PASS
from .rules import BENCHMARK_NAME, CIS_REFS_VERIFIED

COLORS = {PASS: "32", FAIL: "31", ERROR: "33"}


def summarize(results):
    return {
        "total": len(results),
        "passed": sum(1 for r in results if r.status == PASS),
        "failed": sum(1 for r in results if r.status == FAIL),
        "errors": sum(1 for r in results if r.status == ERROR),
    }


def _paint(text, status, use_color):
    if not use_color:
        return text
    return f"\x1b[{COLORS[status]}m{text}\x1b[0m"


def format_text(results, target, use_color=False):
    lines = [
        f"compliance-checker {__version__}",
        f"target: {target}",
        f"based loosely on: {BENCHMARK_NAME}",
        "",
    ]
    for r in results:
        label = _paint(f"[{r.status}]", r.status, use_color)
        pad = " " * (7 - len(r.status) - 2)
        lines.append(f"{label}{pad} {r.rule.id:<6} {r.rule.cis_ref:<8} {r.rule.title}")
        lines.append(f"        {r.detail}")
        if r.status == FAIL:
            lines.append(f"        fix: {r.rule.remediation}")
    counts = summarize(results)
    lines.append("")
    lines.append(
        f"{counts['total']} checks: {counts['passed']} passed, "
        f"{counts['failed']} failed, {counts['errors']} errors"
    )
    if not CIS_REFS_VERIFIED:
        lines.append("note: the CIS control numbers have not been checked against the benchmark PDF.")
    lines.append("This is not an official CIS scan and not a compliance audit.")
    return "\n".join(lines)


def build_report(results, target):
    return {
        "tool": "compliance-checker",
        "version": __version__,
        "based_loosely_on": BENCHMARK_NAME,
        "cis_refs_verified": CIS_REFS_VERIFIED,
        "target": str(target),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summarize(results),
        "results": [
            {
                "id": r.rule.id,
                "category": r.rule.category,
                "title": r.rule.title,
                "cis_ref": r.rule.cis_ref,
                "status": r.status,
                "detail": r.detail,
                "remediation": r.rule.remediation if r.status == FAIL else None,
            }
            for r in results
        ],
    }


def write_json(path, report):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
