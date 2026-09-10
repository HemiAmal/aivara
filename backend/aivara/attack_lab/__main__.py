"""Command-line interface for AIVARA Attack Demonstration Lab (Phase 4.15).

Usage:
  python -m aivara.attack_lab list
  python -m aivara.attack_lab run ATTACK-01
  python -m aivara.attack_lab run --all
  python -m aivara.attack_lab run ATTACK-01 --json
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from aivara.attack_lab.runner import AttackLabRunner


def _format_scenario_table(scenarios: List) -> str:
    lines = []
    lines.append(f"{'ID':<12} {'CATEGORY':<16} {'NAME':<38} {'TARGET':<30}")
    lines.append("-" * 98)
    for sc in scenarios:
        lines.append(f"{sc.attack_id:<12} {sc.category.value:<16} {sc.attack_name:<38} {sc.target:<30}")
    return "\n".join(lines)


def _format_result_box(res) -> str:
    lines = []
    status_sym = "[DETECTED]" if res.detected else "[MISSED]"
    lines.append("=" * 78)
    lines.append(f"  AIVARA ATTACK LAB :: {res.attack_id} — {res.attack_name}")
    lines.append("=" * 78)
    lines.append(f"  Result:             {status_sym}")
    lines.append(f"  Target Asset:       {res.target_asset}")
    lines.append(f"  Attack Technique:   {res.attack_technique}")
    lines.append(f"  Verification:       {res.verification_status}")
    lines.append(f"  Failure Codes:      {', '.join(res.failure_codes) if res.failure_codes else 'None'}")
    lines.append(f"  Cleanup / Restore:  {res.cleanup_status}")
    if res.sub_results:
        lines.append("\n  Sub-Demonstrations:")
        for sr in res.sub_results:
            sr_sym = "[PASS]" if sr.detected else "[FAIL]"
            lines.append(f"    {sr_sym} {sr.sub_id:<18} {sr.name:<45} -> {sr.verification_status}")
    lines.append("=" * 78)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        prog="python -m aivara.attack_lab",
        description="AIVARA Attack & Tampering Demonstration Lab (Phase 4.15)",
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Command: list
    list_parser = subparsers.add_parser("list", help="List all registered attack demonstration scenarios")
    list_parser.add_argument("--json", action="store_true", help="Output raw JSON array")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Run attack demonstration(s)")
    run_parser.add_argument("attack_id", nargs="?", default=None, help="Scenario ID (e.g. ATTACK-01, ATTACK-002, 1)")
    run_parser.add_argument("--all", action="store_true", help="Run all attack scenarios")
    run_parser.add_argument("--json", action="store_true", help="Output raw JSON report")
    run_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")

    args = parser.parse_args()
    runner = AttackLabRunner()

    if args.command == "list":
        scenarios = runner.list_scenarios()
        if args.json:
            print(json.dumps([sc.model_dump() for sc in scenarios], indent=2))
        else:
            print(f"\nAIVARA Attack Lab — Registered Scenarios ({len(scenarios)} total):\n")
            print(_format_scenario_table(scenarios))
            print()
        sys.exit(0)

    elif args.command == "run":
        if args.all or args.attack_id in ("--all", "all", "ALL"):
            summary = runner.run_all()
            if args.json:
                print(summary.model_dump_json(indent=2))
            else:
                print(f"\nAIVARA Attack Lab — Full Demonstration Run ({summary.total_scenarios} scenarios):\n")
                for r in summary.results:
                    print(_format_result_box(r))
                    print()
                print(f"Summary: {summary.scenarios_detected}/{summary.total_scenarios} attacks successfully detected.")
                print(f"All Attacks Detected: {summary.all_detected}\n")
            sys.exit(0 if summary.all_detected else 1)

        elif args.attack_id:
            try:
                res = runner.run_scenario(args.attack_id)
            except KeyError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(2)

            if args.json:
                print(res.model_dump_json(indent=2))
            else:
                print()
                print(_format_result_box(res))
                print()
            sys.exit(0 if res.detected else 1)
        else:
            run_parser.print_help()
            sys.exit(2)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
