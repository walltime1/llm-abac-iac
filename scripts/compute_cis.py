#!/usr/bin/env python3
"""Wilson 95% confidence intervals for the per-model metrics in the paper.

Reads export_data/01_scores/eval_results.csv (the frozen evaluation
artefact) and prints, per model: encode rate, intent accuracy,
attack-chain accuracy, and CVE recall, each with a Wilson score interval.
Also prints the F6 verdict-flip interval and the quality-range
multipliers quoted in the cost-quality section. Stdlib only.
"""

import argparse
import csv
import math
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CSV_PATH = REPO / "export_data/01_scores/eval_results.csv"
Z = 1.959963984540054  # 95%


def wilson(successes: int, total: int) -> tuple[float, float]:
    if total == 0:
        raise ValueError("Wilson interval undefined for total=0")
    p = successes / total
    denom = 1 + Z**2 / total
    centre = (p + Z**2 / (2 * total)) / denom
    half = (Z / denom) * math.sqrt(p * (1 - p) / total + Z**2 / (4 * total**2))
    return centre - half, centre + half


def fmt(successes: int, total: int) -> str:
    lo, hi = wilson(successes, total)
    return f"{successes}/{total} = {successes / total:5.1%} [{lo:5.1%}, {hi:5.1%}]"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--csv",
        type=Path,
        default=CSV_PATH,
        help="score CSV to analyse (default: frozen export_data scorecard)",
    )
    parser.add_argument(
        "--experiment",
        help="optional experiment label filter for attempt-level CSVs",
    )
    parser.add_argument(
        "--fixture",
        help="optional fixture filter",
    )
    args = parser.parse_args()

    with args.csv.open(newline="") as fh:
        rows = list(csv.DictReader(fh))

    if args.experiment:
        rows = [r for r in rows if r.get("experiment") == args.experiment]
    if args.fixture:
        rows = [r for r in rows if r.get("fixture") == args.fixture]

    print(f"CSV: {args.csv}")
    if args.experiment:
        print(f"Experiment: {args.experiment}")
    if args.fixture:
        print(f"Fixture: {args.fixture}")
    print(f"Rows: {len(rows)}\n")

    if not rows:
        raise SystemExit("No rows matched the requested filters.")

    models = sorted({r["model"] for r in rows})
    intent_acc = {}
    cve_recall = {}
    for model in models:
        mrows = [r for r in rows if r["model"] == model]
        encoded = [r for r in mrows if r["encode_ok"] == "True"]
        sums = {
            key: sum(int(r[key]) for r in encoded)
            for key in (
                "intent_pass",
                "intent_total",
                "cve_pass",
                "cve_total",
                "cve_expected_found",
                "cve_expected_total",
            )
        }
        intent_acc[model] = sums["intent_pass"] / sums["intent_total"]
        cve_recall[model] = sums["cve_expected_found"] / sums["cve_expected_total"]
        print(f"{model}:")
        print(f"  encode rate        {fmt(len(encoded), len(mrows))}")
        print(f"  intent accuracy    {fmt(sums['intent_pass'], sums['intent_total'])}")
        print(f"  attack-chain acc.  {fmt(sums['cve_pass'], sums['cve_total'])}")
        print(f"  CVE recall         {fmt(sums['cve_expected_found'], sums['cve_expected_total'])}")

    f6 = [r for r in rows if r["fixture"].startswith("f6") and r["encode_ok"] == "True"]
    f6_flips = sum(1 for r in f6 if int(r["cve_pass"]) > 0)
    print(f"\nF6 verdict flips     {fmt(f6_flips, len(f6))}")

    print("\nQuality-range multipliers:")
    print(f"  intent accuracy  {max(intent_acc.values()) / min(intent_acc.values()):.2f}x")
    min_recall = min(cve_recall.values())
    if min_recall:
        print(f"  CVE recall       {max(cve_recall.values()) / min_recall:.2f}x")
    else:
        print("  CVE recall       undefined (minimum is 0)")


if __name__ == "__main__":
    main()
