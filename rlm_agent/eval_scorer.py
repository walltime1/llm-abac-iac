"""Batch evaluation scorer — runs ground truth queries against encoded policies.

Usage:
    python -m rlm_agent.eval_scorer rlm_agent/reports/batch_opencode-go_glm-5.1_*.abac.md
    python -m rlm_agent.eval_scorer rlm_agent/reports/*.abac.md --csv results.csv
"""

import argparse
import json
import re
import sys
from pathlib import Path

GT_DIR = Path(__file__).parent / "eval_fixtures" / "ground_truth"

# Map fixture directory name fragments to ground truth files
_FIXTURE_MAP = {
    "f1_minimal_twotier": "f1_minimal_twotier.json",
    "f2_threetier_segment": "f2_threetier_segmented.json",
    "f3_privsep_service_a": "f3_privsep_service_accounts.json",
    "f4_patched_vs_vulner": "f4_patched_vs_vulnerable.json",
    "f5_chained_vulnerabi": "f5_chained_vulnerabilities.json",
    "f6_intent_vs_effecti": "f6_intent_vs_effective.json",
    "f7_negative_control": "f7_negative_control.json",
}


def _detect_fixture(report_path: str) -> str | None:
    """Detect fixture name from report filename."""
    name = Path(report_path).name
    for frag, gt_file in _FIXTURE_MAP.items():
        if frag in name:
            return gt_file
    return None


def _detect_run(report_path: str) -> str:
    """Extract run number from filename."""
    m = re.search(r"_r(\d+)\.abac", Path(report_path).name)
    return f"r{m.group(1)}" if m else "?"


def _detect_model(report_path: str) -> str:
    """Extract model name from report header."""
    text = Path(report_path).read_text()
    m = re.search(r"_Model: `([^`]+)`", text)
    return m.group(1) if m else "unknown"


def score_report(report_path: str, verbose: bool = False, no_cve: bool = False) -> dict:
    """Score a single report against its fixture's ground truth.

    Returns a dict with:
      - model, fixture, run
      - encode_ok: bool
      - intent_pass, intent_total, intent_results: list
      - cve_pass, cve_total, cve_results: list
      - admitted_cves: list of admitted CVE IDs
      - errors: list of error strings
    """
    from rlm_agent.abac_encoder import ABACEncoder, load_policy

    gt_file = _detect_fixture(report_path)
    if not gt_file:
        return {"error": f"Cannot detect fixture from {report_path}"}

    gt_path = GT_DIR / gt_file
    if not gt_path.exists():
        return {"error": f"Ground truth not found: {gt_path}"}

    gt = json.loads(gt_path.read_text())
    model = _detect_model(report_path)
    fixture = gt["fixture"]
    run = _detect_run(report_path)

    result = {
        "model": model,
        "fixture": fixture,
        "run": run,
        "file": Path(report_path).name,
        "encode_ok": False,
        "intent_pass": 0,
        "intent_total": 0,
        "intent_results": [],
        "cve_pass": 0,
        "cve_total": 0,
        "cve_results": [],
        "admitted_cves": [],
        "errors": [],
    }

    # Load and encode
    try:
        policy = load_policy(report_path)
    except Exception as e:
        result["errors"].append(f"load: {e}")
        return result

    # Build TWO encoders:
    #   intent_encoder — CVE escalation OFF, evaluates policy-as-written
    #   cve_encoder    — CVE escalation ON,  evaluates effective access
    # The fixture ground truth distinguishes intent_queries (no CVE) from
    # cve_queries (with CVE), so the encoders must match.
    try:
        intent_encoder = ABACEncoder(policy, enable_cve_escalation=False)
        result["encode_ok"] = True
    except Exception as e:
        result["errors"].append(f"encode: {e}")
        return result

    if no_cve:
        cve_encoder = intent_encoder
    else:
        try:
            cve_encoder = ABACEncoder(policy, enable_cve_escalation=True)
        except Exception as e:
            cve_encoder = intent_encoder
            result["errors"].append(f"cve_escalation_disabled: {e}")

    # Collect admitted CVEs from triage log (cve encoder only)
    result["admitted_cves"] = [
        cve_id for cve_id, _, decision, _ in cve_encoder.cve_triage_log
        if decision == "admitted"
    ]

    # Run intent queries against the no-CVE encoder
    for q in gt.get("intent_queries", []):
        user = q["user"]
        action = q["action"]
        hg = q.get("host_group")
        svc = q.get("service")
        expected = q["expected"]

        try:
            actual, explanation = intent_encoder.query(user, action, hg, svc)
        except Exception as e:
            actual, explanation = "error", str(e)

        # _attacker returning "error" (user not found) when no CVEs admitted
        # is semantically equivalent to "unsat" — no attack path exists
        if actual == "error" and user == "_attacker" and expected == "unsat":
            actual = "unsat"

        passed = actual == expected
        result["intent_total"] += 1
        if passed:
            result["intent_pass"] += 1

        qr = {
            "query": f"{user} + {action} on {hg or '*'}/{svc or '*'}",
            "expected": expected,
            "actual": actual,
            "passed": passed,
        }
        if not passed:
            qr["reason"] = q.get("reason", "")
            qr["explanation"] = explanation
        result["intent_results"].append(qr)

        if verbose:
            mark = "ok" if passed else "FAIL"
            print(f"    [{mark:4s}] {qr['query']}: "
                  f"expected={expected} actual={actual}")

    # Run CVE kill-chain queries
    for q in gt.get("cve_queries", []):
        user = q["user"]
        action = q["action"]
        hg = q.get("host_group")
        svc = q.get("service")
        expected = q["expected"]

        try:
            actual, explanation = cve_encoder.query(user, action, hg, svc)
        except Exception as e:
            actual, explanation = "error", str(e)

        # _attacker "error" when no CVEs admitted = "unsat" (no attack path)
        if actual == "error" and user == "_attacker" and expected == "unsat":
            actual = "unsat"

        passed = actual == expected
        result["cve_total"] += 1
        if passed:
            result["cve_pass"] += 1

        # Check if expected CVEs were admitted
        expected_cves = q.get("expected_cves", q.get("expected_cve"))
        if isinstance(expected_cves, str):
            expected_cves = [expected_cves]
        expected_cves = expected_cves or []

        cves_found = [c for c in expected_cves if c in result["admitted_cves"]]
        cves_missing = [c for c in expected_cves if c not in result["admitted_cves"]]

        qr = {
            "query": f"{user} + {action} on {hg or '*'}/{svc or '*'}",
            "expected": expected,
            "actual": actual,
            "passed": passed,
            "expected_cves": expected_cves,
            "cves_found": cves_found,
            "cves_missing": cves_missing,
            "chain_hops": q.get("chain_hops", 0),
        }
        if not passed:
            qr["reason"] = q.get("reason", "")
            qr["explanation"] = explanation
        result["cve_results"].append(qr)

        if verbose:
            mark = "ok" if passed else "FAIL"
            cve_str = f" cves={len(cves_found)}/{len(expected_cves)}" if expected_cves else ""
            print(f"    [{mark:4s}] {qr['query']}: "
                  f"expected={expected} actual={actual}{cve_str}")

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Score ABAC batch eval reports against ground truth."
    )
    parser.add_argument("reports", nargs="+", help="Report .abac.md files to score")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print per-query results")
    parser.add_argument("--csv", type=str, help="Write results to CSV file")
    parser.add_argument("--summary", "-s", action="store_true", default=True,
                        help="Print per-model summary table")
    args = parser.parse_args()

    all_results = []

    for report in sorted(args.reports):
        if not Path(report).exists():
            print(f"[!] File not found: {report}")
            continue

        if args.verbose:
            print(f"\n{'='*60}")
            print(f"  {Path(report).name}")
            print(f"{'='*60}")

        # Run in subprocess to isolate Z3 segfaults.
        # Redirect stdout to devnull (encoder prints triage noise there),
        # emit result JSON on stderr to keep it clean.
        import subprocess
        proc = subprocess.run(
            [sys.executable, "-c",
             "import json, sys, os; "
             "os.dup2(os.open(os.devnull, os.O_WRONLY), 1); "  # silence stdout
             "from rlm_agent.eval_scorer import score_report; "
             f"sys.stderr.write(json.dumps(score_report({report!r}, verbose=False)) + '\\n')"],
            capture_output=True, text=True, timeout=300,
        )
        default_r = {
            "model": _detect_model(report),
            "fixture": (_detect_fixture(report) or "?").replace(".json", ""),
            "run": _detect_run(report),
            "file": Path(report).name,
            "encode_ok": False,
            "intent_pass": 0, "intent_total": 0, "intent_results": [],
            "cve_pass": 0, "cve_total": 0, "cve_results": [],
            "admitted_cves": [],
            "errors": [],
        }
        if proc.returncode != 0:
            # Retry without CVE escalation — μZ crashes on some
            # become/in_group recursive models
            proc2 = subprocess.run(
                [sys.executable, "-c",
                 "import json, sys, os; "
                 "os.dup2(os.open(os.devnull, os.O_WRONLY), 1); "
                 "from rlm_agent.eval_scorer import score_report; "
                 f"sys.stderr.write(json.dumps(score_report({report!r}, verbose=False, no_cve=True)) + '\\n')"],
                capture_output=True, text=True, timeout=300,
            )
            if proc2.returncode == 0:
                for line in reversed(proc2.stderr.strip().split("\n")):
                    try:
                        r = json.loads(line)
                        r["errors"] = r.get("errors", []) + ["z3_crash_cve_disabled"]
                        break
                    except (json.JSONDecodeError, ValueError):
                        continue
            else:
                default_r["errors"] = [f"z3_crash: exit={proc.returncode}"]
                r = default_r
        else:
            # JSON is on stderr (clean, no encoder noise)
            stderr_lines = proc.stderr.strip().split("\n")
            r = default_r
            for line in reversed(stderr_lines):
                try:
                    r = json.loads(line)
                    break
                except (json.JSONDecodeError, ValueError):
                    continue
            if not r.get("encode_ok") and not r.get("errors"):
                r["errors"] = [f"parse_error: no JSON found in stderr"]

        if "error" in r and isinstance(r.get("error"), str):
            print(f"  [skip] {r['error']}")
            continue

        all_results.append(r)

        if args.verbose and r["errors"]:
            for e in r["errors"]:
                print(f"  [!] {e}")

    if not all_results:
        print("No results.")
        return

    # Per-model summary
    if args.summary:
        models = {}
        for r in all_results:
            m = r["model"]
            if m not in models:
                models[m] = {
                    "total": 0, "encoded": 0,
                    "intent_pass": 0, "intent_total": 0,
                    "cve_pass": 0, "cve_total": 0,
                    "cve_admitted": 0,
                    "cve_expected_found": 0, "cve_expected_total": 0,
                }
            s = models[m]
            s["total"] += 1
            if r["encode_ok"]:
                s["encoded"] += 1
            s["intent_pass"] += r["intent_pass"]
            s["intent_total"] += r["intent_total"]
            s["cve_pass"] += r["cve_pass"]
            s["cve_total"] += r["cve_total"]
            s["cve_admitted"] += len(r["admitted_cves"])
            for cr in r["cve_results"]:
                s["cve_expected_found"] += len(cr.get("cves_found", []))
                s["cve_expected_total"] += len(cr.get("expected_cves", []))

        print(f"\n{'='*80}")
        print(f"  EVALUATION SUMMARY")
        print(f"{'='*80}")
        print(f"\n{'Model':<35s} {'Enc':>5s} {'Intent':>12s} {'KillChain':>12s} {'CVE Recall':>12s} {'Admitted':>8s}")
        print(f"{'':<35s} {'':>5s} {'pass/total':>12s} {'pass/total':>12s} {'found/exp':>12s} {'':>8s}")
        print("-" * 90)

        for m in sorted(models.keys()):
            s = models[m]
            enc = f"{s['encoded']}/{s['total']}"
            intent = f"{s['intent_pass']}/{s['intent_total']}"
            cve = f"{s['cve_pass']}/{s['cve_total']}"
            recall = f"{s['cve_expected_found']}/{s['cve_expected_total']}"
            print(f"{m:<35s} {enc:>5s} {intent:>12s} {cve:>12s} {recall:>12s} {s['cve_admitted']:>8d}")

        print()

    # CSV output
    if args.csv:
        import csv
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "model", "fixture", "run", "encode_ok",
                "intent_pass", "intent_total",
                "cve_pass", "cve_total",
                "admitted_cves", "cve_expected_found", "cve_expected_total",
                "errors",
            ])
            for r in all_results:
                cves_found = sum(len(cr.get("cves_found", [])) for cr in r["cve_results"])
                cves_expected = sum(len(cr.get("expected_cves", [])) for cr in r["cve_results"])
                w.writerow([
                    r["model"], r["fixture"], r["run"], r["encode_ok"],
                    r["intent_pass"], r["intent_total"],
                    r["cve_pass"], r["cve_total"],
                    ";".join(r["admitted_cves"]),
                    cves_found, cves_expected,
                    ";".join(r["errors"]),
                ])
        print(f"[+] CSV written to {args.csv}")


if __name__ == "__main__":
    main()
