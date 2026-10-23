"""Dump per-query verdicts for all reports (fixed encoder) to a long CSV.

Enables the SAT-recall / UNSAT-specificity decomposition and CVE precision proxy.
Run from repo root:  python3 -m rlm_agent.dump_per_query
Writes: /tmp/per_query_all.csv
"""
import csv
import glob
import os

from rlm_agent.eval_scorer import score_report

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = [
    ("april", os.path.join(BASE, "export_data", "05_reports", "files", "*.abac.md")),
    ("june", os.path.join(BASE, "rlm_agent", "reports", "*.abac.md")),
]
FIELDS = ["batch", "model", "fixture", "run", "encode_ok", "query_kind",
          "expected", "actual", "passed", "n_expected_cves", "n_cves_found",
          "n_admitted"]


def main():
    rows = []
    for batch, pattern in SOURCES:
        for path in sorted(glob.glob(pattern)):
            r = score_report(path, verbose=False)
            n_admitted = len([c for c in r.get("admitted_cves", []) if c])
            common = dict(batch=batch, model=r["model"], fixture=r["fixture"],
                          run=r["run"], encode_ok=r["encode_ok"])
            for q in r.get("intent_results", []):
                rows.append({**common, "query_kind": "intent",
                             "expected": q.get("expected"), "actual": q.get("actual"),
                             "passed": q.get("passed"), "n_expected_cves": 0,
                             "n_cves_found": 0, "n_admitted": n_admitted})
            for q in r.get("cve_results", []):
                rows.append({**common, "query_kind": "cve",
                             "expected": q.get("expected"), "actual": q.get("actual"),
                             "passed": q.get("passed"),
                             "n_expected_cves": len(q.get("expected_cves", [])),
                             "n_cves_found": len(q.get("cves_found", [])),
                             "n_admitted": n_admitted})
    out = "/tmp/per_query_all.csv"
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} per-query rows to {out}")


if __name__ == "__main__":
    main()
