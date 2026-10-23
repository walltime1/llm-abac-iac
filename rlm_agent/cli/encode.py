"""CLI entry point for Z3 ABAC encoder."""

import argparse
import sys


def main():
    # Import here so z3 isn't needed just to parse --help
    from rlm_agent.abac_encoder import load_policy, ABACEncoder, run_smoke_tests

    parser = argparse.ArgumentParser(description="Z3 ABAC policy encoder and verifier.")
    parser.add_argument("--policy", "-p", required=True, help="Path to policy .md or .json file")
    parser.add_argument("--smoke", action="store_true", help="Run smoke tests after encoding")
    parser.add_argument("--no-cve", action="store_true", help="Disable CVE escalation modeling")
    parser.add_argument("--query", nargs=4, metavar=("USER", "ACTION", "HOST_GROUP", "SERVICE"),
                        help="Run a single reachability query")
    args = parser.parse_args()

    try:
        policy = load_policy(args.policy)
    except Exception as e:
        print(f"[!] Failed to load policy: {e}")
        sys.exit(1)

    try:
        encoder = ABACEncoder(policy, enable_cve_escalation=not args.no_cve)
    except Exception as e:
        print(f"[!] Encoder error: {e}")
        sys.exit(1)

    if args.query:
        user, action, hg, svc = args.query
        result, explanation = encoder.query(user, action, hg, svc)
        print(f"{user} + {action} on {hg}/{svc}: {result}")
        if result == "sat":
            print(f"  derivation: {explanation[:300]}")
    elif args.smoke:
        run_smoke_tests(encoder)
    else:
        print(f"[+] Encoder ready. Sorts: {len(encoder.users)} users, "
              f"{len(encoder.groups)} groups, {len(encoder.host_groups)} host_groups, "
              f"{len(encoder.services)} services, {len(encoder.actions)} actions")


if __name__ == "__main__":
    main()
