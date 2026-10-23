"""CLI entry point for ABAC policy mining."""

import argparse
import sys


def main():
    from rlm_agent.abac_poc import mine_policy
    from rlm_agent.lm import REASONING_CHOICES

    parser = argparse.ArgumentParser(
        description="Mine ABAC policies from Ansible configurations using DSPy RLM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--goal", "-g", default="all",
                        help="Policy slice: all|ssh|sudo|db-access|firewall|filesystem")
    parser.add_argument("--ansible-dir", "-d", default=None,
                        help="Path to the Ansible directory (overrides RLM_ANSIBLE_DIR)")
    parser.add_argument("--model", "-m", default="claude-sonnet")
    parser.add_argument("--api-key", "-k", default=None)
    parser.add_argument("--base-url", "-u", default=None)
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("-i", "--iterations", type=int, default=15)
    parser.add_argument("--interpreter", choices=["docker", "local", "deno"], default="local")
    parser.add_argument("--trace", action="store_true")
    parser.add_argument("--phoenix-endpoint", default="http://localhost:6006/v1/traces")
    parser.add_argument("--phoenix-project", default="rlm-abac-poc")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--phase-order", choices=["eager", "lazy"], default="eager")
    parser.add_argument("--reasoning", choices=list(REASONING_CHOICES), default="auto")
    parser.add_argument("--retries", type=int, default=5)
    parser.add_argument("--max-tokens", type=int, default=16000)
    parser.add_argument("--no-cache", action="store_true")
    args = parser.parse_args()

    try:
        meta = mine_policy(
            policy_goal=args.goal,
            ansible_dir=args.ansible_dir,
            output_file=args.output,
            model=args.model,
            api_key=args.api_key,
            base_url=args.base_url,
            max_iterations=args.iterations,
            interpreter_mode=args.interpreter,
            trace=args.trace,
            phoenix_endpoint=args.phoenix_endpoint,
            phoenix_project=args.phoenix_project,
            reasoning=args.reasoning,
            live=args.live,
            retries=args.retries,
            max_tokens=args.max_tokens,
            cache=not args.no_cache,
            phase_order=args.phase_order,
        )
    except ValueError as e:
        print(f"[!] Configuration error: {e}")
        sys.exit(1)

    print(f"\n Done in {meta['trajectory_steps']} agent steps.")


if __name__ == "__main__":
    main()
