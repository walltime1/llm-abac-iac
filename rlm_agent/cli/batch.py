"""CLI entry point for batch runner."""

import argparse
import sys


def main():
    from rlm_agent.batch_run import run_batch, _load_config

    parser = argparse.ArgumentParser(description="Batch ABAC policy mining runner.")
    parser.add_argument("--config", "-c", required=True, help="Path to batch config (YAML or JSON)")
    parser.add_argument("--dry-run", action="store_true", help="Show plan without executing")
    args = parser.parse_args()

    try:
        config = _load_config(args.config)
    except Exception as e:
        print(f"[!] Failed to load config: {e}")
        sys.exit(1)

    run_batch(config, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
