"""Dispatch: python -m rlm_agent {abac,encode,batch}"""

import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m rlm_agent {abac,encode,batch}")
        print("  abac   — mine ABAC policies from Ansible configs")
        print("  encode — encode and verify mined policies with Z3")
        print("  batch  — run batch evaluation")
        sys.exit(1)

    cmd = sys.argv.pop(1)
    if cmd == "abac":
        from rlm_agent.cli.abac import main as abac_main
        abac_main()
    elif cmd == "encode":
        from rlm_agent.cli.encode import main as encode_main
        encode_main()
    elif cmd == "batch":
        from rlm_agent.cli.batch import main as batch_main
        batch_main()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
