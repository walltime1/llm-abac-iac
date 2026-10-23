#!/usr/bin/env python3
"""Experiment 4 pre-flight: verify provider API keys before a 168-run batch.

--dry-run only plans; it never hits the network, so a wrong key (401) is not
caught until real runs start. This sends ONE trivial completion per provider
(a few tokens, sub-cent) and reports auth/connectivity per model.

Run from inside rlm_agent/:
    ../.venv/bin/python exp4_preflight.py
"""

import sys

from rlm_agent.lm import build_lm

# One representative model per provider used by the Exp4 configs.
MODELS = [
    "openrouter/qwen/qwen3.5-27b:alibaba",  # OPENROUTER_API_KEY
    "opencode-go/qwen3.6-plus",             # OPENCODE_API_KEY
    "opencode-go/glm-5.1",
    "opencode-go/kimi-k2.6",
    "opencode-go/minimax-m2.7",
]


def check(model: str) -> bool:
    try:
        lm = build_lm(model, max_tokens=5, reasoning="off", num_retries=0,
                      cache=False)
        out = lm("Reply with the single word: ok")
        text = (out[0] if isinstance(out, list) else out)
        print(f"  OK    {model}  -> {str(text)[:40]!r}")
        return True
    except Exception as e:
        msg = str(e)
        hint = ""
        low = msg.lower()
        if "401" in msg or "unauthor" in low or "invalid" in low and "key" in low:
            hint = "  <- bad/expired API key"
        elif "403" in msg:
            hint = "  <- key valid but forbidden (model/plan)"
        elif "429" in msg:
            hint = "  <- rate limited (key works)"
        print(f"  FAIL  {model}  [{type(e).__name__}] {msg[:120]}{hint}")
        return False


def main() -> None:
    print("=== Experiment 4 pre-flight: provider key check ===\n")
    results = {m: check(m) for m in MODELS}
    n_ok = sum(results.values())
    print(f"\n{n_ok}/{len(MODELS)} models reachable.")
    providers_ok = {
        "OPENROUTER_API_KEY": results["openrouter/qwen/qwen3.5-27b:alibaba"],
        "OPENCODE_API_KEY": any(v for m, v in results.items()
                                if m.startswith("opencode-go/")),
    }
    for prov, ok in providers_ok.items():
        print(f"  {prov:20s} {'OK' if ok else 'NOT WORKING'}")
    sys.exit(0 if all(providers_ok.values()) else 1)


if __name__ == "__main__":
    main()
