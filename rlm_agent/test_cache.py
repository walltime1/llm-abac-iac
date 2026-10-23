"""Quick cache test for OpenCode Go models via litellm.

Tests multiple cache key formats to see if any trigger provider-side caching.
Run from the terminal where OPENCODE_API_KEY is set:

  python test_cache.py
"""

import os
import litellm

BASE_URL = "https://opencode.ai/zen/go/v1"
API_KEY = os.environ.get("OPENCODE_API_KEY") or os.environ.get("OPENAI_API_KEY", "none")
SYSTEM = "You are a security policy analyzer for Ansible IaC. " * 200  # ~1200 tokens


def try_variant(label, extra_body=None):
    print(f"\n--- {label} ---")
    for i in range(2):
        resp = litellm.completion(
            model="openai/qwen3.6-plus",
            api_key=API_KEY,
            api_base=BASE_URL,
            messages=[
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"Say 'hello {i}'."},
            ],
            max_tokens=20,
            drop_params=True,
            **({"extra_body": extra_body} if extra_body else {}),
        )
        u = resp.usage
        details = getattr(u, "prompt_tokens_details", None)
        cached = getattr(details, "cached_tokens", None) if details else None
        print(f"  req {i+1}: prompt={u.prompt_tokens} cached={cached}")


print("=== OpenCode Go Cache Test (Qwen 3.6 Plus) ===")
print(f"API key set: {bool(os.environ.get('OPENCODE_API_KEY'))}")

try_variant("no cache hint")
try_variant("prompt_cache_key (snake_case)", {"prompt_cache_key": "test-123"})
try_variant("promptCacheKey (camelCase)", {"promptCacheKey": "test-123"})
try_variant("cache_key", {"cache_key": "test-123"})

print("\n=== Done ===")
print("Check OpenCode Go usage dashboard for 'Cache Read' column.")
