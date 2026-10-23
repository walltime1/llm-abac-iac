"""LM factory — build a dspy.LM for any supported provider."""

import os
import subprocess
from typing import Optional

import dspy


# Well-known model shorthands so users don't have to remember DSPy prefixes.
MODEL_ALIASES = {
    # Anthropic
    "claude-sonnet": "claude-sonnet-4-20250514",
    "claude-opus": "claude-opus-4-20250514",
    "claude-haiku": "claude-haiku-4-5-20251001",
    # OpenAI
    "gpt-4o": "openai/gpt-4o",
    "gpt-4o-mini": "openai/gpt-4o-mini",
    "gpt-4-turbo": "openai/gpt-4-turbo",
    "o1": "openai/o1",
    "o3-mini": "openai/o3-mini",
    # OpenRouter
    "or-sonnet": "openrouter/anthropic/claude-sonnet-4",
    "or-opus": "openrouter/anthropic/claude-opus-4",
    "or-gpt-4o": "openrouter/openai/gpt-4o",
    "or-llama-3.3-70b": "openrouter/meta-llama/llama-3.3-70b-instruct",
    "or-deepseek": "openrouter/deepseek/deepseek-chat",
    "or-qwen-72b": "openrouter/qwen/qwen-2.5-72b-instruct",
    # OpenCode Go
    "go-glm-5.1": "opencode-go/glm-5.1",
    "go-glm-5": "opencode-go/glm-5",
    "go-kimi-k2.5": "opencode-go/kimi-k2.5",
    "go-kimi-k2.6": "opencode-go/kimi-k2.6",
    "go-mimo-v2-pro": "opencode-go/mimo-v2-pro",
    "go-mimo-v2.5-pro": "opencode-go/mimo-v2.5-pro",
    "go-mimo-v2.5": "opencode-go/mimo-v2.5",
    "go-qwen3.6-plus": "opencode-go/qwen3.6-plus",
    "go-qwen3.5-plus": "opencode-go/qwen3.5-plus",
    "go-minimax-m2.7": "opencode-go/minimax-m2.7",
}

# Provider detection by model-string prefix
_ANTHROPIC_PREFIXES = ("claude-",)
_OPENAI_PREFIXES = ("openai/", "gpt-", "o1", "o3")
_OPENROUTER_PREFIXES = ("openrouter/",)
_OPENCODE_GO_PREFIXES = ("opencode-go/",)

_OPENCODE_GO_BASE_URL = "https://opencode.ai/zen/go/v1"

REASONING_CHOICES = ("auto", "off", "low", "medium", "high")


def _detect_provider(model: str) -> str:
    """Return 'anthropic', 'openai', 'openrouter', 'opencode-go', or 'custom'."""
    m = model.lower()
    if any(m.startswith(p) for p in _OPENCODE_GO_PREFIXES):
        return "opencode-go"
    if any(m.startswith(p) for p in _OPENROUTER_PREFIXES):
        return "openrouter"
    if any(m.startswith(p) for p in _ANTHROPIC_PREFIXES):
        return "anthropic"
    if any(m.startswith(p) for p in _OPENAI_PREFIXES):
        return "openai"
    return "custom"


def _normalize_base_url(url: str) -> str:
    """Ensure the base URL ends with /v1."""
    url = url.rstrip("/")
    if not url.endswith("/v1"):
        url = f"{url}/v1"
    return url


def _reasoning_kwargs(reasoning: str, provider: str) -> dict:
    """Translate a reasoning setting into provider-specific kwargs for dspy.LM."""
    if reasoning == "auto":
        return {}
    if reasoning == "off":
        if provider in ("custom", "openrouter"):
            return {
                "extra_body": {
                    "chat_template_kwargs": {"enable_thinking": False},
                    "enable_thinking": False,
                }
            }
        if provider == "openai":
            return {"reasoning_effort": "low"}
        return {}
    kwargs: dict = {"reasoning_effort": reasoning}
    if provider in ("custom", "openrouter"):
        kwargs["extra_body"] = {
            "chat_template_kwargs": {"enable_thinking": True},
            "enable_thinking": True,
        }
    return kwargs


def _open_in_private_window(url: str) -> None:
    """Best-effort: open URL in a private/incognito window on macOS."""
    import platform
    import webbrowser

    if platform.system() == "Darwin":
        attempts = [
            ["open", "-na", "Google Chrome", "--args", "--incognito", url],
            ["open", "-na", "Firefox", "--args", "-private-window", url],
            ["open", "-na", "Microsoft Edge", "--args", "--inprivate", url],
        ]
        for cmd in attempts:
            result = subprocess.run(cmd, capture_output=True)
            if result.returncode == 0:
                print(f"[openrouter] Opened private window via {cmd[2]}.")
                return
    webbrowser.open(url)
    print("[openrouter] Opened default browser (private mode not available).")


def _prompt_openrouter_key() -> str:
    """Pop a private browser window to OpenRouter's keys page and read the key."""
    import getpass

    keys_url = "https://openrouter.ai/keys"
    print("[openrouter] No API key found.")
    print(f"[openrouter] Create one at: {keys_url}")

    try:
        key = getpass.getpass("[openrouter] Paste API key (input hidden): ").strip()
    except (EOFError, KeyboardInterrupt):
        raise RuntimeError("OpenRouter key prompt cancelled.") from None

    if not key:
        raise RuntimeError("No OpenRouter key entered.")

    os.environ["OPENROUTER_API_KEY"] = key
    print(
        "[openrouter] Key accepted for this session. To skip next time:\n"
        "  export OPENROUTER_API_KEY=<your key>"
    )
    return key


def build_lm(
    model: str = "claude-sonnet",
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    max_tokens: int = 8000,
    reasoning: str = "auto",
    num_retries: int = 5,
    cache: bool = True,
) -> dspy.LM:
    """Build a dspy.LM for any supported provider.

    Provider is auto-detected from the model string.
    """
    resolved = MODEL_ALIASES.get(model, model)
    provider = _detect_provider(resolved)
    reasoning_kw = _reasoning_kwargs(reasoning, provider)

    if provider == "anthropic":
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ValueError(
                "Anthropic model requires ANTHROPIC_API_KEY env var or --api-key."
            )
        kwargs = dict(model=resolved, api_key=key, max_tokens=max_tokens, num_retries=num_retries, **reasoning_kw)
        if base_url:
            kwargs["api_base"] = _normalize_base_url(base_url)
        print(f"[+] LM  : Anthropic / {resolved}")

    elif provider == "openai":
        key = api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise ValueError(
                "OpenAI model requires OPENAI_API_KEY env var or --api-key."
            )
        kwargs = dict(model=resolved, api_key=key, max_tokens=max_tokens, num_retries=num_retries, **reasoning_kw)
        if base_url:
            kwargs["api_base"] = _normalize_base_url(base_url)
        print(f"[+] LM  : OpenAI / {resolved}")

    elif provider == "openrouter":
        key = api_key or os.environ.get("OPENROUTER_API_KEY")
        if not key:
            key = _prompt_openrouter_key()
        kwargs = dict(model=resolved, api_key=key, max_tokens=max_tokens, num_retries=num_retries, **reasoning_kw)
        if base_url:
            kwargs["api_base"] = _normalize_base_url(base_url)
        print(f"[+] LM  : OpenRouter / {resolved.removeprefix('openrouter/')}")

    elif provider == "opencode-go":
        model_id = resolved.removeprefix("opencode-go/")
        key = (
            api_key
            or os.environ.get("OPENCODE_API_KEY")
            or os.environ.get("OPENAI_API_KEY", "none")
        )
        _minimax_models = ("minimax-m2.7", "minimax-m2.5")
        if model_id in _minimax_models:
            model_str = f"anthropic/{model_id}"
            # litellm's Anthropic handler appends /v1/messages to api_base
            api_base = base_url or _OPENCODE_GO_BASE_URL.removesuffix("/v1")
        else:
            model_str = f"openai/{model_id}"
            api_base = base_url or _OPENCODE_GO_BASE_URL
        kwargs = dict(
            model=model_str, api_key=key, api_base=api_base,
            max_tokens=max_tokens, num_retries=num_retries,
            drop_params=True, **reasoning_kw,
        )
        print(f"[+] LM  : OpenCode Go / {model_id}")

    else:
        if not base_url:
            raise ValueError(
                f"Model {resolved!r} not recognised as Anthropic or OpenAI. "
                "Provide --base-url for a custom OpenAI-compatible endpoint.\n"
                "  Examples:\n"
                "    LM Studio : --base-url http://localhost:1234\n"
                "    Ollama    : --base-url http://localhost:11434\n"
                "    vLLM      : --base-url http://localhost:8000\n"
            )
        key = (
            api_key
            or os.environ.get("CUSTOM_API_KEY")
            or os.environ.get("OPENAI_API_KEY", "none")
        )
        normalized_url = _normalize_base_url(base_url)
        model_str = resolved if "/" in resolved else f"openai/{resolved}"
        kwargs = dict(
            model=model_str, api_key=key, api_base=normalized_url,
            max_tokens=max_tokens, num_retries=num_retries,
            drop_params=True, **reasoning_kw,
        )
        print(f"[+] LM  : Custom endpoint ({normalized_url}) / {resolved}")

    if base_url and provider != "custom":
        print(f"[+] Base: {_normalize_base_url(base_url)}")

    kwargs["cache"] = cache
    if not cache:
        print("[+] Cache: disabled")
    return dspy.LM(**kwargs)
