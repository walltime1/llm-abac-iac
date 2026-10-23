"""Retry helper for DSPy adapter parse failures."""

from typing import Optional


def run_with_adapter_retries(call, *, attempts: int, view=None):
    """
    Invoke `call` (a zero-arg callable returning the RLM prediction), retrying
    up to `attempts` times when DSPy's adapter can't parse the model output.
    """
    import dspy
    from dspy.utils.exceptions import AdapterParseError

    last_exc: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            return call()
        except (AdapterParseError, AttributeError) as e:
            last_exc = e
            msg = f"adapter/RLM failure (attempt {attempt}/{attempts})"
            if view is not None:
                view.log("error", msg)
            else:
                print(f"[retry] {msg}: {str(e)[:200]}")
            if attempt == attempts:
                break
            try:
                lm = dspy.settings.lm
                if lm is not None:
                    lm.kwargs["temperature"] = 0.01 * attempt
            except Exception:
                pass
    assert last_exc is not None
    raise last_exc
