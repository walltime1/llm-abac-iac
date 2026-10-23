"""Arize Phoenix OTEL tracing for DSPy + LiteLLM."""

import os
from typing import Optional


_TRACER_PROVIDER = None  # set by setup_tracing(); used by flush_tracing()


def setup_tracing(
    endpoint: str = "http://localhost:6006/v1/traces",
    project_name: str = "rlm-vuln-poc",
    resource_attrs: Optional[dict] = None,
):
    """
    Register OpenTelemetry tracing to a Phoenix collector and auto-instrument
    DSPy + LiteLLM so every RLM iteration, LM call, and tool invocation is
    captured as a span.

    `resource_attrs` (e.g. model name, API base, provider, interpreter mode)
    are stamped onto every emitted span via OTEL resource attributes, so they
    show up in Phoenix's Project/Trace metadata side-panels.

    Returns the TracerProvider (or None if Phoenix SDK is missing) so callers
    can force_flush() before process exit.
    """
    global _TRACER_PROVIDER
    try:
        from phoenix.otel import register
        from openinference.instrumentation.dspy import DSPyInstrumentor
        from openinference.instrumentation.litellm import LiteLLMInstrumentor
    except ImportError as e:
        print(f"[trace] Skipping — Phoenix SDK not installed ({e})")
        return None

    # Set OTEL_RESOURCE_ATTRIBUTES env var BEFORE register() so the
    # TracerProvider's Resource picks them up.
    if resource_attrs:
        existing = os.environ.get("OTEL_RESOURCE_ATTRIBUTES", "")
        extra = ",".join(
            f"{k}={v}" for k, v in resource_attrs.items() if v not in (None, "")
        )
        os.environ["OTEL_RESOURCE_ATTRIBUTES"] = (
            f"{existing},{extra}" if existing else extra
        )

    tracer_provider = register(
        project_name=project_name,
        endpoint=endpoint,
        auto_instrument=False,
        batch=True,
    )
    DSPyInstrumentor().instrument(tracer_provider=tracer_provider)
    LiteLLMInstrumentor().instrument(tracer_provider=tracer_provider)
    _TRACER_PROVIDER = tracer_provider

    import atexit
    atexit.register(flush_tracing)

    print(f"[trace] Phoenix tracing enabled → {endpoint} (project={project_name})")
    if resource_attrs:
        for k, v in resource_attrs.items():
            if v not in (None, ""):
                print(f"[trace]   {k}={v}")
    return tracer_provider


def flush_tracing() -> None:
    """Force-flush the active TracerProvider so spans land before process exit."""
    tp = _TRACER_PROVIDER
    if tp is None:
        return
    try:
        tp.force_flush()
        print("[trace] spans flushed")
    except Exception as e:
        print(f"[trace] flush failed: {e}")
