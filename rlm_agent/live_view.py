"""Rich TUI dashboard for live RLM step visualization."""

import json
import time
from collections import deque
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from dspy.utils.callback import BaseCallback


class LiveView:
    """Rich Live dashboard. Push events via log(kind, text)."""

    _ICONS = {
        "lm-start": ("\U0001f9e0", "cyan"),
        "lm-end": ("\U0001f4ac", "bright_cyan"),
        "code": ("\u25b6", "yellow"),
        "obs": ("\u2713", "green"),
        "tool": ("\U0001f527", "magenta"),
        "error": ("\u26a0", "red"),
        "info": ("\u2022", "white"),
    }

    def __init__(self, target: str, max_events: int = 200):
        from rich.console import Console  # noqa: F401
        self._target = target
        self._events: deque = deque(maxlen=max_events)
        self._iter = 0
        self._started = time.time()
        self._live = None

    def log(self, kind: str, text: str) -> None:
        self._events.append((time.time(), kind, text))
        if self._live is not None:
            self._live.update(self._render())

    def bump_iteration(self) -> int:
        self._iter += 1
        return self._iter

    def _render(self):
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        from rich.console import Group

        elapsed = time.time() - self._started
        header = Panel.fit(
            f"[bold]RLM Agent[/bold]   target=[yellow]{self._target}[/yellow]   "
            f"iter=[cyan]{self._iter}[/cyan]   elapsed=[green]{elapsed:6.1f}s[/green]",
            border_style="blue",
        )

        log = Table.grid(padding=(0, 1), expand=True)
        log.add_column(width=8, no_wrap=True)
        log.add_column(width=3, no_wrap=True)
        log.add_column(ratio=1)

        for ts, kind, text in self._events:
            icon, colour = self._ICONS.get(kind, ("\u2022", "white"))
            dt = ts - self._started
            log.add_row(
                Text(f"{dt:6.2f}s", style="dim"),
                Text(icon, style=colour),
                Text(text, style=colour, overflow="ellipsis", no_wrap=False),
            )

        return Group(header, Panel(log, title="events", border_style="blue"))

    def __enter__(self) -> "LiveView":
        from rich.live import Live
        self._live = Live(
            self._render(), refresh_per_second=8,
            screen=False, transient=False,
        )
        self._live.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        if self._live is not None:
            self._live.__exit__(*exc)
            self._live = None


class LiveCallback(BaseCallback):
    """Pushes DSPy LM and tool events into a LiveView."""

    def __init__(self, view: LiveView):
        self._view = view

    def on_lm_start(self, call_id, instance, inputs):  # noqa: ARG002
        self._view.log("lm-start", f"\u2192 LLM call ({getattr(instance, 'model', '?')})")

    def on_lm_end(self, call_id, outputs, exception):  # noqa: ARG002
        if exception:
            self._view.log("error", f"LLM error: {exception}")
        else:
            self._view.log("lm-end", "\u2190 LLM response received")

    def on_tool_start(self, call_id, instance, inputs):  # noqa: ARG002
        name = getattr(instance, "name", None) or type(instance).__name__
        args_preview = json.dumps(inputs, default=str)[:120]
        self._view.log("tool", f"{name}({args_preview})")

    def on_tool_end(self, call_id, outputs, exception):  # noqa: ARG002
        if exception:
            self._view.log("error", f"tool error: {exception}")


class _WrappedInterpreter:
    """Proxy over a CodeInterpreter that pushes execute() events into LiveView."""

    def __init__(self, wrapped, view: LiveView):
        self._wrapped = wrapped
        self._view = view

    @property
    def tools(self) -> dict:
        return self._wrapped.tools

    @tools.setter
    def tools(self, value: dict) -> None:
        self._wrapped.tools = value

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_wrapped", "_view"):
            object.__setattr__(self, name, value)
        else:
            setattr(self._wrapped, name, value)

    def execute(self, code: str, variables: Optional[dict] = None) -> Any:
        step = self._view.bump_iteration()
        preview = code.strip().splitlines()[0][:120] if code.strip() else "<empty>"
        self._view.log("code", f"step {step:02d}  {preview}")
        try:
            result = self._wrapped.execute(code, variables=variables)
        except Exception as exc:
            self._view.log("error", f"exec error: {exc}")
            raise
        obs_preview = str(result)[:200].replace("\n", " \u23ce ")
        self._view.log("obs", obs_preview or "(no output)")
        return result

    def shutdown(self) -> None:
        self._wrapped.shutdown()

    def close(self) -> None:
        if hasattr(self._wrapped, "close"):
            self._wrapped.close()
        else:
            self.shutdown()


@contextmanager
def live_view(
    target: str, enabled: bool = True
) -> Iterator[Optional[LiveView]]:
    """Yield a LiveView if enabled (and Rich is importable); else yield None."""
    if not enabled:
        yield None
        return
    try:
        view = LiveView(target)
    except ImportError:
        print("[live] Rich not available \u2014 falling back to plain stdout.")
        yield None
        return
    with view:
        yield view
