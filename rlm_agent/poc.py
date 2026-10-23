"""
DSPy RLM PoC — Vulnerability Report Generator
Uses dspy.RLM with vulnx CLI tools to research and compile
structured vulnerability reports.

Requirements:
  pip install dspy
  go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest
  export ANTHROPIC_API_KEY=...
  (optional) export PDCP_API_KEY=...  # projectdiscovery cloud key
"""

import subprocess
import json
import os
import sys
from typing import Optional
from datetime import datetime

import dspy


# ---------------------------------------------------------------------------
# 0. Observability — Arize Phoenix OTEL tracing
# ---------------------------------------------------------------------------
#
# Run a Phoenix server separately (in another terminal or container):
#   uv run phoenix serve           # binds UI on :6006, OTLP collector on :4317
#   # or: docker run -p 6006:6006 -p 4317:4317 arizephoenix/phoenix:latest
#
# Then start this PoC with --trace (or PHOENIX_ENABLED=1) and open
# http://localhost:6006 to inspect each RLM step, LLM call, and tool use.


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
    # TracerProvider's Resource picks them up. Verified: Phoenix's
    # register() reads this env var and includes the attrs in the resource.
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
        batch=True,  # BatchSpanProcessor — exports on background thread,
                     # avoids RecursionError from deeply nested span attrs
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


# ---------------------------------------------------------------------------
# 1a. TOON (Token-Oriented Object Notation) encoder
# ---------------------------------------------------------------------------
# A compact JSON → TOON v3 encoder, used to shrink vulnx responses before
# feeding them to the LLM. Enabled by --toon; default off (raw JSON).
#
# Spec: https://github.com/toon-format/spec/blob/main/SPEC.md
# Key saving: arrays of uniform objects are rendered as tabular rows with
# the field list declared once, e.g.
#   results[2]{cve_id,severity,cvss}:
#     CVE-2024-1,critical,9.8
#     CVE-2024-2,high,8.1
# which saves ~40-60% tokens vs JSON for typical vulnx output.

import re

_USE_TOON = False  # flipped on by --toon


def _toon_needs_quoting(s: str, delim: str = ",") -> bool:
    if not s or s != s.strip():
        return True
    if any(c in s for c in (delim, ":", "\n", "\r", "\t", "[", "]", "{", "}", '"', "\\", "-")):
        return True
    if s in ("true", "false", "null"):
        return True
    try:
        float(s)
        return True
    except ValueError:
        return False


def _toon_quote(s: str) -> str:
    escaped = (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _toon_primitive(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, bool):  # defensive, bool is a subclass of int
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            return "null"
        return str(int(v)) if v.is_integer() else format(v, "g")
    if isinstance(v, str):
        return v if not _toon_needs_quoting(v) else _toon_quote(v)
    return _toon_quote(str(v))


_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def _toon_key(key: str) -> str:
    return key if _KEY_RE.fullmatch(key) else _toon_quote(key)


def _is_uniform_primitive_objects(arr: list) -> tuple:
    """True iff every element is a dict with the same key-set and only primitive values."""
    if not arr or not all(isinstance(x, dict) for x in arr):
        return False, []
    keys = list(arr[0].keys())
    keyset = set(keys)
    for item in arr:
        if set(item.keys()) != keyset:
            return False, []
        for val in item.values():
            if isinstance(val, (dict, list)):
                return False, []
    return True, keys


def _toon_emit(value, indent: int, key) -> list:
    pad = "  " * indent
    out: list = []
    prefix = f"{_toon_key(key)}" if key is not None else ""

    if isinstance(value, dict):
        if key is None:
            for k, v in value.items():
                out.extend(_toon_emit(v, indent, k))
        elif not value:
            out.append(f"{pad}{prefix}:")
        else:
            out.append(f"{pad}{prefix}:")
            for k, v in value.items():
                out.extend(_toon_emit(v, indent + 1, k))
        return out

    if isinstance(value, list):
        header_key = prefix
        n = len(value)
        if n == 0:
            out.append(f"{pad}{header_key}[0]:")
            return out

        if all(not isinstance(x, (dict, list)) for x in value):
            inline = ",".join(_toon_primitive(x) for x in value)
            out.append(f"{pad}{header_key}[{n}]: {inline}")
            return out

        uniform, fields = _is_uniform_primitive_objects(value)
        if uniform:
            field_list = ",".join(_toon_key(f) for f in fields)
            out.append(f"{pad}{header_key}[{n}]{{{field_list}}}:")
            for item in value:
                row = ",".join(_toon_primitive(item[f]) for f in fields)
                out.append(f"{pad}  {row}")
            return out

        out.append(f"{pad}{header_key}[{n}]:")
        for item in value:
            if isinstance(item, dict):
                if not item:
                    out.append(f"{pad}  - {{}}")
                    continue
                items = list(item.items())
                first_k, first_v = items[0]
                if isinstance(first_v, (dict, list)):
                    out.append(f"{pad}  -")
                    for k, v in items:
                        out.extend(_toon_emit(v, indent + 2, k))
                else:
                    out.append(f"{pad}  - {_toon_key(first_k)}: {_toon_primitive(first_v)}")
                    for k, v in items[1:]:
                        out.extend(_toon_emit(v, indent + 2, k))
            elif isinstance(item, list):
                sub_n = len(item)
                if all(not isinstance(x, (dict, list)) for x in item):
                    inline = ",".join(_toon_primitive(x) for x in item)
                    out.append(f"{pad}  - [{sub_n}]: {inline}")
                else:
                    out.append(f"{pad}  - [{sub_n}]:")
                    for sub in item:
                        out.extend(_toon_emit(sub, indent + 2, None))
            else:
                out.append(f"{pad}  - {_toon_primitive(item)}")
        return out

    # primitive at arbitrary depth
    if key is None:
        out.append(f"{pad}{_toon_primitive(value)}")
    else:
        out.append(f"{pad}{prefix}: {_toon_primitive(value)}")
    return out


def json_to_toon(value) -> str:
    """Encode a JSON-compatible Python value as TOON v3 text."""
    return "\n".join(_toon_emit(value, indent=0, key=None))


def _maybe_toon(raw_json: str) -> str:
    """If --toon is on, convert a JSON (or JSONL) string to TOON.

    vulnx `search` emits JSONL (one object per line), while `id` emits a single
    JSON document. We try single-document first, then fall back to line-by-line
    parsing, then give up and return the raw text unchanged.
    """
    if not _USE_TOON or not raw_json.strip():
        return raw_json
    try:
        return json_to_toon(json.loads(raw_json))
    except (json.JSONDecodeError, ValueError):
        pass
    # JSONL fallback
    try:
        rows = [json.loads(line) for line in raw_json.splitlines() if line.strip()]
    except (json.JSONDecodeError, ValueError):
        return raw_json
    if not rows:
        return raw_json
    return json_to_toon({"results": rows})


# ---------------------------------------------------------------------------
# 1. Tools — thin wrappers around the vulnx CLI
# ---------------------------------------------------------------------------


def _run_vulnx(*args):
    """Run vulnx with given args and return parsed Python object.

    Returns a dict or list (native Python), not a JSON string, so
    RLM-generated code can iterate results directly without json.loads().
    Same convention as ansible_tools.py.
    """
    cmd = ["vulnx", "--silent", "--json"] + list(args)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout.strip()
        if not output and result.stderr.strip():
            return {"error": result.stderr.strip()}
        if not output:
            return {"results": []}
        # Parse JSON; handle JSONL (one JSON object per line)
        try:
            return json.loads(output)
        except (json.JSONDecodeError, ValueError):
            pass
        try:
            rows = [json.loads(line) for line in output.splitlines() if line.strip()]
            return rows if rows else {"results": []}
        except (json.JSONDecodeError, ValueError):
            return {"raw": output}
    except FileNotFoundError:
        return {
            "error": "vulnx not found. Install: go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest"
        }
    except subprocess.TimeoutExpired:
        return {"error": "vulnx timed out after 30s"}
    except Exception as e:
        return {"error": str(e)}


def search_vulnerabilities(
    query: str, limit: int = 15, sort_by: str = "cvss_score"
) -> str:
    """
    Search for vulnerabilities using a vulnx query string.
    Supports field syntax like 'severity:critical && is_remote:true',
    product names like 'apache', CVSSscore filters like 'cvss_score:>8.0',
    and boolean operators (&&, ||, NOT).
    Returns JSON list of matching vulnerabilities.

    Args:
        query:   vulnx search query (e.g. 'apache && severity:critical')
        limit:   max number of results (default 15)
        sort_by: field to sort descending by (default 'cvss_score')
    """
    return _run_vulnx("search", query, "--limit", str(limit), "--sort-desc", sort_by)


def get_cve_details(cve_id: str) -> str:
    """
    Fetch full details for one or more CVE IDs (comma-separated).
    Returns JSON with CVSS score, severity, description, affected products,
    exploit availability, EPSS score, KEV status, and remediation info.

    Args:
        cve_id: single or comma-separated CVE IDs, e.g. 'CVE-2021-44228'
                or 'CVE-2021-44228,CVE-2024-1234'
    """
    return _run_vulnx("id", cve_id)


def search_critical_remote(product: str, limit: int = 10) -> str:
    """
    Find critical and high-severity, remotely-exploitable vulnerabilities.
    Uses vulnx's --product (-p) flag for CPE-based product matching,
    avoiding free-text ranking that returns wrong-product CVEs.
    Post-filters for is_remote=true and severity critical/high in Python.

    Args:
        product: product or vendor name (e.g. 'nginx', 'postgresql', 'log4j')
        limit:   max results to return (default 10)
    """
    raw = _run_vulnx(
        "search", "-p", product,
        "--limit", str(limit * 2),  # fetch extra for post-filtering
        "--sort-desc", "cvss_score"
    )
    # Extract results list
    if isinstance(raw, dict):
        items = raw.get("results", [])
    elif isinstance(raw, list):
        items = raw
    else:
        return []
    # Post-filter: remote + critical/high severity
    filtered = []
    for v in items:
        if not isinstance(v, dict):
            continue
        if v.get("is_remote") is not True:
            continue
        sev = (v.get("severity") or "").lower()
        if sev not in ("critical", "high"):
            continue
        filtered.append(v)
        if len(filtered) >= limit:
            break
    return filtered


def search_kev_vulnerabilities(product: str, limit: int = 10) -> str:
    """
    Find Known Exploited Vulnerabilities (KEV) for a given product.
    KEV entries are confirmed to be actively exploited in the wild.
    Uses vulnx's --product flag for CPE-based product matching.

    Args:
        product: product or technology name (e.g. 'apache', 'vmware')
        limit:   max results to return (default 10)
    """
    return _run_vulnx(
        "search", "-p", product, "--kev",
        "--limit", str(limit), "--sort-desc", "cvss_score"
    )


def search_recent_vulnerabilities(product: str, days: int = 90, limit: int = 10) -> str:
    """
    Find vulnerabilities published in the last N days for a product.
    Useful for detecting emerging threats.

    Args:
        product: product or vendor name
        days:    look back window in days (default 90)
        limit:   max results to return (default 10)
    """
    query = f"{product} && age_in_days:<{days}"
    return _run_vulnx(
        "search", query, "--limit", str(limit), "--sort-desc", "cvss_score"
    )


def analyze_severity_distribution(product: str) -> str:
    """
    Analyze the severity distribution of vulnerabilities for a product.
    Returns counts broken down by severity level (critical/high/medium/low).
    Useful for risk scoring and prioritisation.

    Args:
        product: product or vendor name to analyse
    """
    return _run_vulnx("search", product, "--term-facets", "severity=5", "--limit", "0")


VULNX_TOOLS = [
    search_vulnerabilities,
    get_cve_details,
    search_critical_remote,
    search_kev_vulnerabilities,
    search_recent_vulnerabilities,
    analyze_severity_distribution,
]


# ---------------------------------------------------------------------------
# 2. DSPy Signature
# ---------------------------------------------------------------------------


class VulnerabilityReportSignature(dspy.Signature):
    """
    Research and compile a professional vulnerability security report for the
    given target (product, vendor, or technology). Use the provided tools to:
      1. Search for critical and high-severity vulnerabilities.
      2. Find known-exploited (KEV) vulnerabilities.
      3. Retrieve full details for the most important CVEs.
      4. Analyse severity distribution.
      5. Look for recent (last 90 days) emerging threats.

    Produce a detailed, well-structured Markdown report that a security team
    can act on immediately. The report MUST include:
      - Executive Summary
      - Severity Distribution
      - Critical/High Vulnerabilities (table with CVE, CVSS, description,
        exploit status, remediation)
      - Known Exploited Vulnerabilities (KEV) section
      - Recent Emerging Threats
      - Risk Prioritisation & Recommendations
      - Appendix: full CVE details for top 3 most critical findings
    """

    target: str = dspy.InputField(
        desc="Product, vendor, or technology to research (e.g. 'apache tomcat', 'nginx', 'log4j')"
    )
    report: str = dspy.OutputField(desc="Complete Markdown vulnerability report")
    executive_summary: str = dspy.OutputField(
        desc="2-3 sentence plain-language summary of the overall risk level and top concerns"
    )


# ---------------------------------------------------------------------------
# 3. Code interpreters
# ---------------------------------------------------------------------------
# Three options, selected via --interpreter flag (default: docker):
#
#   docker  — runs each REPL step inside a persistent Docker container built
#             from Dockerfile.sandbox (Python 3.12 + vulnx binary). Real
#             isolation; vulnx available inside the sandbox.
#
#   local   — runs code in-process via exec(). No sandbox; fastest iteration.
#             Tools are injected into the exec() namespace directly.
#
#   deno    — DSPy's built-in PythonInterpreter: Python running in Pyodide
#             under Deno, WASM-isolated from host network/fs. Our vulnx tool
#             wrappers are executed host-side via JSON-RPC, so vulnx does NOT
#             need to live inside the sandbox — it just needs to be on the
#             host PATH. Requires `deno` to be installed.

import inspect
import uuid
from dspy.predict.rlm import CodeInterpreter


# ── Option A: Docker interpreter ─────────────────────────────────────────────


class DockerPythonInterpreter(CodeInterpreter):
    """
    Executes RLM-generated code inside a persistent Docker container.

    The container runs a REPL process (_repl.py) that accepts JSON-RPC
    commands over stdin/stdout. Tool modules (ansible_tools.py, vulnx
    tool functions) are copied as files into the container — no
    inspect.getsource() serialization. State persists across steps.
    """

    IMAGE_TAG = "rlm-abac-sandbox:latest"
    _image_built = False  # class-level flag to avoid rebuilding

    def __init__(self, tools: list, dockerfile_dir: str = "."):
        self._interp_tools: dict = {}
        self._container_id: str | None = None
        self._proc = None
        self._dockerfile_dir = os.path.abspath(dockerfile_dir)
        self._user_tool_fns = tools
        if not DockerPythonInterpreter._image_built:
            self._build_image()
            DockerPythonInterpreter._image_built = True
        self._write_repl_script()
        self._start_container()

    @property
    def tools(self) -> dict:
        return self._interp_tools

    @tools.setter
    def tools(self, value: dict):
        self._interp_tools = value

    def _build_image(self) -> None:
        print("[docker] Building sandbox image...")
        dockerfile = os.path.join(self._dockerfile_dir, "Dockerfile.sandbox")
        result = subprocess.run(
            ["docker", "build", "-f", dockerfile, "-t", self.IMAGE_TAG, self._dockerfile_dir],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Docker build failed:\n{result.stderr}")
        print(f"[docker] Image ready: {self.IMAGE_TAG}")

    def _write_repl_script(self) -> None:
        """Write a persistent REPL script that the container runs."""
        repl_path = os.path.join(self._dockerfile_dir, "_repl.py")
        # Collect tool function source
        tool_source_lines = ["import subprocess, json, os, sys, yaml, re\nfrom typing import Optional\nfrom pathlib import Path"]
        tool_source_lines.append("os.environ['RLM_ANSIBLE_DIR'] = '/ansible_configs'")
        tool_source_lines.append("sys.path.insert(0, '/sandbox')")
        # Copy entire source modules rather than individual functions —
        # avoids missing helper functions (_root, _safe_join, etc.)
        for module_file in ["ansible_tools.py"]:
            module_path = os.path.join(self._dockerfile_dir, module_file)
            if os.path.exists(module_path):
                tool_source_lines.append(f"# --- {module_file} ---")
                tool_source_lines.append(open(module_path).read())
        # Copy _run_vulnx + vulnx tool functions
        tool_source_lines.append(inspect.getsource(_run_vulnx))
        for fn in self._user_tool_fns:
            # Skip ansible_tools functions (already copied as module)
            if fn.__module__ == "ansible_tools":
                continue
            try:
                tool_source_lines.append(inspect.getsource(fn))
            except (OSError, TypeError):
                pass
        repl_code = "\n".join(tool_source_lines) + "\n" + '''
import io, contextlib, traceback

# Build the exec namespace with all tools + stdlib pre-imported.
# This mirrors what LocalPythonInterpreter does.
_globals = {}
_globals["__builtins__"] = __builtins__

# Pre-import modules the model commonly needs
import yaml, json, re, os, sys
for _mod_name, _mod in [("yaml", yaml), ("json", json), ("re", re),
                         ("os", os), ("sys", sys)]:
    _globals[_mod_name] = _mod

# Register all tool functions by name
for _name, _obj in list(globals().items()):
    if callable(_obj) and not _name.startswith("_"):
        _globals[_name] = _obj
# Also register private helpers that tools depend on
for _name in ["_root", "_safe_join", "_run_vulnx", "_TEXT_EXTS", "_MAX_BYTES",
              "ANSIBLE_DIR_ENV"]:
    if _name in globals():
        _globals[_name] = globals()[_name]

# Startup self-test
try:
    _test_files = list_ansible_files()
    sys.stderr.write(f"[repl] ready: {len(_test_files)} ansible files, "
                     f"yaml={yaml.__name__}, tools ok\\n")
    sys.stderr.flush()
except Exception as _e:
    sys.stderr.write(f"[repl] warning: tool self-test failed: {_e}\\n")
    sys.stderr.flush()

while True:
    try:
        line = input()
        msg = json.loads(line)
    except EOFError:
        break
    except json.JSONDecodeError:
        print(json.dumps({"error": "invalid JSON"}), flush=True)
        continue

    if msg.get("method") == "execute":
        code = msg.get("code", "")
        variables = msg.get("variables") or {}
        _globals.update(variables)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                exec(code, _globals)
            output = buf.getvalue().strip()
        except Exception:
            output = "ERROR:\\n" + traceback.format_exc()
        print(json.dumps({"output": output or "(no output)"}), flush=True)
    elif msg.get("method") == "shutdown":
        break
    else:
        print(json.dumps({"error": "unknown method"}), flush=True)
'''
        with open(repl_path, "w") as f:
            f.write(repl_code)

    def _start_container(self) -> None:
        pdcp_key = os.environ.get("PDCP_API_KEY", "")
        ansible_dir = os.environ.get("RLM_ANSIBLE_DIR", "")
        name = f"rlm-sandbox-{uuid.uuid4().hex[:8]}"
        cmd = [
            "docker", "run", "-i", "--rm",
            "--name", name,
            "-e", f"PDCP_API_KEY={pdcp_key}",
            "-e", "RLM_ANSIBLE_DIR=/ansible_configs",
            "-v", f"{os.path.join(self._dockerfile_dir, '_repl.py')}:/sandbox/_repl.py:ro",
        ]
        if ansible_dir and os.path.isdir(ansible_dir):
            cmd.extend(["-v", f"{os.path.abspath(ansible_dir)}:/ansible_configs:ro"])
        cmd.extend([self.IMAGE_TAG])

        self._proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        self._container_id = name
        # Verify REPL is alive
        test = self._send({"method": "execute", "code": "print('ok')"})
        if "ok" not in test:
            raise RuntimeError(f"Docker REPL failed to start: {test}")
        print(f"[docker] Container started: {name}")

    def _send(self, msg: dict) -> str:
        if not self._proc or self._proc.poll() is not None:
            return "ERROR: container not running"
        self._proc.stdin.write(json.dumps(msg) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline().strip()
        if not line:
            return "ERROR: no response from container"
        try:
            resp = json.loads(line)
            return resp.get("output", resp.get("error", ""))
        except json.JSONDecodeError:
            return line

    def execute(self, code: str, variables: Optional[dict] = None) -> str:
        return self._send({
            "method": "execute",
            "code": code,
            "variables": variables or {},
        })

    def shutdown(self) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                self._send({"method": "shutdown"})
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()
        self._proc = None
        self._container_id = None
        print("[docker] Container stopped.")

    def close(self) -> None:
        self.shutdown()


# ── Option B: Local interpreter (no Docker, exec() in-process) ───────────────


class _SubmitCalled(BaseException):
    """Raised by SUBMIT() inside exec() to signal early exit with FinalOutput."""
    def __init__(self, final_output):
        self.final_output = final_output


class LocalPythonInterpreter(CodeInterpreter):
    """
    Runs RLM code directly in the current Python process via exec().
    No Docker or Deno required. Tools are injected into the exec() namespace.
    Use for quick iteration; not sandboxed.
    """

    def __init__(self, tools: list):
        self._tools: dict = {}
        self._output_fields: list[dict] = []
        self._globals: dict = {fn.__name__: fn for fn in tools}
        # Pre-import commonly needed modules so the model doesn't waste
        # iterations discovering they're missing.
        import yaml, json, re, os
        self._globals.update({"yaml": yaml, "json": json, "re": re, "os": os})

    @property
    def tools(self) -> dict:
        return self._tools

    @tools.setter
    def tools(self, value: dict):
        self._tools = value
        self._globals["_run_vulnx"] = _run_vulnx
        self._globals["__builtins__"] = __builtins__

    @property
    def output_fields(self) -> list[dict]:
        return self._output_fields

    @output_fields.setter
    def output_fields(self, value: list[dict]):
        self._output_fields = value or []
        # Register SUBMIT() so the RLM can call it to exit early.
        # DSPy's PythonInterpreter does this inside its Deno sandbox;
        # we do it in the exec() namespace directly.
        from dspy.primitives.code_interpreter import FinalOutput
        def SUBMIT(**kwargs):
            raise _SubmitCalled(FinalOutput(kwargs))
        self._globals["SUBMIT"] = SUBMIT

    def execute(self, code: str, variables: Optional[dict] = None):
        import io, contextlib, traceback

        buf = io.StringIO()
        local_vars: dict = {}
        # Merge DSPy-injected tools (llm_query, etc.) into the exec namespace
        self._globals.update(self._tools)
        if variables:
            self._globals.update(variables)
        try:
            with contextlib.redirect_stdout(buf):
                exec(code, self._globals, local_vars)  # noqa: S102
            self._globals.update(local_vars)
            output = buf.getvalue()
            if not output and "result" in local_vars:
                output = str(local_vars["result"])
            return output or "(no output)"
        except _SubmitCalled as sc:
            return sc.final_output
        except Exception:
            return f"ERROR:\n{traceback.format_exc()}"

    def shutdown(self) -> None:
        self._globals.clear()

    def close(self) -> None:
        self.shutdown()


# ── Factory ───────────────────────────────────────────────────────────────────


def _bootstrap_deno_pyodide() -> None:
    """
    DSPy's runner.js imports `npm:pyodide` and a std/io module. At runtime
    DSPy spawns Deno WITHOUT --allow-net, so those specifiers must already
    be in Deno's global cache or Deno aborts before Pyodide can boot.

    We pre-cache them once via `deno cache`, guarded by a marker file so
    repeat launches are instant. Idempotent.
    """
    marker = os.path.expanduser("~/.cache/rlm-poc/deno_pyodide.cached")
    if os.path.exists(marker):
        return

    print("[deno] Warming pyodide cache (first run, ~20-30s)...")
    cmd = [
        "deno",
        "cache",
        "--node-modules-dir=none",  # force use of Deno's global npm cache
        "npm:pyodide/pyodide.js",
        "https://deno.land/std@0.186.0/io/mod.ts",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"`deno cache` failed:\n{result.stderr}\n\n"
            "Try running once manually to see the full error:\n"
            f"  {' '.join(cmd)}"
        )
    os.makedirs(os.path.dirname(marker), exist_ok=True)
    open(marker, "w").close()
    print("[deno] Cache warm — pyodide ready.")


def _build_deno_interpreter() -> CodeInterpreter:
    """
    Return DSPy's built-in Pyodide/Deno sandbox (WASM-isolated Python).

    Tool functions passed to dspy.RLM are injected by the RLM into the
    interpreter's `tools` dict; the sandbox invokes them via JSON-RPC back
    to the host, so our vulnx subprocess wrappers run on the host with full
    network access while the LLM-generated Python runs sandboxed in WASM.
    """
    import shutil

    if shutil.which("deno") is None:
        raise RuntimeError(
            "Deno not found — required by the 'deno' interpreter.\n"
            "Install it:\n"
            "  macOS:  brew install deno\n"
            "  Linux:  curl -fsSL https://deno.land/install.sh | sh\n"
            "  or see: https://docs.deno.com/runtime/getting_started/installation/"
        )

    _bootstrap_deno_pyodide()

    # Imported lazily so users without Deno can still use docker/local modes.
    from dspy.primitives.python_interpreter import PythonInterpreter

    pi = PythonInterpreter(
        # Allow Pyodide to fetch packages (pyyaml, etc.) from its CDN.
        enable_network_access=["cdn.jsdelivr.net", "pypi.org", "files.pythonhosted.org"],
    )
    # Force the global npm cache lookup so no node_modules is ever required.
    if "--node-modules-dir=none" not in pi.deno_command:
        pi.deno_command.insert(2, "--node-modules-dir=none")
    return pi


def build_interpreter(mode: str, tools: list) -> CodeInterpreter:
    if mode == "docker":
        return DockerPythonInterpreter(tools, dockerfile_dir=os.path.dirname(os.path.abspath(__file__)))
    elif mode == "local":
        return LocalPythonInterpreter(tools)
    elif mode == "deno":
        return _build_deno_interpreter()
    else:
        raise ValueError(
            f"Unknown interpreter mode {mode!r}. Choose 'docker', 'local', or 'deno'."
        )


# ---------------------------------------------------------------------------
# 3c. Retry helper — re-runs an RLM call when the adapter fails to parse the
#     model's output (common with weak models that drift off the ChatAdapter
#     format). LiteLLM transport retries are already handled per-LM-call via
#     dspy.LM(num_retries=...).
# ---------------------------------------------------------------------------


def run_with_adapter_retries(call, *, attempts: int, view=None):
    """
    Invoke `call` (a zero-arg callable returning the RLM prediction), retrying
    up to `attempts` times when DSPy's adapter can't parse the model output.

    AdapterParseError is raised by ChatAdapter/JSONAdapter when the LM returns
    text that doesn't match the signature's expected field markers. Retrying
    the whole RLM call gives the model a fresh shot; most transient format
    drift clears on the second attempt.
    """
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
            # Bust the DSPy diskcache so the next attempt gets a fresh
            # LLM response instead of replaying the identical failure.
            # DSPy caches by request content; setting a unique rollout_id
            # or nudging temperature changes the cache key.
            try:
                lm = dspy.settings.lm
                if lm is not None:
                    lm.kwargs["temperature"] = 0.01 * attempt
            except Exception:
                pass
    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# 4. Build the RLM
# ---------------------------------------------------------------------------


def build_rlm(
    max_iterations: int = 12,
    interpreter_mode: str = "docker",
    view: Optional["LiveView"] = None,
) -> dspy.RLM:
    tools = [
        search_vulnerabilities,
        get_cve_details,
        search_critical_remote,
        search_kev_vulnerabilities,
        search_recent_vulnerabilities,
        analyze_severity_distribution,
    ]
    interpreter = build_interpreter(interpreter_mode, tools)
    if view is not None:
        interpreter = _WrappedInterpreter(interpreter, view)
    return dspy.RLM(
        VulnerabilityReportSignature,
        tools=tools,
        max_iterations=max_iterations,
        interpreter=interpreter,
    )


# ---------------------------------------------------------------------------
# 3b. Live TUI view — Rich dashboard showing every RLM step as it happens
# ---------------------------------------------------------------------------
#
# When --live is passed we build a dashboard that renders:
#   - a header with target / iteration / elapsed
#   - a scrolling log of events (LM calls, code exec, observations, errors)
#
# Two entry points feed events:
#   - LiveCallback    — subclass of dspy.utils.callback.BaseCallback, captures
#                       LM and tool calls driven by DSPy itself.
#   - _WrappedInterpreter — decorator around the CodeInterpreter, captures
#                       each execute(code) call and its observation.

import time
from collections import deque
from contextlib import contextmanager
from typing import Any, Iterator

from dspy.utils.callback import BaseCallback


class LiveView:
    """
    A Rich Live dashboard. Push events via `log(kind, text)` — they render
    in order with icons and colour-coded by kind. Context-manager friendly.

    kinds:
      'lm-start' 🧠   — LLM request issued
      'lm-end'   💬   — LLM response received
      'code'     ▶    — interpreter executing generated code
      'obs'      ✓    — code execution observation
      'tool'     🔧   — tool call (captured via callback)
      'error'    ⚠    — exception during a step
      'info'     •    — generic info
    """

    _ICONS = {
        "lm-start": ("🧠", "cyan"),
        "lm-end": ("💬", "bright_cyan"),
        "code": ("▶", "yellow"),
        "obs": ("✓", "green"),
        "tool": ("🔧", "magenta"),
        "error": ("⚠", "red"),
        "info": ("•", "white"),
    }

    def __init__(self, target: str, max_events: int = 200):
        from rich.console import Console  # noqa: F401 — verify Rich presence

        self._target = target
        self._events: deque = deque(maxlen=max_events)
        self._iter = 0
        self._started = time.time()
        self._live = None

    # public API ---------------------------------------------------------------

    def log(self, kind: str, text: str) -> None:
        self._events.append((time.time(), kind, text))
        if self._live is not None:
            self._live.update(self._render())

    def bump_iteration(self) -> int:
        self._iter += 1
        return self._iter

    # rendering ----------------------------------------------------------------

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
        log.add_column(width=8, no_wrap=True)   # time
        log.add_column(width=3, no_wrap=True)   # icon
        log.add_column(ratio=1)                 # body

        for ts, kind, text in self._events:
            icon, colour = self._ICONS.get(kind, ("•", "white"))
            dt = ts - self._started
            log.add_row(
                Text(f"{dt:6.2f}s", style="dim"),
                Text(icon, style=colour),
                Text(text, style=colour, overflow="ellipsis", no_wrap=False),
            )

        return Group(header, Panel(log, title="events", border_style="blue"))

    # context manager ----------------------------------------------------------

    def __enter__(self) -> "LiveView":
        from rich.live import Live

        self._live = Live(
            self._render(),
            refresh_per_second=8,
            screen=False,
            transient=False,
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
        self._view.log("lm-start", f"→ LLM call ({getattr(instance, 'model', '?')})")

    def on_lm_end(self, call_id, outputs, exception):  # noqa: ARG002
        if exception:
            self._view.log("error", f"LLM error: {exception}")
        else:
            self._view.log("lm-end", "← LLM response received")

    def on_tool_start(self, call_id, instance, inputs):  # noqa: ARG002
        name = getattr(instance, "name", None) or type(instance).__name__
        args_preview = json.dumps(inputs, default=str)[:120]
        self._view.log("tool", f"{name}({args_preview})")

    def on_tool_end(self, call_id, outputs, exception):  # noqa: ARG002
        if exception:
            self._view.log("error", f"tool error: {exception}")


class _WrappedInterpreter:
    """
    Thin proxy over a CodeInterpreter that pushes execute() events into a
    LiveView. Keeps the original interpreter's protocol intact (tools
    property, execute(code, variables=...), shutdown()).
    """

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
        # Forward any other attributes (output_fields, _tools_registered, …)
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
        obs_preview = str(result)[:200].replace("\n", " ⏎ ")
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
        print("[live] Rich not available — falling back to plain stdout.")
        yield None
        return
    with view:
        yield view


# ---------------------------------------------------------------------------
# 4. LM factory — Anthropic / OpenAI / custom endpoint
# ---------------------------------------------------------------------------

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
    # OpenRouter — any model available on openrouter.ai/models
    "or-sonnet": "openrouter/anthropic/claude-sonnet-4",
    "or-opus": "openrouter/anthropic/claude-opus-4",
    "or-gpt-4o": "openrouter/openai/gpt-4o",
    "or-llama-3.3-70b": "openrouter/meta-llama/llama-3.3-70b-instruct",
    "or-deepseek": "openrouter/deepseek/deepseek-chat",
    "or-qwen-72b": "openrouter/qwen/qwen-2.5-72b-instruct",
    # OpenCode Go — free API for Chinese models
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

# OpenCode Go endpoint — free OpenAI-compatible API for Chinese models
_OPENCODE_GO_BASE_URL = "https://opencode.ai/zen/go/v1"


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
    """
    Ensure the base URL ends with /v1.
    Most local servers (LM Studio, Ollama, vLLM) serve the OpenAI-compatible
    API at /v1, but users commonly omit it. litellm requires the /v1 suffix
    to route requests correctly.
    """
    url = url.rstrip("/")
    if not url.endswith("/v1"):
        url = f"{url}/v1"
    return url


REASONING_CHOICES = ("auto", "off", "low", "medium", "high")


def _reasoning_kwargs(reasoning: str, provider: str) -> dict:
    """
    Translate a reasoning setting into provider-specific kwargs for dspy.LM.

      auto            — no kwargs (provider default)
      off             — disable reasoning/thinking where the provider allows it
      low|medium|high — cross-provider reasoning_effort (OpenAI/OpenRouter),
                        also forwarded to custom OpenAI-compat endpoints which
                        mostly ignore unknown params.

    For LM Studio / vLLM serving Qwen3-family models, the canonical "off"
    switch is extra_body={"chat_template_kwargs": {"enable_thinking": False}}.
    """
    if reasoning == "auto":
        return {}

    if reasoning == "off":
        # Qwen3 / vLLM / LM Studio — disable thinking via chat_template_kwargs.
        # Harmless for servers that ignore it.
        if provider in ("custom", "openrouter"):
            return {
                "extra_body": {
                    "chat_template_kwargs": {"enable_thinking": False},
                    "enable_thinking": False,
                }
            }
        # OpenAI reasoning models (o1/o3) can't be disabled — use lowest effort.
        if provider == "openai":
            return {"reasoning_effort": "low"}
        return {}

    # low / medium / high
    kwargs: dict = {"reasoning_effort": reasoning}
    if provider in ("custom", "openrouter"):
        # Also flip the Qwen3 toggle on so a server defaulting to off wakes up.
        kwargs["extra_body"] = {
            "chat_template_kwargs": {"enable_thinking": True},
            "enable_thinking": True,
        }
    return kwargs


# ── OpenRouter interactive key prompt ────────────────────────────────────────
# If OPENROUTER_API_KEY is missing we open the OpenRouter keys page in a
# private/incognito browser window and wait for the user to paste their key
# on stdin. No OAuth, no callback server — just a prompt.


def _open_in_private_window(url: str) -> None:
    """
    Best-effort: open URL in a private/incognito window on macOS.
    Tries Chrome → Firefox → Edge → default browser.
    """
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
    """
    Pop a private browser window to OpenRouter's keys page and read the key
    from stdin. Returns the key (also sets OPENROUTER_API_KEY for the process).
    """
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
    """
    Build a dspy.LM for any supported provider.

    Provider is auto-detected from the model string:
      • Anthropic  — model starts with 'claude-'
      • OpenAI     — model starts with 'openai/', 'gpt-', 'o1', 'o3'
      • OpenRouter — model starts with 'openrouter/'
      • Custom     — anything else; requires --base-url (OpenAI-compatible API)

    Model aliases (short names → full DSPy model string):
      claude-sonnet, claude-opus, claude-haiku,
      gpt-4o, gpt-4o-mini, gpt-4-turbo, o1, o3-mini,
      or-sonnet, or-opus, or-gpt-4o, or-llama-3.3-70b, or-deepseek, or-qwen-72b

    Base URL normalisation:
      /v1 is appended automatically if missing, so both work:
        --base-url http://192.168.50.27:1234
        --base-url http://192.168.50.27:1234/v1
    """
    resolved = MODEL_ALIASES.get(model, model)
    provider = _detect_provider(resolved)
    reasoning_kw = _reasoning_kwargs(reasoning, provider)

    # ── Anthropic ────────────────────────────────────────────────────────────
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

    # ── OpenAI ───────────────────────────────────────────────────────────────
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

    # ── OpenRouter ───────────────────────────────────────────────────────────
    # Any model listed at https://openrouter.ai/models, referenced as
    # 'openrouter/<provider>/<model>' (e.g. openrouter/anthropic/claude-sonnet-4).
    # litellm handles routing natively when it sees the 'openrouter/' prefix.
    elif provider == "openrouter":
        key = api_key or os.environ.get("OPENROUTER_API_KEY")
        if not key:
            # No key on disk/env — prompt interactively.
            key = _prompt_openrouter_key()
        kwargs = dict(model=resolved, api_key=key, max_tokens=max_tokens, num_retries=num_retries, **reasoning_kw)
        # Custom base_url lets users point at an OpenRouter-compatible proxy.
        if base_url:
            kwargs["api_base"] = _normalize_base_url(base_url)
        print(f"[+] LM  : OpenRouter / {resolved.removeprefix('openrouter/')}")

    # ── OpenCode Go — free API for Chinese models (GLM, Kimi, MiMo, Qwen) ──
    elif provider == "opencode-go":
        # Model string: "opencode-go/glm-5.1" → model_id "glm-5.1"
        model_id = resolved.removeprefix("opencode-go/")
        key = (
            api_key
            or os.environ.get("OPENCODE_API_KEY")
            or os.environ.get("OPENAI_API_KEY", "none")
        )
        # MiniMax uses Anthropic-style /messages endpoint; others use
        # OpenAI-compatible /chat/completions. litellm routes based on
        # the model prefix.
        _minimax_models = ("minimax-m2.7", "minimax-m2.5")
        if model_id in _minimax_models:
            model_str = f"anthropic/{model_id}"
            # litellm's Anthropic handler appends /v1/messages to api_base,
            # so strip the trailing /v1 to avoid /v1/v1/messages
            api_base = base_url or _OPENCODE_GO_BASE_URL.removesuffix("/v1")
        else:
            model_str = f"openai/{model_id}"
            api_base = base_url or _OPENCODE_GO_BASE_URL
        kwargs = dict(
            model=model_str,
            api_key=key,
            api_base=api_base,
            max_tokens=max_tokens,
            num_retries=num_retries,
            drop_params=True,
            **reasoning_kw,
        )
        print(f"[+] LM  : OpenCode Go / {model_id}")

    # ── Custom / OpenAI-compatible endpoint (LM Studio, Ollama, vLLM, …) ────
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
        # DSPy/litellm needs the 'openai/' prefix to route through the
        # OpenAI-compatible code path for unknown model names.
        model_str = resolved if "/" in resolved else f"openai/{resolved}"
        kwargs = dict(
            model=model_str,
            api_key=key,
            api_base=normalized_url,
            max_tokens=max_tokens,
            num_retries=num_retries,
            drop_params=True,
            **reasoning_kw,
        )
        print(f"[+] LM  : Custom endpoint ({normalized_url}) / {resolved}")

    if base_url and provider != "custom":
        print(f"[+] Base: {_normalize_base_url(base_url)}")

    kwargs["cache"] = cache
    if not cache:
        print("[+] Cache: disabled")
    return dspy.LM(**kwargs)


# ---------------------------------------------------------------------------
# 5. Runner
# ---------------------------------------------------------------------------


def generate_report(
    target: str,
    output_file: Optional[str] = None,
    model: str = "claude-sonnet",
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    max_iterations: int = 12,
    interpreter_mode: str = "docker",
    trace: bool = False,
    phoenix_endpoint: str = "http://localhost:6006/v1/traces",
    reasoning: str = "auto",
    live: bool = False,
    toon: bool = False,
    retries: int = 5,
) -> dict:
    global _USE_TOON
    _USE_TOON = toon
    if toon:
        print("[+] TOON: vulnx JSON → TOON encoding enabled (token saver).")

    lm = build_lm(
        model=model,
        api_key=api_key,
        base_url=base_url,
        reasoning=reasoning,
        num_retries=retries,
    )

    if trace or os.environ.get("PHOENIX_ENABLED"):
        resolved_model = MODEL_ALIASES.get(model, model)
        provider = _detect_provider(resolved_model)
        api_base = lm.kwargs.get("api_base") or base_url or ""
        setup_tracing(
            endpoint=phoenix_endpoint,
            resource_attrs={
                "rlm.model": resolved_model,
                "rlm.model_alias": model,
                "rlm.provider": provider,
                "rlm.api_base": api_base,
                "rlm.interpreter": interpreter_mode,
                "rlm.reasoning": reasoning,
                "rlm.toon": str(toon).lower(),
                "rlm.target": target,
            },
        )

    print(f"[+] Target: {target!r}")
    print(f"[+] Interpreter: {interpreter_mode}")
    if live:
        print("[+] Live TUI enabled — press Ctrl+C to abort.")

    with live_view(target=target, enabled=live) as view:
        callbacks = [LiveCallback(view)] if view is not None else []
        dspy.configure(lm=lm, callbacks=callbacks)

        rlm = build_rlm(
            max_iterations=max_iterations,
            interpreter_mode=interpreter_mode,
            view=view,
        )

        if view is None:
            print(
                "[+] Starting RLM — this may take a minute as the agent queries vulnx...\n"
            )
        else:
            view.log("info", "RLM started")
        result = run_with_adapter_retries(
            lambda: rlm(target=target), attempts=retries, view=view
        )
        if view is not None:
            view.log("info", "RLM finished")

    # ---- print trajectory summary ----------------------------------------
    print("\n" + "=" * 60)
    print("AGENT TRAJECTORY SUMMARY")
    print("=" * 60)
    for i, step in enumerate(result.trajectory, 1):
        reasoning = step.get("reasoning", "")[:120].replace("\n", " ")
        code_preview = step.get("code", "")[:80].replace("\n", " ")
        print(f"  Step {i:02d}: {reasoning}...")
        if code_preview:
            print(f"          > {code_preview}...")
    print("=" * 60)

    # ---- save report -------------------------------------------------------
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(" ", "_").replace("/", "-")[:40]
    filename = output_file or f"vuln_report_{safe_target}_{timestamp}.md"

    with open(filename, "w") as f:
        f.write(f"# Vulnerability Report: {target}\n")
        f.write(f"_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_\n\n")
        f.write(f"**Executive Summary:** {result.executive_summary}\n\n")
        f.write("---\n\n")
        f.write(result.report)

    print(f"\n[+] Report saved → {filename}")
    flush_tracing()
    return {
        "target": target,
        "report_file": filename,
        "executive_summary": result.executive_summary,
        "trajectory_steps": len(result.trajectory),
    }


# ---------------------------------------------------------------------------
# 6. CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="DSPy RLM Vulnerability Report Generator (uses vulnx)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Provider & model examples:
  # Anthropic (default)
  python poc.py apache
  python poc.py apache --model claude-sonnet
  python poc.py apache --model claude-opus

  # OpenAI
  python poc.py apache --model gpt-4o
  python poc.py apache --model gpt-4o-mini --api-key sk-...

  # OpenRouter (set OPENROUTER_API_KEY or pass --api-key)
  python poc.py apache --model or-sonnet
  python poc.py apache --model or-llama-3.3-70b
  python poc.py apache --model openrouter/deepseek/deepseek-chat

  # Custom / OpenAI-compatible endpoint (Ollama, LiteLLM, vLLM, Azure, …)
  python poc.py apache --model llama3.3 --base-url http://localhost:11434/v1
  python poc.py apache --model my-model  --base-url https://my-proxy.example.com/v1 --api-key ...

  # Interpreter selection
  python poc.py apache                         # docker (default)
  python poc.py apache --interpreter docker    # explicit docker
  python poc.py apache --interpreter local     # in-process exec, no sandbox
  python poc.py apache --interpreter deno      # Pyodide/WASM sandbox (needs deno)

  # Other options
  python poc.py log4j --output log4j_report.md
  python poc.py "vmware esxi" --iterations 18
  python poc.py apache --model or-sonnet --toon      # shrink tool JSON via TOON

Supported model aliases:
  claude-sonnet (default), claude-opus, claude-haiku
  gpt-4o, gpt-4o-mini, gpt-4-turbo, o1, o3-mini
  or-sonnet, or-opus, or-gpt-4o, or-llama-3.3-70b, or-deepseek, or-qwen-72b
  (or pass any full DSPy model string, e.g. 'openai/gpt-4o',
   'openrouter/anthropic/claude-sonnet-4')
        """,
    )
    parser.add_argument("target", help="Product/vendor/tech to research")
    parser.add_argument(
        "--model",
        "-m",
        default="claude-sonnet",
        help="Model alias or full DSPy model string (default: claude-sonnet)",
    )
    parser.add_argument(
        "--api-key",
        "-k",
        default=None,
        help="API key (overrides env vars ANTHROPIC_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY / CUSTOM_API_KEY)",
    )
    parser.add_argument(
        "--base-url",
        "-u",
        default=None,
        help="Custom base URL for OpenAI-compatible endpoints (Ollama, LiteLLM, vLLM, Azure, …)",
    )
    parser.add_argument("-o", "--output", help="Output Markdown file path")
    parser.add_argument(
        "-i",
        "--iterations",
        type=int,
        default=12,
        help="Max RLM iterations (default: 12)",
    )
    parser.add_argument(
        "--interpreter",
        choices=["docker", "local", "deno"],
        default="docker",
        help=(
            "Code execution backend: 'docker' (isolated container, default), "
            "'local' (in-process exec, no sandbox), or 'deno' (Pyodide/WASM "
            "sandbox via DSPy's built-in PythonInterpreter — requires Deno)"
        ),
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Enable Arize Phoenix OTEL tracing (start Phoenix separately: `uv run phoenix serve`)",
    )
    parser.add_argument(
        "--phoenix-endpoint",
        default="http://localhost:6006/v1/traces",
        help="Phoenix OTLP/HTTP traces endpoint (default: http://localhost:6006/v1/traces)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Show a Rich TUI dashboard of RLM steps in real time",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=5,
        help=(
            "How many times to retry on failure. Applies to both LiteLLM "
            "transport errors (rate limits, 5xx) and DSPy adapter parse "
            "failures when a weak model returns malformed output. Default: 5."
        ),
    )
    parser.add_argument(
        "--toon",
        action="store_true",
        help=(
            "Convert vulnx JSON responses to TOON v3 notation before handing "
            "them to the LLM. Tabular arrays compress especially well — "
            "typical token savings are ~40-60%% on vulnx search/id output."
        ),
    )
    parser.add_argument(
        "--reasoning",
        choices=list(REASONING_CHOICES),
        default="auto",
        help=(
            "Reasoning/thinking mode: 'auto' (provider default), 'off' (disable; "
            "sets chat_template_kwargs.enable_thinking=false for LM Studio/vLLM), "
            "'low'|'medium'|'high' (reasoning_effort for OpenAI/OpenRouter)."
        ),
    )
    args = parser.parse_args()

    try:
        meta = generate_report(
            target=args.target,
            output_file=args.output,
            model=args.model,
            api_key=args.api_key,
            base_url=args.base_url,
            max_iterations=args.iterations,
            interpreter_mode=args.interpreter,
            trace=args.trace,
            phoenix_endpoint=args.phoenix_endpoint,
            reasoning=args.reasoning,
            live=args.live,
            toon=args.toon,
            retries=args.retries,
        )
    except ValueError as e:
        print(f"[!] Configuration error: {e}")
        sys.exit(1)

    print(f"\n✓ Done in {meta['trajectory_steps']} agent steps.")
    print(f"  Summary: {meta['executive_summary']}")
