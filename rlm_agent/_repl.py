import subprocess, json, os, sys, yaml, re
from typing import Optional
from pathlib import Path
os.environ['RLM_ANSIBLE_DIR'] = '/ansible_configs'
sys.path.insert(0, '/sandbox')
# --- ansible_tools.py ---
"""
Ansible config access tools for the RLM.

The directory to mine is selected via the RLM_ANSIBLE_DIR env var (absolute
or resolved against the current working directory). The RLM never sees the
full directory contents in its prompt — it calls list_ansible_files() to
discover them and read_ansible_file() to load a specific one.

Return values are **native Python objects** (lists, dicts, strings), not
JSON-encoded strings, so the RLM-generated Python can index them directly
(e.g. `for f in list_ansible_files(): read_ansible_file(f['path'])`).

Read-only. Symlinks out of the root are rejected.
"""

import os
from pathlib import Path
from typing import Optional


ANSIBLE_DIR_ENV = "RLM_ANSIBLE_DIR"
_TEXT_EXTS = {".yml", ".yaml", ".ini", ".cfg", ".j2", ".txt", ".md"}
_MAX_BYTES = 256 * 1024  # 256 KiB — don't flood the LLM with a binary dump


def _root() -> Path:
    raw = os.environ.get(ANSIBLE_DIR_ENV)
    if not raw:
        raise RuntimeError(
            f"{ANSIBLE_DIR_ENV} is not set. "
            "Point it at the Ansible directory before starting the RLM, e.g.\n"
            "  export RLM_ANSIBLE_DIR=$(pwd)/ansible_configs"
        )
    p = Path(raw).expanduser().resolve()
    if not p.is_dir():
        raise RuntimeError(f"{ANSIBLE_DIR_ENV}={raw} is not a directory.")
    return p


def _safe_join(rel: str) -> Path:
    """Join rel onto the root, refusing any path that escapes it."""
    root = _root()
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise RuntimeError(f"Path {rel!r} escapes {ANSIBLE_DIR_ENV}.") from None
    return candidate


def list_ansible_files(subdir: Optional[str] = None) -> list:
    """
    List Ansible-relevant text files under RLM_ANSIBLE_DIR (or a subdir).

    Returns a list of {'path': <str relative>, 'size': <int bytes>} dicts.
    On configuration errors (env var missing, path escape), raises
    RuntimeError so the caller sees a clean stack trace.

    Args:
        subdir: optional subdirectory relative to RLM_ANSIBLE_DIR
    """
    root = _root()
    base = _safe_join(subdir) if subdir else root
    entries: list = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in _TEXT_EXTS:
            continue
        entries.append(
            {"path": str(path.relative_to(root)), "size": path.stat().st_size}
        )
    return entries


def read_ansible_file(path: str) -> str:
    """
    Read a single Ansible file relative to RLM_ANSIBLE_DIR.

    Returns the file's text content as a string (truncated with a marker
    comment if above the safety limit). Raises RuntimeError for missing
    files or path escapes.

    Args:
        path: path relative to RLM_ANSIBLE_DIR (e.g. 'roles/webserver/tasks/main.yml')
    """
    target = _safe_join(path)
    if not target.is_file():
        raise RuntimeError(f"Not a file: {path}")
    size = target.stat().st_size
    with target.open("rb") as f:
        blob = f.read(_MAX_BYTES + 1)
    truncated = len(blob) > _MAX_BYTES
    text = blob[:_MAX_BYTES].decode("utf-8", errors="replace")
    if truncated:
        text += f"\n\n# …truncated at {_MAX_BYTES} bytes of {size}…\n"
    return text


ANSIBLE_TOOLS = [list_ansible_files, read_ansible_file]

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
    Shortcut: find critical, remotely-exploitable vulnerabilities for a product.
    Equivalent to: vulnx search '<product> && severity:critical && is_remote:true'
    sorted by CVSS score descending.

    Args:
        product: product or vendor name (e.g. 'nginx', 'microsoft', 'log4j')
        limit:   max results to return (default 10)
    """
    query = f"{product} && severity:critical && is_remote:true"
    return _run_vulnx(
        "search", query, "--limit", str(limit), "--sort-desc", "cvss_score"
    )

def search_kev_vulnerabilities(product: str, limit: int = 10) -> str:
    """
    Find Known Exploited Vulnerabilities (KEV) for a given product.
    KEV entries are confirmed to be actively exploited in the wild.
    Returns JSON list sorted by CVSS score.

    Args:
        product: product or technology name (e.g. 'apache', 'vmware')
        limit:   max results to return (default 10)
    """
    query = f"{product} && is_kev:true"
    return _run_vulnx(
        "search", query, "--limit", str(limit), "--sort-desc", "cvss_score"
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
                     f"yaml={yaml.__name__}, tools ok\n")
    sys.stderr.flush()
except Exception as _e:
    sys.stderr.write(f"[repl] warning: tool self-test failed: {_e}\n")
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
            output = "ERROR:\n" + traceback.format_exc()
        print(json.dumps({"output": output or "(no output)"}), flush=True)
    elif msg.get("method") == "shutdown":
        break
    else:
        print(json.dumps({"error": "unknown method"}), flush=True)
