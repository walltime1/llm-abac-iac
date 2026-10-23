"""Code interpreters for DSPy RLM execution (Docker, Local, Deno)."""

import inspect
import json
import os
import subprocess
import uuid
from typing import Optional

from dspy.predict.rlm import CodeInterpreter

from rlm_agent.vulnx_tools import _run_vulnx


class DockerPythonInterpreter(CodeInterpreter):
    """Executes RLM-generated code inside a persistent Docker container.

    The container runs a REPL process (_repl.py) that accepts JSON-RPC
    commands over stdin/stdout. Tool modules (ansible_tools.py, vulnx
    tool functions) are copied as files into the container.
    """

    IMAGE_TAG = "rlm-abac-sandbox:latest"
    _image_built = False

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
        tool_source_lines = [
            "import subprocess, json, os, sys, yaml, re\n"
            "from typing import Optional\nfrom pathlib import Path"
        ]
        tool_source_lines.append("os.environ['RLM_ANSIBLE_DIR'] = '/ansible_configs'")
        tool_source_lines.append("sys.path.insert(0, '/sandbox')")
        for module_file in ["ansible_tools.py"]:
            module_path = os.path.join(self._dockerfile_dir, module_file)
            if os.path.exists(module_path):
                tool_source_lines.append(f"# --- {module_file} ---")
                tool_source_lines.append(open(module_path).read())
        tool_source_lines.append(inspect.getsource(_run_vulnx))
        for fn in self._user_tool_fns:
            if fn.__module__ == "ansible_tools":
                continue
            try:
                tool_source_lines.append(inspect.getsource(fn))
            except (OSError, TypeError):
                pass
        repl_code = "\n".join(tool_source_lines) + "\n" + '''
import io, contextlib, traceback

_globals = {}
_globals["__builtins__"] = __builtins__

import yaml, json, re, os, sys
for _mod_name, _mod in [("yaml", yaml), ("json", json), ("re", re),
                         ("os", os), ("sys", sys)]:
    _globals[_mod_name] = _mod

for _name, _obj in list(globals().items()):
    if callable(_obj) and not _name.startswith("_"):
        _globals[_name] = _obj
for _name in ["_root", "_safe_join", "_run_vulnx", "_TEXT_EXTS", "_MAX_BYTES",
              "ANSIBLE_DIR_ENV"]:
    if _name in globals():
        _globals[_name] = globals()[_name]

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


class _SubmitCalled(BaseException):
    """Raised by SUBMIT() inside exec() to signal early exit with FinalOutput."""
    def __init__(self, final_output):
        self.final_output = final_output


class LocalPythonInterpreter(CodeInterpreter):
    """Runs RLM code directly in the current Python process via exec().
    No Docker or Deno required. Not sandboxed.
    """

    def __init__(self, tools: list):
        self._tools: dict = {}
        self._output_fields: list[dict] = []
        self._globals: dict = {fn.__name__: fn for fn in tools}
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
        from dspy.primitives.code_interpreter import FinalOutput
        def SUBMIT(**kwargs):
            raise _SubmitCalled(FinalOutput(kwargs))
        self._globals["SUBMIT"] = SUBMIT

    def execute(self, code: str, variables: Optional[dict] = None):
        import io, contextlib, traceback

        buf = io.StringIO()
        local_vars: dict = {}
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


def _bootstrap_deno_pyodide() -> None:
    """Pre-cache Deno/Pyodide dependencies for DSPy's WASM sandbox."""
    marker = os.path.expanduser("~/.cache/rlm-poc/deno_pyodide.cached")
    if os.path.exists(marker):
        return

    print("[deno] Warming pyodide cache (first run, ~20-30s)...")
    cmd = [
        "deno", "cache", "--node-modules-dir=none",
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
    """Return DSPy's built-in Pyodide/Deno sandbox (WASM-isolated Python)."""
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

    from dspy.primitives.python_interpreter import PythonInterpreter

    pi = PythonInterpreter(
        enable_network_access=["cdn.jsdelivr.net", "pypi.org", "files.pythonhosted.org"],
    )
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
