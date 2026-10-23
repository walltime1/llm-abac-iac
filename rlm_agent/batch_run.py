"""
Batch runner for ABAC policy mining.

Reads a JSON/YAML config specifying models × ansible dirs × run count,
then executes mine_policy() for each combination. API models run in
parallel via ProcessPoolExecutor; local models run sequentially.

A Rich live dashboard shows all runs with their current status.

Usage:
  python batch_run.py --config batch_config.json
  python batch_run.py --config batch_config.json --dry-run
"""

import argparse
import json
import os
import sys
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

sys.setrecursionlimit(10000)

try:
    import yaml
except ImportError:
    yaml = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


def _load_config(path: str) -> dict:
    text = Path(path).read_text()
    if yaml is not None:
        return yaml.safe_load(text)
    return json.loads(text)


def _is_local(model: str) -> bool:
    return not any(
        model.startswith(p)
        for p in ("openrouter/", "claude-", "gpt-", "o1", "o3")
    ) and "/" not in model


# ── Shared state for cross-process status updates ──────────────────────────

def _make_status_table(run_states: dict, total: int) -> Table:
    """Build a Rich table showing all run statuses."""
    table = Table(title=f"Batch Runner — {total} runs", expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Model", width=30)
    table.add_column("Ansible Dir", width=18)
    table.add_column("Run", width=5)
    table.add_column("Status", width=12)
    table.add_column("Steps", width=6)
    table.add_column("Rules", width=6)
    table.add_column("CVEs", width=5)
    table.add_column("Time", width=8)
    table.add_column("Output", width=30)

    for idx in sorted(run_states.keys()):
        s = run_states[idx]
        status = s.get("status", "pending")
        if status == "running":
            style = "yellow"
            status_text = f"iter {s.get('step', '?')}"
        elif status == "ok":
            style = "green"
            status_text = "done"
        elif status == "error":
            style = "red"
            status_text = "FAIL"
        else:
            style = "dim"
            status_text = "pending"

        elapsed = s.get("elapsed", "")
        table.add_row(
            str(idx + 1),
            s.get("model", "")[:30],
            s.get("dir", "")[:18],
            str(s.get("run", "")),
            Text(status_text, style=style),
            str(s.get("steps", "")),
            str(s.get("rules", "")),
            str(s.get("cves", "")),
            elapsed,
            s.get("output", "")[-30:],
        )
    return table


def _run_one(
    task_idx: int,
    model: str,
    ansible_dir: str,
    run_index: int,
    total_runs: int,
    config: dict,
    status_dict: dict = None,
) -> dict:
    """Execute a single mine_policy run."""
    from rlm_agent.abac_poc import mine_policy
    import time

    start = time.time()

    if status_dict is not None:
        status_dict[task_idx] = {
            "model": model, "dir": Path(ansible_dir).name,
            "run": run_index, "status": "running", "step": 0,
            "steps": "", "rules": "", "cves": "", "elapsed": "", "output": "",
        }

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_model = model.replace("/", "_").replace(":", "_")[:40]
    safe_dir = Path(ansible_dir).name[:20]
    Path("reports").mkdir(exist_ok=True)
    output_file = f"reports/batch_{safe_model}_{safe_dir}_{ts}_r{run_index}.abac.md"

    defaults = config.get("defaults", {})
    try:
        meta = mine_policy(
            policy_goal=defaults.get("policy_goal", "all"),
            ansible_dir=ansible_dir,
            output_file=output_file,
            model=model,
            api_key=defaults.get("api_key"),
            base_url=defaults.get("base_url"),
            max_iterations=defaults.get("max_iterations", 15),
            interpreter_mode=defaults.get("interpreter", "deno"),
            trace=defaults.get("trace", True),
            phoenix_project=defaults.get("phoenix_project", "rlm-abac-poc"),
            reasoning=defaults.get("reasoning", "auto"),
            live=False,
            retries=defaults.get("retries", 5),
            max_tokens=defaults.get("max_tokens", 16000),
            cache=not defaults.get("no_cache", False),
            phase_order=defaults.get("phase_order", "eager"),
        )
        elapsed = f"{time.time() - start:.0f}s"
        meta["output_file"] = output_file
        meta["model"] = model
        meta["ansible_dir"] = ansible_dir
        meta["run_index"] = run_index
        meta["status"] = "ok"
        meta["elapsed"] = elapsed

        if status_dict is not None:
            status_dict[task_idx] = {
                "model": model, "dir": Path(ansible_dir).name,
                "run": run_index, "status": "ok",
                "steps": meta.get("trajectory_steps", "?"),
                "rules": meta.get("policy_file", "?"),
                "cves": "", "elapsed": elapsed,
                "output": output_file,
            }
        return meta

    except Exception as e:
        elapsed = f"{time.time() - start:.0f}s"
        meta = {
            "output_file": output_file,
            "model": model,
            "ansible_dir": ansible_dir,
            "run_index": run_index,
            "status": "error",
            "error": str(e)[:200],
            "elapsed": elapsed,
        }
        if status_dict is not None:
            status_dict[task_idx] = {
                "model": model, "dir": Path(ansible_dir).name,
                "run": run_index, "status": "error",
                "steps": "", "rules": "", "cves": "",
                "elapsed": elapsed, "output": str(e)[:50],
            }
        return meta


def _run_one_process(args):
    """Wrapper for ProcessPoolExecutor (can't pickle status_dict)."""
    task_idx, model, ansible_dir, run_index, total_runs, config = args
    # Restore env vars that may not propagate to child processes
    env_vars = config.get("_env", {})
    for k, v in env_vars.items():
        if v:
            os.environ[k] = v
    return _run_one(task_idx, model, ansible_dir, run_index, total_runs, config)


def run_batch(config: dict, dry_run: bool = False):
    models = config.get("models", [])
    ansible_dirs = config.get("ansible_dirs", [])
    runs_per_combo = config.get("runs", 1)
    defaults = config.get("defaults", {})
    max_parallel = defaults.get("max_parallel", 3)

    # Build run list
    tasks = []
    for model in models:
        for ansible_dir in ansible_dirs:
            for run_idx in range(1, runs_per_combo + 1):
                tasks.append((model, ansible_dir, run_idx, runs_per_combo))

    console = Console() if HAS_RICH else None

    if console:
        console.print(f"\n[bold]Batch Runner[/bold] — {len(tasks)} runs planned\n")
        plan_table = Table(show_header=True)
        plan_table.add_column("Setting", style="dim")
        plan_table.add_column("Value")
        plan_table.add_row("Models", ", ".join(models))
        plan_table.add_row("Ansible dirs", ", ".join(str(Path(d).name) for d in ansible_dirs))
        plan_table.add_row("Runs per combo", str(runs_per_combo))
        plan_table.add_row("Interpreter", defaults.get("interpreter", "deno"))
        plan_table.add_row("Max iterations", str(defaults.get("max_iterations", 15)))
        plan_table.add_row("Max parallel", str(max_parallel))
        plan_table.add_row("Cache", "off" if defaults.get("no_cache") else "on")
        plan_table.add_row("Trace", "on" if defaults.get("trace") else "off")
        console.print(plan_table)
        console.print()
    else:
        print(f"[batch] {len(tasks)} runs planned")
        print(f"  Models: {models}")
        print(f"  Dirs:   {ansible_dirs}")
        print(f"  Runs:   {runs_per_combo}")
        print()

    if dry_run:
        for i, (model, adir, ridx, total) in enumerate(tasks):
            local = "LOCAL" if _is_local(model) else "API"
            line = f"  [{local}] #{i+1} {model} × {Path(adir).name} (run {ridx}/{total})"
            if console:
                console.print(line)
            else:
                print(line)
        return []

    local_tasks = [(i, m, a, r, t) for i, (m, a, r, t) in enumerate(tasks) if _is_local(m)]
    api_tasks = [(i, m, a, r, t) for i, (m, a, r, t) in enumerate(tasks) if not _is_local(m)]

    # Capture env vars so child processes can access API keys
    config["_env"] = {
        k: os.environ.get(k, "")
        for k in ["OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                   "CUSTOM_API_KEY", "PDCP_API_KEY", "RLM_ANSIBLE_DIR",
                   "DOCKER_HOST", "HOME", "PATH"]
    }

    # Shared status for Rich display (only works for sequential/main-thread)
    manager = multiprocessing.Manager()
    run_states = manager.dict()
    for i, (m, a, r, t) in enumerate(tasks):
        run_states[i] = {
            "model": m, "dir": Path(a).name, "run": r,
            "status": "pending", "steps": "", "rules": "",
            "cves": "", "elapsed": "", "output": "",
        }

    results = []

    # API tasks — parallel processes
    if api_tasks:
        if console:
            console.print(f"[bold yellow]Running {len(api_tasks)} API tasks (parallel, max {max_parallel})...[/bold yellow]\n")

        pool_args = [
            (idx, m, a, r, t, config) for idx, m, a, r, t in api_tasks
        ]
        # Stagger launches when using deno: start first process, wait
        # for Pyodide to boot (~10s), then launch the rest. Prevents
        # 3 concurrent Pyodide WASM boots from deadlocking.
        is_deno = defaults.get("interpreter", "deno") == "deno"

        with ProcessPoolExecutor(max_workers=max_parallel) as pool:
            if console and HAS_RICH:
                futures = {}
                if is_deno and len(pool_args) > 1:
                    import time
                    # Launch first process
                    first = pool_args[0]
                    futures[pool.submit(_run_one_process, first)] = first[0]
                    run_states[first[0]] = {**run_states[first[0]], "status": "running"}
                    if console:
                        console.print("[dim]Staggering deno launches (waiting 15s for Pyodide boot)...[/dim]")
                    time.sleep(15)
                    # Launch rest
                    for arg in pool_args[1:]:
                        futures[pool.submit(_run_one_process, arg)] = arg[0]
                        run_states[arg[0]] = {**run_states[arg[0]], "status": "running"}
                else:
                    futures = {
                        pool.submit(_run_one_process, arg): arg[0]
                        for arg in pool_args
                    }
                    for arg in pool_args:
                        run_states[arg[0]] = {**run_states[arg[0]], "status": "running"}
                with Live(_make_status_table(dict(run_states), len(tasks)),
                          console=console, refresh_per_second=1) as live:
                    done_futures = set()
                    while len(done_futures) < len(futures):
                        # Poll with short timeout so table refreshes
                        try:
                            for future in as_completed(futures, timeout=5):
                                if future in done_futures:
                                    continue
                                done_futures.add(future)
                                idx = futures[future]
                                try:
                                    meta = future.result()
                                    results.append(meta)
                                    run_states[idx] = {
                                        "model": meta["model"],
                                        "dir": Path(meta["ansible_dir"]).name,
                                        "run": meta["run_index"],
                                        "status": meta["status"],
                                        "steps": meta.get("trajectory_steps", "?"),
                                        "rules": "",
                                        "cves": "",
                                        "elapsed": meta.get("elapsed", ""),
                                        "output": meta.get("output_file", ""),
                                    }
                                except Exception as e:
                                    run_states[idx] = {
                                        **run_states[idx],
                                        "status": "error", "output": str(e)[:50],
                                    }
                                    results.append({
                                        "status": "error", "error": str(e)[:200],
                                        "run_index": idx,
                                    })
                                break  # refresh after each completion
                        except TimeoutError:
                            pass  # no future completed — just refresh
                        live.update(_make_status_table(dict(run_states), len(tasks)))
            else:
                futures = {
                    pool.submit(_run_one_process, arg): arg[0]
                    for arg in pool_args
                }
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        idx = futures[future]
                        results.append({
                            "status": "error", "error": str(e)[:200],
                            "run_index": idx,
                        })

    # Local tasks — sequential with live status
    if local_tasks:
        if console:
            console.print(f"\n[bold cyan]Running {len(local_tasks)} local tasks (sequential)...[/bold cyan]\n")
        for idx, m, a, r, t in local_tasks:
            meta = _run_one(idx, m, a, r, t, config, run_states)
            results.append(meta)

    # Summary
    if console:
        console.print()
        summary = Table(title="Batch Results", expand=True)
        summary.add_column("#", style="dim", width=3)
        summary.add_column("Model", width=30)
        summary.add_column("Dir", width=18)
        summary.add_column("Run", width=4)
        summary.add_column("Status", width=8)
        summary.add_column("Steps", width=6)
        summary.add_column("Time", width=8)
        summary.add_column("Output", width=40)
        for i, r in enumerate(results):
            status = r.get("status", "?")
            style = "green" if status == "ok" else "red"
            summary.add_row(
                str(i + 1),
                r.get("model", "?")[:30],
                Path(r.get("ansible_dir", "?")).name[:18],
                str(r.get("run_index", "?")),
                Text(status, style=style),
                str(r.get("trajectory_steps", "?")),
                r.get("elapsed", "?"),
                r.get("output_file", r.get("error", "?"))[:40],
            )
        console.print(summary)
        ok = sum(1 for r in results if r.get("status") == "ok")
        fail = sum(1 for r in results if r.get("status") == "error")
        console.print(f"\n  [green]{ok} ok[/green], [red]{fail} failed[/red], {len(results)} total")
    else:
        print(f"\n{'='*60}")
        print("BATCH SUMMARY")
        print(f"{'='*60}")
        for r in results:
            status = "ok" if r.get("status") == "ok" else "FAIL"
            print(f"  [{status}] {r.get('model','?')[:35]} → {r.get('output_file', r.get('error','?'))}")

    # Write results JSON
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = f"batch_results_{ts}.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    if console:
        console.print(f"  Results → [bold]{results_file}[/bold]")
    else:
        print(f"  Results → {results_file}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batch ABAC policy mining runner")
    parser.add_argument("--config", "-c", required=True, help="YAML/JSON config file")
    parser.add_argument("--dry-run", action="store_true", help="Show planned runs without executing")
    args = parser.parse_args()

    config = _load_config(args.config)
    run_batch(config, dry_run=args.dry_run)
