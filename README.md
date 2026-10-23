# LLM-assisted ABAC mining from Ansible IaC: code and raw results

This repository contains the code used to run the evaluation and the raw outputs it produced. It has no paper drafts or analysis notes.

## Layout

```
pyproject.toml, uv.lock, .python-version   Python project and pinned dependencies
rlm_agent/                                  Pipeline code (see below)
scripts/compute_cis.py                      Wilson confidence intervals for the reported rates
export_data/                                Raw evaluation data (see below)
```

### `rlm_agent/` (code)

| Path | Purpose |
|---|---|
| `poc.py`, `abac_poc.py`, `normalize_to_ir.py` | RLM agent: reads Ansible files, emits the ABAC policy report (`python -m rlm_agent.poc` runs the vulnx report PoC) |
| `abac_encoder.py`, `encoder/` | Parses the report and compiles it to Z3 μZ Datalog (`parser.py`, `catalog.py`, `nvd.py`) |
| `eval_scorer.py`, `dump_per_query.py` | Score run reports against ground truth |
| `batch_run.py`, `cli/` | Batch runner and CLI entry points (`abac.py`, `batch.py`, `encode.py`) |
| `vulnx_tools.py`, `ansible_tools.py`, `lm.py`, `retry.py`, `tracing.py` | Tool wrappers, LM client, retries, Phoenix tracing |
| `ir_schema.json`, `ir/` | Schema and example intermediate representations |
| `batch_*.yml`, `batch_config.*` | Batch configurations, one per model or experiment |
| `eval_fixtures/` | The seven evaluation fixtures (`f1_…` to `f7_…`), each with Ansible inputs, a `ground_truth/` folder, and a README |
| `ansible_configs/` | Example Ansible project (inventory, group_vars, roles, site.yml) |
| `tests/` | pytest suite (`test_nvd.py`, `test_parser.py`) |
| `Dockerfile.sandbox` | Container used for sandboxed execution |
| `.nvd_cache/` | Offline cache of NVD responses. Re-encoding is deterministic only with this cache |
| `reports/` | Raw agent reports (`*.abac.md`) from the runs |
| `batch_results_*.json` | Batch run summaries |
| `eval_results*.csv` | Scored results (`eval_results_pre_*.csv` are snapshots from before encoder fixes) |

### `export_data/` (raw results)

| Path | Contents |
|---|---|
| `01_scores/` | Per-run scores. `eval_results.csv` is the 105-run main grid. `eval_results_deepening.csv` is the 162-run supplemental batch. `*_pre_*` files are earlier snapshots |
| `02_batches/` | `batch_runs.csv` lists every run, with its batch file, model, fixture, run number, and report file. `raw/` holds the batch JSON files |
| `03_ground_truth/` | Expected SAT/UNSAT verdicts per fixture (`f*.json`) and the long-format `ground_truth_long.csv` |
| `04_fixtures/` | `INDEX.csv` describing the fixtures |
| `05_reports/` | `reports_index.csv` and `files/`, the raw `*.abac.md` report for each run |
| `06_ir/` | Intermediate representation (IR) files, one per model variant |
| `07_costs/` | `per_model_costs.csv` |

## Naming

- Run reports follow `batch_<provider>_<model>_<fixture>_<timestamp>_r<run>.abac.md`. The fixture name is truncated to 20 characters, so `f5_chained_vulnerabi` is `f5_chained_vulnerabilities`.
- Run IDs are model, fixture, and run number. The main grid has 3 runs per model and fixture.
- Fixture IDs: `f1_minimal_twotier`, `f2_threetier_segmented`, `f3_privsep_service_accounts`, `f4_patched_vs_vulnerable`, `f5_chained_vulnerabilities`, `f6_intent_vs_effective`, `f7_negative_control`.

## Finding a run

1. Look up the run in `export_data/02_batches/batch_runs.csv` and note its `report_file`.
2. Open the matching report in `export_data/05_reports/files/` or `rlm_agent/reports/`.
3. Find its scores in `export_data/01_scores/eval_results.csv` (main grid) or `eval_results_deepening.csv` (supplemental batch).

## Re-scoring

Recompute the main-grid scores from the archived reports without any LLM calls:

```bash
uv run python -m rlm_agent.eval_scorer export_data/05_reports/files/*.abac.md --csv /tmp/rescored.csv
```

Diff `/tmp/rescored.csv` against `export_data/01_scores/eval_results.csv`. They should match.

## Running

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/). Install the test and Z3 extras from the lockfile:

```bash
uv sync --frozen --extra test --extra z3
uv run --frozen pytest
```

Entry points: `rlm-abac`, `rlm-encode`, `rlm-batch` (use `--dry-run` to print a plan without calling an LLM).

Running the agent live also needs `vulnx` (a Go CLI) and an LLM API key set in the environment. See `rlm_agent/README.md`.

## Not included

The analysis-side scripts (`regen_derived.py`, `build_export_data.py`) and the derived tables they write are kept out of this release. They read paper-side folders that are not part of this repository.

## License

- Code (`rlm_agent/`, `scripts/`, project files): MIT, see `LICENSE`.
- Data (`export_data/`, `rlm_agent/reports/`, `rlm_agent/batch_results_*.json`): CC BY 4.0, see `DATA-LICENSE.md`.

## Citation

Copyright remains with the author. Reuse is permitted with attribution. To cite the code and data, see `CITATION.cff`, or use:

> Osinnii, M. (2026). *LLM-assisted ABAC mining from Ansible IaC: code and raw results* (version 0.1.0) [Software and data].
