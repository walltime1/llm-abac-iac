# DSPy RLM × vulnx — Vulnerability Report PoC

A proof-of-concept showing how **`dspy.RLM`** (Recursive Language Model) can
autonomously research and compile a structured security report by calling real
vulnerability data tools.

```
Target: "apache"
      │
      ▼
 ┌──────────────────────────────────────────────────────┐
 │              dspy.RLM  (REPL loop)                   │
 │                                                      │
 │  Step 1 → search_critical_remote("apache")          │
 │  Step 2 → analyze_severity_distribution("apache")   │
 │  Step 3 → search_kev_vulnerabilities("apache")      │
 │  Step 4 → get_cve_details("CVE-2021-41773,...")     │
 │  Step 5 → search_recent_vulnerabilities("apache",90)│
 │  Step 6 → get_cve_details("CVE-2024-...")           │
 │     ...   (up to max_iterations)                    │
 │  SUBMIT → structured Markdown report               │
 └──────────────────────────────────────────────────────┘
```

## Prerequisites

### 1 — Install vulnx (Go CLI)
```bash
go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest
vulnx healthcheck
```

> **Optional**: get a free API key at https://cloud.projectdiscovery.io  
> and run `vulnx auth` to avoid rate limits.

### 2 — Install Python dependencies
```bash
pip install dspy
```

### 3 — Set API keys
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export PDCP_API_KEY="..."        # optional, avoids vulnx rate limits
```

## Usage

```bash
# Anthropic (default — uses ANTHROPIC_API_KEY)
python poc.py apache
python poc.py apache --model claude-sonnet
python poc.py apache --model claude-opus

# OpenAI (uses OPENAI_API_KEY)
python poc.py apache --model gpt-4o
python poc.py apache --model gpt-4o-mini --api-key sk-...

# Custom / OpenAI-compatible endpoint (Ollama, LiteLLM, vLLM, Azure, …)
python poc.py apache --model llama3.3 --base-url http://localhost:11434/v1
python poc.py apache --model my-model  --base-url https://proxy.example.com/v1 --api-key ...

# Other options
python poc.py log4j --output log4j_report.md
python poc.py "vmware esxi" --iterations 18
python poc.py "nginx && severity:critical"
```

### Model aliases

| Alias | Resolves to |
|-------|------------|
| `claude-sonnet` *(default)* | `claude-sonnet-4-20250514` |
| `claude-opus` | `claude-opus-4-20250514` |
| `claude-haiku` | `claude-haiku-4-5-20251001` |
| `gpt-4o` | `openai/gpt-4o` |
| `gpt-4o-mini` | `openai/gpt-4o-mini` |
| `gpt-4-turbo` | `openai/gpt-4-turbo` |
| `o1` | `openai/o1` |
| `o3-mini` | `openai/o3-mini` |

You can also pass any full DSPy model string directly, e.g. `openai/gpt-4o`.

### Environment variables

| Var | Used for |
|-----|---------|
| `ANTHROPIC_API_KEY` | Anthropic models |
| `OPENAI_API_KEY` | OpenAI models or custom endpoints |
| `CUSTOM_API_KEY` | Custom endpoints (alternative to `OPENAI_API_KEY`) |
| `PDCP_API_KEY` | ProjectDiscovery vulnx API key (optional) |

`--api-key` on the CLI overrides all of the above.

## Tool inventory

| Tool | vulnx command | Purpose |
|------|--------------|---------|
| `search_vulnerabilities` | `vulnx search <query>` | Flexible search with full query syntax |
| `get_cve_details` | `vulnx id <cve>` | Full detail on specific CVEs |
| `search_critical_remote` | search + severity:critical + is_remote:true | Fast critical/remote filter |
| `search_kev_vulnerabilities` | search + is_kev:true | Known-exploited vulns only |
| `search_recent_vulnerabilities` | search + age_in_days:<N | Emerging threat detection |
| `analyze_severity_distribution` | search + --term-facets severity=5 | Risk distribution stats |

## Report structure

The generated Markdown report includes:

- **Executive Summary** (2-3 sentences on overall risk)
- **Severity Distribution** (breakdown by critical/high/medium/low)
- **Critical & High Vulnerabilities** (table: CVE · CVSS · description · exploit status · fix)
- **Known Exploited Vulnerabilities** (KEV section — actively exploited in wild)
- **Recent Emerging Threats** (last 90 days)
- **Risk Prioritisation & Recommendations**
- **Appendix** — full detail for the top 3 most critical CVEs

## How RLM differs from ReAct here

| ReAct agent | This RLM agent |
|------------|----------------|
| Selects one tool at a time from a list | Writes Python code to call tools — can loop, chain, filter |
| Linear reasoning | Non-linear: can call the same tool multiple times with different args |
| All context in prompt | Context (tool results) stored in REPL variable space — no context rot |
| Fixed call sequence | LLM decides its own research strategy |

## Extending

To add a new data source, just write a Python function with a clear docstring
and add it to the `tools=[]` list in `build_rlm()`. The RLM will automatically
learn when and how to use it from the docstring alone.

```python
def search_poc_exploits(product: str) -> str:
    """Find vulnerabilities with public proof-of-concept exploits for a product."""
    return _run_vulnx("search", f"{product} && is_poc:true",
                       "--limit", "10", "--sort-desc", "cvss_score")

# then in build_rlm():
tools = [..., search_poc_exploits]
```
