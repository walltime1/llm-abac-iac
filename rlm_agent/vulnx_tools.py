"""Thin wrappers around the vulnx CLI for CVE discovery."""

import json
import subprocess
from typing import Optional


def _run_vulnx(*args):
    """Run vulnx with given args and return parsed Python object.

    Returns a dict or list (native Python), not a JSON string, so
    RLM-generated code can iterate results directly without json.loads().
    """
    cmd = ["vulnx", "--silent", "--json"] + list(args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )
        output = result.stdout.strip()
        if not output and result.stderr.strip():
            return {"error": result.stderr.strip()}
        if not output:
            return {"results": []}
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

    Args:
        query:   vulnx search query (e.g. 'apache && severity:critical')
        limit:   max number of results (default 15)
        sort_by: field to sort descending by (default 'cvss_score')
    """
    return _run_vulnx("search", query, "--limit", str(limit), "--sort-desc", sort_by)


def get_cve_details(cve_id: str) -> str:
    """
    Fetch full details for one or more CVE IDs (comma-separated).

    Args:
        cve_id: single or comma-separated CVE IDs, e.g. 'CVE-2021-44228'
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
        "--limit", str(limit * 2),
        "--sort-desc", "cvss_score"
    )
    if isinstance(raw, dict):
        items = raw.get("results", [])
    elif isinstance(raw, list):
        items = raw
    else:
        return []
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
