"""NVD version-range checker — mechanical CVE applicability."""

import json
import os
import re
import time as _time
from pathlib import Path


def _normalize_to_upstream(v: str) -> str:
    """Normalize a distro-packaged version to NVD's upstream version scheme."""
    v = re.sub(r"^\d+:", "", v)         # strip epoch
    v = re.sub(r"-[^-]*$", "", v)       # strip debian/rpm revision
    v = re.sub(r"[+~].*$", "", v)       # strip +dfsg, ~rc, etc.
    v = re.sub(r"p\d+$", "", v)         # strip OpenSSH portable suffix
    return v


def _parse_version(v: str):
    """Parse a version string using univers.SemverVersion."""
    from univers.versions import SemverVersion
    normed = _normalize_to_upstream(v)
    parts = normed.split(".")
    while len(parts) < 3:
        parts.append("0")
    return SemverVersion(".".join(parts[:3]))


def _version_in_range(pinned: str, match: dict) -> bool:
    """Check if pinned version falls within a cpeMatch range from NVD."""
    try:
        pv = _parse_version(pinned)
    except Exception:
        return False

    start_inc = match.get("versionStartIncluding")
    start_exc = match.get("versionStartExcluding")
    end_inc = match.get("versionEndIncluding")
    end_exc = match.get("versionEndExcluding")

    if not any([start_inc, start_exc, end_inc, end_exc]):
        cpe_str = match.get("criteria", "")
        parts = cpe_str.split(":")
        cpe_ver = parts[5] if len(parts) > 5 else "*"
        cpe_update = parts[6] if len(parts) > 6 else "*"
        if cpe_ver in ("*", "-"):
            return True
        try:
            cpe_full = cpe_ver if cpe_update in ("*", "-", "") else f"{cpe_ver}{cpe_update}"
            return _parse_version(cpe_full) == pv
        except Exception:
            return False

    try:
        if start_inc and pv < _parse_version(start_inc):
            return False
        if start_exc and pv <= _parse_version(start_exc):
            return False
        if end_exc and pv >= _parse_version(end_exc):
            return False
        if end_inc and pv > _parse_version(end_inc):
            return False
        return True
    except Exception:
        return False


_NVD_CACHE: dict[str, list[dict]] = {}
_NVD_CACHE_DIR = Path(__file__).parent.parent / ".nvd_cache"

_CPE_PRODUCT_ALIASES: dict[str, set[str]] = {
    "openssh-server": {"openssh"},
    "openssh": {"openssh"},
    "postgresql": {"postgresql"},
    "postgres": {"postgresql"},
    "mysql-server": {"mysql"},
    "mysql": {"mysql"},
    "mariadb-server": {"mariadb"},
    "mariadb": {"mariadb"},
    "httpd": {"http_server", "httpd"},
    "apache2": {"http_server", "httpd"},
    "apache-httpd": {"http_server", "httpd"},
    "nginx": {"nginx"},
    "nginx-core": {"nginx"},
    "haproxy": {"haproxy"},
    "nagios": {"nagios", "nagios_xi"},
    "log4j": {"log4j"},
    "tomcat": {"tomcat"},
    "tomcat9": {"tomcat"},
}


def _get_cpe_matches(cve_id: str, cache_ttl_days: int = 30) -> list[dict]:
    """Fetch vulnerable cpeMatch entries from NVD via nvdlib.

    Three-tier cache: in-memory → disk (.nvd_cache/) → nvdlib API.
    Set NVD_API_KEY for 10x higher rate limits.
    """
    if cve_id in _NVD_CACHE:
        return _NVD_CACHE[cve_id]

    _NVD_CACHE_DIR.mkdir(exist_ok=True)
    cache_file = _NVD_CACHE_DIR / f"{cve_id}.json"
    if cache_file.exists():
        age_days = (_time.time() - cache_file.stat().st_mtime) / 86400
        if age_days < cache_ttl_days:
            try:
                cpe_matches = json.loads(cache_file.read_text())
                _NVD_CACHE[cve_id] = cpe_matches
                return cpe_matches
            except (json.JSONDecodeError, OSError):
                pass

    api_key = os.environ.get("NVD_API_KEY")
    try:
        import nvdlib
        kwargs = {"cveId": cve_id}
        if api_key:
            kwargs["key"] = api_key
        results = nvdlib.searchCVE(**kwargs)
    except Exception as e:
        print(f"  [nvd] lookup failed for {cve_id}: {e}")
        _NVD_CACHE[cve_id] = []
        return []

    if not results:
        _NVD_CACHE[cve_id] = []
        return []

    cve = results[0]
    cpe_matches = []
    for cfg in getattr(cve, "configurations", []):
        nodes = getattr(cfg, "nodes", [])
        for node in nodes:
            matches = getattr(node, "cpeMatch", [])
            for m in matches:
                md = m.__dict__ if hasattr(m, "__dict__") and not isinstance(m, dict) else m
                if md.get("vulnerable", False):
                    cpe_matches.append(md)

    _NVD_CACHE[cve_id] = cpe_matches
    try:
        cache_file.write_text(json.dumps(cpe_matches))
    except OSError:
        pass

    return cpe_matches


def nvd_check_affects(cve_id: str, product_name: str,
                      pinned_version: str) -> tuple[bool, str]:
    """Check if a CVE affects a pinned version using NVD CPE data.

    Returns (affects, reason) for audit logging.
    """
    if not pinned_version or pinned_version.lower() in ("unpinned", "unknown", "latest"):
        return False, f"no pinned version to check ('{pinned_version}')"

    cpe_matches = _get_cpe_matches(cve_id)
    if not cpe_matches:
        return False, "no vulnerable CPE configurations in NVD"

    product_lower = product_name.lower()
    product_aliases = {product_lower}
    product_aliases.update(_CPE_PRODUCT_ALIASES.get(product_lower, set()))

    relevant_matches = []
    for m in cpe_matches:
        cpe_str = m.get("criteria", "").lower()
        cpe_parts = cpe_str.split(":")
        cpe_product = cpe_parts[4] if len(cpe_parts) > 4 else ""
        if cpe_product in product_aliases:
            relevant_matches.append(m)

    if not relevant_matches:
        cpe_products = {m.get("criteria", "").split(":")[4]
                        for m in cpe_matches if len(m.get("criteria", "").split(":")) > 4}
        return False, f"CPE product mismatch: NVD has {cpe_products}, not '{product_name}'"

    for m in relevant_matches:
        if _version_in_range(pinned_version, m):
            return True, f"pinned {pinned_version} in range: {m.get('criteria', '')}"

    return False, f"pinned {pinned_version} not in any affected range"
