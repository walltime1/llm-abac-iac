"""
Z3 μZ Datalog encoder for mined ABAC policies.

Reads a policy JSON (attributes + rules + catalog) produced by abac_poc.py,
builds a Z3 Fixedpoint program with finite EnumSorts, and answers reachability
queries: "can user X perform action A on resource R?"

Architecture follows the positive (monotone) abstraction from ASASP/VAC:
  - All attribute domains → EnumSort (finite, decidable)
  - Each ABAC rule → one or more Horn clauses (disjunctions expanded)
  - Deny rules → stratified negation via effective_permit
  - Queries → Fixedpoint.query() returning sat/unsat + derivation trace

Reference: Hoder, Bjørner, de Moura — "μZ: An Efficient Engine for Fixed
Points with Constraints" (CAV 2011).
"""

import json
import re
import sys
from itertools import product as cartesian
from pathlib import Path
from typing import Optional

import math

from z3 import (
    BitVecSort,
    BitVecVal,
    BoolSort,
    Const,
    Fixedpoint,
    Function,
    Not,
    sat,
    unsat,
)


# ---------------------------------------------------------------------------
# 1. Policy parser — extract JSON from .md or load raw JSON
# ---------------------------------------------------------------------------


def load_policy(path: str) -> dict:
    """Load a policy from a .md file (abac_poc output) or raw JSON file."""
    text = Path(path).read_text()

    # Try raw JSON first
    try:
        obj = json.loads(text)
        if "rules" in obj:
            return _normalize_policy(obj, "")
    except (json.JSONDecodeError, ValueError):
        pass

    # Extract from markdown fences
    blocks = re.findall(r"```json\n(.*?)```", text, re.S)
    if len(blocks) < 2:
        raise ValueError(f"Expected at least 2 JSON blocks in {path} (attributes + rules)")

    attrs = _lenient_json(blocks[0])
    rules = _lenient_json(blocks[1])
    vulns = _lenient_json(blocks[2]) if len(blocks) > 2 else []
    return _normalize_policy(
        {"attributes": attrs, "rules": rules, "vulnerabilities": vulns},
        text,
    )


def _lenient_json(raw: str):
    """Parse JSON leniently, recovering from common LLM output errors.

    Handles:
      - Trailing garbage (extra braces/whitespace after valid JSON)
      - Concatenated JSON objects (takes the first valid parse)
    """
    raw = raw.strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        pass
    # Trailing garbage — take first valid object
    try:
        decoder = json.JSONDecoder()
        obj, _ = decoder.raw_decode(raw)
        return obj
    except (json.JSONDecodeError, ValueError):
        pass
    # Last resort
    return json.loads(raw)  # raise the original error


# ---------------------------------------------------------------------------
# 1b. Policy normalizer — handle model-specific output shapes
# ---------------------------------------------------------------------------


def _unwrap_collection(val):
    """Unwrap schema-first envelopes on a single collection value.

    Models wrap catalog arrays in various ways:
      {"entries": [...]}, {"values": [...]}, {"domain": [...]},
      {"description": "...", "entries": [...]}, etc.
    Unwrap to the bare list.  When a dict has both ``domain`` (as a
    non-list or None) *and* ``values``/``entries`` (as a list), prefer
    the object list.
    """
    if not isinstance(val, dict):
        return val
    # Prefer entries/values/items (object arrays) over domain (string enum)
    for key in ("entries", "values", "items"):
        if key in val and isinstance(val[key], list):
            return val[key]
    if "domain" in val and isinstance(val["domain"], list):
        return val["domain"]
    return val


def _parse_users_from_md(raw_md: str) -> list[dict]:
    """Extract user records from a markdown Subjects table.

    Parses tables with columns like: User | UID | Groups | Clearance | Department.
    This is the fallback for models (e.g. GLM) that emit schema-definition
    attributes but list actual user records in the narrative report section.
    """
    if not raw_md:
        return []

    # Find a markdown table row containing "User" and "Groups" headers
    header_pat = re.compile(
        r"^\|[^|]*(?:User|Name)[^|]*\|.*(?:Groups?)[^|]*\|",
        re.IGNORECASE | re.MULTILINE,
    )
    match = header_pat.search(raw_md)
    if not match:
        return []

    # Locate table start
    table_start = raw_md.rfind("\n", 0, match.start()) + 1
    lines = raw_md[table_start:].split("\n")

    # Parse header column names
    header = lines[0]
    cols = [c.strip().lower() for c in header.split("|")[1:-1]]

    # Collect data rows (skip separator)
    users: list[dict] = []
    for line in lines[2:]:
        line = line.strip()
        if not line.startswith("|"):
            break
        if re.match(r"^\|[\s\-:|]+\|$", line):
            continue
        values = [v.strip() for v in line.split("|")[1:-1]]
        if len(values) < 2:
            continue

        user: dict = {}
        for col, val in zip(cols, values):
            if col in ("user", "name"):
                user["name"] = val
            elif col == "uid":
                try:
                    user["uid"] = int(val)
                except ValueError:
                    pass
            elif col in ("groups", "group"):
                user["groups"] = [
                    g.strip()
                    for g in re.split(r"[,;]", val)
                    if g.strip() and g.strip() not in ("\u2014", "-", "\u2013")
                ]
            elif col == "clearance":
                clean = re.sub(r"\s*\(.*\)", "", val).strip()
                if clean and clean not in ("\u2014", "-", "\u2013"):
                    user["clearance"] = clean
            elif col == "department":
                if val and val not in ("\u2014", "-", "\u2013"):
                    user["department"] = val

        if user.get("name"):
            users.append(user)

    return users


def _normalize_attrs(attrs: dict, raw_md: str = "") -> dict:
    """Normalize model-specific attribute JSON into canonical encoder IR.

    Canonical shape expected by ``_extract_catalog``::

        {
          "subjects": {
            "users": [{"name": str, "groups": [str], "clearance": str, ...}],
            "groups": ["sudo", ...]
          },
          "resources": {
            "hosts": [{"hostname": str, "inventory_group": str, ...}],
            "services": [{"name": str, ...}],
            "paths": [{"path": str, ...}]
          }
        }
    """
    # ---- key aliases -------------------------------------------------------
    # subject → subjects, resource → resources, subject_attributes → subjects
    key_map = {
        "subject": "subjects",
        "resource": "resources",
        "subject_attributes": "subjects",
        "resource_attributes": "resources",
        "environment_attributes": "environment",
    }
    attrs = {key_map.get(k, k): v for k, v in attrs.items()}

    # ---- detect shape -------------------------------------------------------
    subj = attrs.get("subjects")

    # Schema-definition: {subjects: {user: {type, domain}, groups: {type, domain}}}
    # Also matches when subjects has attribute-name keys but no 'users' key
    # DeepSeek dual-layer: {subject: {attributes: [...], entities: {users: [...]}}}
    is_schema_def = False
    if isinstance(subj, dict):
        # DeepSeek dual-layer: has 'entities' sub-dict with user objects
        # and 'attributes' list with typed schema definitions
        if "entities" in subj and isinstance(subj["entities"], dict):
            entities = subj["entities"]
            res_obj = attrs.get("resources", attrs.get("resource", {}))
            res_entities = res_obj.get("entities", {}) if isinstance(res_obj, dict) else {}
            # Extract groups from schema attributes array if not in entities
            groups = entities.get("groups", [])
            if not groups:
                # Look in the attributes array for groups domain
                for attr_def in (subj.get("attributes") or []):
                    if isinstance(attr_def, dict) and attr_def.get("name") == "groups":
                        groups = attr_def.get("domain", [])
                        break
            attrs["subjects"] = {
                "users": _unwrap_collection(entities.get("users", [])),
                "groups": _flatten_string_list(groups),
            }
            attrs["resources"] = {
                "hosts": _unwrap_collection(res_entities.get("hosts", [])),
                "services": _unwrap_collection(res_entities.get("services", [])),
                "paths": _unwrap_collection(res_entities.get("paths", [])),
            }
            subj = attrs["subjects"]
        user_field = subj.get("user") or subj.get("users")
        if isinstance(user_field, dict) and "type" in user_field:
            is_schema_def = True
        elif not subj.get("users") and ("user" in subj or "name" in subj):
            # subjects has attribute-name keys (name, groups, clearance) but no 'users'
            is_schema_def = True

    # Array-of-attribute-defs: {subjects: [{name: "user", type: "enum", domain: [...]}, ...]}
    is_array_schema = (
        isinstance(subj, list) and subj
        and isinstance(subj[0], dict) and "name" in subj[0] and "type" in subj[0]
    )

    # Flat top-level: {users: {...}, groups: {...}, hosts: {...}, ...}
    # Also covers: {subjects: {description, values: [users]}, groups: {...}, hostname: {...}}
    # when other attribute names (hostname, host_group, etc.) appear at top level
    is_flat_top = (
        "subjects" not in attrs
        and "catalog" not in attrs
        and ("users" in attrs or "user" in attrs)
    ) or (
        # subjects exists but is a wrapper around users; other attrs are top-level
        isinstance(subj, dict)
        and ("description" in subj or "domain" in subj)
        and ("values" in subj or "entries" in subj)
        and ("groups" in attrs or "hostname" in attrs or "host_group" in attrs)
    )

    if is_schema_def:
        attrs = _from_schema_def(attrs, raw_md)
    elif is_array_schema:
        attrs = _from_array_schema(attrs, raw_md)
    elif is_flat_top:
        attrs = _from_flat_top(attrs, raw_md)
    else:
        # Standard catalog format — just deep-unwrap collections
        attrs = _unwrap_catalog(attrs)

    return attrs


def _domain_vals(field: dict) -> list:
    """Extract domain values from a typed attribute definition."""
    if not isinstance(field, dict):
        return []
    for key in ("domain", "values", "entries"):
        v = field.get(key)
        if isinstance(v, list):
            return v
    return []


def _from_schema_def(attrs: dict, raw_md: str) -> dict:
    """Convert GLM schema-definition format to canonical catalog.

    Input: {subjects: {user: {type, domain}, groups: {type, domain}, ...},
            resources: {hostname: {type, domain}, ...}}
    """
    subj = attrs.get("subjects", {})
    res = attrs.get("resources", {})

    # Extract domain values for key attributes
    user_field = subj.get("user") or subj.get("users", {})
    user_names = _domain_vals(user_field) if isinstance(user_field, dict) and "type" in user_field else []
    group_names = _domain_vals(subj.get("groups", {}))
    clearance_vals = _domain_vals(subj.get("clearance", {}))
    dept_vals = _domain_vals(subj.get("department", {}))

    # Try to get real user→attribute mappings from the markdown report
    md_users = _parse_users_from_md(raw_md)

    if md_users:
        users = md_users
    elif user_names:
        # Fallback: create minimal user objects from domain values
        users = [{"name": n, "groups": []} for n in user_names]
    else:
        users = []

    groups = group_names or []

    # Synthesize host objects from resource attribute domains
    hg_vals = _domain_vals(res.get("host_group", res.get("inventory_group", {})))
    hostname_vals = _domain_vals(res.get("hostname", {}))
    svc_vals = _domain_vals(res.get("service", {}))
    path_vals = _domain_vals(res.get("path", {}))

    # Build minimal host objects (encoder only needs inventory_group)
    if hostname_vals and len(hostname_vals) == len(hg_vals):
        hosts = [{"hostname": h, "inventory_group": g}
                 for h, g in zip(hostname_vals, hg_vals)]
    elif hg_vals:
        hosts = [{"inventory_group": g} for g in hg_vals]
    else:
        hosts = []

    services = [{"name": s} for s in svc_vals]
    paths = [{"path": p} for p in path_vals] if path_vals else []

    return {
        "subjects": {"users": users, "groups": groups},
        "resources": {"hosts": hosts, "services": services, "paths": paths},
        "environment": attrs.get("environment", {}),
    }


def _from_array_schema(attrs: dict, raw_md: str) -> dict:
    """Convert array-of-attribute-defs to canonical catalog.

    Input: {subjects: [{name: "user", type: "enum", domain: [...]}, ...],
            resources: [...], environment: [...]}
    """
    subj_list = attrs.get("subjects", [])
    res_list = attrs.get("resources", [])

    # Convert to dict keyed by attribute name
    subj_dict = {}
    for item in subj_list:
        if isinstance(item, dict) and "name" in item:
            subj_dict[item["name"]] = item

    res_dict = {}
    for item in res_list:
        if isinstance(item, dict) and "name" in item:
            res_dict[item["name"]] = item

    # Now process as schema-definition format
    new_attrs = {
        "subjects": subj_dict,
        "resources": res_dict,
        "environment": attrs.get("environment", {}),
    }
    return _from_schema_def(new_attrs, raw_md)


def _from_flat_top(attrs: dict, raw_md: str) -> dict:
    """Convert flat top-level layout to canonical catalog.

    Handles two variants:
      (a) {users: {...}, groups: {...}, hosts: {...}, ...}
      (b) {subjects: {values: [users]}, groups: {...}, hostname: {...}, ...}
    """
    # Get users from 'users', 'user', or 'subjects' (as wrapper)
    subj_wrapper = attrs.get("subjects")
    if isinstance(subj_wrapper, dict) and ("values" in subj_wrapper or "entries" in subj_wrapper):
        users = _unwrap_collection(subj_wrapper)
    else:
        users = _unwrap_collection(attrs.get("users") or attrs.get("user", []))

    groups = _unwrap_collection(attrs.get("groups", []))

    # Hosts: try 'hosts', or synthesize from top-level host_group/hostname
    hosts_raw = attrs.get("hosts")
    if hosts_raw:
        hosts = _unwrap_collection(hosts_raw)
    else:
        # Synthesize from top-level host_group/hostname domains
        hg_vals = _domain_vals(attrs.get("host_group", {}))
        hostname_vals = _domain_vals(attrs.get("hostname", {}))
        if hg_vals:
            if hostname_vals and len(hostname_vals) == len(hg_vals):
                hosts = [{"hostname": h, "inventory_group": g}
                         for h, g in zip(hostname_vals, hg_vals)]
            else:
                hosts = [{"inventory_group": g} for g in hg_vals]
        else:
            hosts = []

    # Services: try 'services', or synthesize from top-level service domain
    services_raw = attrs.get("services")
    if services_raw:
        services = _unwrap_collection(services_raw)
    else:
        svc_vals = _domain_vals(attrs.get("service", {}))
        services = [{"name": s} for s in svc_vals] if svc_vals else []

    paths_raw = attrs.get("paths")
    paths = _unwrap_collection(paths_raw) if paths_raw else []

    env = attrs.get("environment", {})
    if isinstance(env, dict) and ("values" in env or "entries" in env):
        env = _unwrap_collection(env)

    # If users is still a schema-def dict or string list, fall back to markdown
    if isinstance(users, dict) or (isinstance(users, list) and users and isinstance(users[0], str)):
        md_users = _parse_users_from_md(raw_md)
        if md_users:
            users = md_users
        elif isinstance(users, list) and users and isinstance(users[0], str):
            users = [{"name": n, "groups": []} for n in users]
        else:
            users = []

    # Normalize groups to flat strings
    groups = _flatten_string_list(groups)

    return {
        "subjects": {"users": users, "groups": groups},
        "resources": {"hosts": hosts, "services": services, "paths": paths},
        "environment": env,
    }


def _flatten_string_list(val) -> list[str]:
    """Ensure a value is a flat list of strings.

    Handles: ["a", "b"], [{"name": "a"}, ...], {"domain": [...]}, etc.
    """
    if isinstance(val, dict):
        val = _unwrap_collection(val)
    if not isinstance(val, list):
        return []
    if not val:
        return []
    if isinstance(val[0], str):
        return val
    if isinstance(val[0], dict):
        return [
            v.get("name") or v.get("value") or v.get("level", "")
            for v in val
            if isinstance(v, dict) and (v.get("name") or v.get("value") or v.get("level"))
        ]
    return [str(v) for v in val]


def _unwrap_catalog(attrs: dict) -> dict:
    """Deep-unwrap a catalog-format attributes dict.

    The structure is already canonical (subjects/resources) but collections
    may be wrapped in {entries: [...]}, {values: [...]}, etc.
    """
    subj = attrs.get("subjects", {})
    res = attrs.get("resources", {})

    if isinstance(subj, dict):
        for key in ("users", "groups", "clearance_levels", "departments"):
            if key in subj:
                subj[key] = _unwrap_collection(subj[key])

        # Normalize clearance_levels / departments if they're object arrays
        # e.g., [{level: "secret", source: ...}] → ["secret"]
        for key, subkey in [("clearance_levels", ("level", "value", "name")),
                            ("departments", ("name", "value"))]:
            val = subj.get(key, [])
            if isinstance(val, list) and val and isinstance(val[0], dict):
                flat = []
                for item in val:
                    for sk in subkey:
                        if sk in item:
                            flat.append(item[sk])
                            break
                subj[key] = flat

        # Ensure groups is a flat string list
        groups = subj.get("groups", [])
        subj["groups"] = _flatten_string_list(groups)

        # If users are strings (names only), convert to minimal dicts
        users = subj.get("users", [])
        if isinstance(users, list) and users and isinstance(users[0], str):
            subj["users"] = [{"name": n, "groups": []} for n in users]

    if isinstance(res, dict):
        for key in ("hosts", "services", "paths", "networks"):
            if key in res:
                val = _unwrap_collection(res[key])
                # Handle hosts with 'attrs' key (schema def, not data)
                if isinstance(val, dict) and "attrs" in val:
                    val = []  # Can't recover data from schema def
                res[key] = val if isinstance(val, list) else []

    attrs["subjects"] = subj
    attrs["resources"] = res
    return attrs


def _normalize_rules(rules: list) -> list:
    """Normalize rule fields across model outputs."""
    for rule in rules:
        # rule_id → id  (MiniMax uses rule_id)
        if "rule_id" in rule and "id" not in rule:
            rule["id"] = rule.pop("rule_id")
        # Ensure id exists
        if "id" not in rule:
            rule["id"] = f"rule-{rules.index(rule) + 1:03d}"
    return rules


def _normalize_vulns(vulns: list) -> list:
    """Normalize vulnerability fields."""
    for v in vulns:
        # Only infer is_remote from the model's own explicit output.
        # If the model wrote category: "critical_remote_kev", it said remote.
        # If it said nothing, we don't guess — missing = missing.
        if v.get("is_remote") is None:
            cat = (v.get("category") or "").lower()
            if "remote" in cat:
                v["is_remote"] = True
        # Normalize field names
        if "cve_id" not in v and "cve" in v:
            v["cve_id"] = v.pop("cve")
        if "product" not in v and "package" in v:
            v["product"] = v["package"]
    return vulns


def _normalize_policy(policy: dict, raw_md: str) -> dict:
    """Top-level normalizer: fix attributes, rules, and vulns."""
    policy["attributes"] = _normalize_attrs(policy["attributes"], raw_md)
    policy["rules"] = _normalize_rules(policy.get("rules", []))
    policy["vulnerabilities"] = _normalize_vulns(policy.get("vulnerabilities", []))
    return policy


def validate_ir(policy: dict) -> None:
    """Validate policy against ir_schema.json if jsonschema is available."""
    try:
        import jsonschema
    except ImportError:
        return
    schema_path = Path(__file__).parent / "ir_schema.json"
    if not schema_path.exists():
        return
    schema = json.loads(schema_path.read_text())
    try:
        jsonschema.validate(policy, schema)
    except jsonschema.ValidationError as e:
        print(f"[schema] IR validation warning: {e.message}")
        # Don't raise — schema is advisory, encoder has its own checks


# ---------------------------------------------------------------------------
# 2. Catalog extractor — normalize different model output shapes
# ---------------------------------------------------------------------------


def _extract_catalog(attrs: dict, rules: list | None = None) -> dict:
    """Extract the catalog from the attributes block.

    Expects the canonical IR shape — attributes MUST have either:
      (a) a top-level `catalog` key (Opus dual-layer), or
      (b) a `subjects` dict with `users` and `groups` keys (flat shape).

    When host_groups cannot be derived from hosts, falls back to
    extracting them from ``rules`` resource_conditions.
    """
    # Opus dual-layer: schema (subject/resource/environment) + catalog
    catalog = attrs.get("catalog") or attrs.get("subjects_catalog")
    if catalog and "users" in catalog:
        users = catalog["users"]
        groups = catalog.get("groups", [])
        hosts = catalog.get("hosts", [])
        services = catalog.get("services", [])
        paths = catalog.get("paths", [])
    elif "subjects" in attrs and isinstance(attrs["subjects"], dict):
        subj = attrs["subjects"]
        users = subj.get("users", [])
        groups = subj.get("groups", [])
        res = attrs.get("resources", {})
        hosts = res.get("hosts", []) if isinstance(res, dict) else []
        services = res.get("services", []) if isinstance(res, dict) else []
        paths = res.get("paths", []) if isinstance(res, dict) else []
        # Unwrap schema-first envelope: {"type":..., "domain": [...]} → [...]
        # MiniMax M2.7 consistently wraps catalog lists in this format.
        # Unwrap schema-first envelopes. MiniMax M2.7 wraps catalog
        # lists in various shapes: {"domain": [...]}, {"entries": [...]},
        # {"values": [...]}, or {"description":..., "domain": [...]}.
        def _unwrap(val):
            if not isinstance(val, dict):
                return val
            for key in ("domain", "entries", "values"):
                if key in val and isinstance(val[key], list):
                    return val[key]
            return val

        users = _unwrap(users)
        groups = _unwrap(groups)
        hosts = _unwrap(hosts)
        services = _unwrap(services)
        paths = _unwrap(paths)
    else:
        raise ValueError(
            "Non-conforming attributes shape. Expected `catalog.users` "
            "(Opus dual-layer) or `subjects.users` (flat). The post-processor "
            "in mine_policy should normalize model output before encoding."
        )

    if not users:
        raise ValueError("Empty user catalog — cannot build Z3 model.")
    if not groups or not isinstance(groups[0], str):
        raise ValueError(
            f"groups must be a flat list of strings, got: {type(groups[0]) if groups else 'empty'}. "
            "Run the flatten post-processor first."
        )

    # Normalize hosts: if strings, convert to dicts
    if hosts and isinstance(hosts[0], str):
        hosts = [{"hostname": h} for h in hosts]

    # Derive domains from catalog
    clearance_levels = sorted({u["clearance"] for u in users if u.get("clearance")})
    departments = sorted({u["department"] for u in users if u.get("department")})
    host_groups = sorted({
        h.get("inventory_group") or h.get("host_group")
        for h in hosts
        if isinstance(h, dict) and (h.get("inventory_group") or h.get("host_group"))
    })
    service_names = sorted({s["name"] for s in services if isinstance(s, dict) and s.get("name")})
    # Also accept service strings
    if not service_names and services and isinstance(services[0], str):
        service_names = sorted(set(services))
    path_strs = sorted({
        p["path"] if isinstance(p, dict) else p
        for p in paths
        if (isinstance(p, dict) and p.get("path")) or isinstance(p, str)
    })

    if not clearance_levels:
        # Some repos have no clearance model — use a placeholder
        clearance_levels = ["_none"]

    # Fallback: derive host_groups from rules if not in hosts
    if not host_groups and rules:
        for r in rules:
            rc = r.get("resource_condition", {})
            if isinstance(rc, dict):
                for key in ("host_group", "inventory_group"):
                    val = rc.get(key)
                    if isinstance(val, dict) and "equals" in val:
                        host_groups.append(val["equals"])
                    elif isinstance(val, str):
                        host_groups.append(val)
        host_groups = sorted(set(host_groups))

    if not host_groups:
        raise ValueError(
            "No host_groups found in hosts catalog or rules. Each host needs "
            "'inventory_group' or 'host_group' field."
        )

    return {
        "users": users,
        "groups": groups,
        "clearance_levels": clearance_levels,
        "departments": departments,
        "host_groups": host_groups,
        "service_names": service_names,
        "paths": path_strs,
        "hosts": hosts,
    }


# ---------------------------------------------------------------------------
# 3. Action normalizer — sanitize action strings for EnumSort
# ---------------------------------------------------------------------------


def _safe_enum_name(s: str) -> str:
    """Replace characters invalid in Z3 enum names."""
    return s.replace(":", "_").replace("/", "_").replace(".", "_").replace("*", "wildcard").replace(" ", "_")


# ---------------------------------------------------------------------------
# 4. NVD version-range checker (mechanical CVE applicability)
# ---------------------------------------------------------------------------


def _normalize_to_upstream(v: str) -> str:
    """Normalize a distro-packaged version to NVD's upstream version scheme.

    NVD CPE ranges use upstream versions (e.g., "9.8" for OpenSSH, not
    "1:9.6p1-3ubuntu1"). This strips distro packaging metadata:
      - Debian/Ubuntu epoch and revision: "1:9.6p1-3ubuntu1" → "9.6"
      - RPM release: "5.5.68-1.el7" → "5.5.68"
      - OpenSSH portable suffix: "9.6p1" → "9.6" (p1 = portable build 1,
        not a sub-version; NVD tracks p-releases as separate exact CPE
        entries, not as range endpoints)
      - Misc: +dfsg, ~rc, etc.
    """
    v = re.sub(r"^\d+:", "", v)         # strip epoch
    v = re.sub(r"-[^-]*$", "", v)       # strip debian/rpm revision
    v = re.sub(r"[+~].*$", "", v)       # strip +dfsg, ~rc, etc.
    v = re.sub(r"p\d+$", "", v)         # strip OpenSSH portable suffix
    return v


def _parse_version(v: str):
    """Parse a version string using univers.SemverVersion.

    SemverVersion does numeric segment comparison (16.4 > 9.0).
    GenericVersion does lexicographic comparison (16.4 < 9.0 — wrong).
    Versions are zero-padded to 3 segments for semver compliance.
    """
    from univers.versions import SemverVersion
    normed = _normalize_to_upstream(v)
    # Pad to 3 segments: "16.4" → "16.4.0", "9" → "9.0.0"
    parts = normed.split(".")
    while len(parts) < 3:
        parts.append("0")
    return SemverVersion(".".join(parts[:3]))


def _version_in_range(pinned: str, match: dict) -> bool:
    """Check if pinned version falls within a cpeMatch range from NVD.

    Uses univers.GenericVersion for comparison, which handles
    multi-segment versions correctly without PEP 440 assumptions.
    """
    try:
        pv = _parse_version(pinned)
    except Exception:
        return False

    start_inc = match.get("versionStartIncluding")
    start_exc = match.get("versionStartExcluding")
    end_inc = match.get("versionEndIncluding")
    end_exc = match.get("versionEndExcluding")

    # No range bounds → check CPE version field for exact or wildcard match
    if not any([start_inc, start_exc, end_inc, end_exc]):
        cpe_str = match.get("criteria", "")
        parts = cpe_str.split(":")
        # cpe:2.3:a:vendor:product:version:update:...
        cpe_ver = parts[5] if len(parts) > 5 else "*"
        cpe_update = parts[6] if len(parts) > 6 else "*"
        if cpe_ver in ("*", "-"):
            return True  # wildcard → conservatively true
        # Exact version match — also check update field for portable suffix
        # (e.g., cpe:...:openssh:8.5:p1:... matches 8.5p1)
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
        return False  # unparseable → conservative reject


_NVD_CACHE: dict[str, list[dict]] = {}
_NVD_CACHE_DIR = Path(__file__).parent / ".nvd_cache"

# Package-name → NVD CPE product aliases.
# Exact match only — substring matching causes false positives
# (e.g., "nginx" matching "nginx_ui", "postgresql" matching
# "postgresql_jdbc_driver").
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
    "apache_httpd": {"http_server", "httpd"},
    "apache": {"http_server", "httpd"},
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

    Three-tier cache:
      1. In-memory dict (_NVD_CACHE) — instant, lost on exit.
      2. Local disk (.nvd_cache/<CVE-ID>.json) — survives restarts,
         enables offline re-runs for evaluation reproducibility.
         TTL defaults to 30 days (CVE configurations rarely change).
      3. nvdlib API call — rate-limited by NVD (5 req/30s public,
         50 req/30s with API key set via NVD_API_KEY env var).

    Set NVD_API_KEY for 10× higher rate limits (free, instant signup).
    """
    import os
    import time as _time

    # Tier 1: in-memory
    if cve_id in _NVD_CACHE:
        return _NVD_CACHE[cve_id]

    # Tier 2: disk cache
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
                pass  # stale/corrupt → re-fetch

    # Tier 3: NVD API via nvdlib
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

    # Persist to all cache tiers
    _NVD_CACHE[cve_id] = cpe_matches
    try:
        cache_file.write_text(json.dumps(cpe_matches))
    except OSError:
        pass

    return cpe_matches


_NVD_AV_CACHE: dict[str, bool | None] = {}


def nvd_is_remote(cve_id: str) -> bool | None:
    """Check if a CVE is remotely exploitable using NVD CVSS attack vector.

    Returns True (AV:N or AV:A), False (AV:L or AV:P), or None (unknown).
    Uses a separate disk cache keyed by CVE ID.
    """
    import os
    import time as _time

    if cve_id in _NVD_AV_CACHE:
        return _NVD_AV_CACHE[cve_id]

    # Disk cache
    _NVD_CACHE_DIR.mkdir(exist_ok=True)
    cache_file = _NVD_CACHE_DIR / f"{cve_id}.av.json"
    if cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text())
            _NVD_AV_CACHE[cve_id] = cached.get("is_remote")
            return _NVD_AV_CACHE[cve_id]
        except (json.JSONDecodeError, OSError):
            pass

    # NVD API
    api_key = os.environ.get("NVD_API_KEY")
    try:
        import nvdlib
        kwargs = {"cveId": cve_id}
        if api_key:
            kwargs["key"] = api_key
        results = nvdlib.searchCVE(**kwargs)
    except Exception:
        _NVD_AV_CACHE[cve_id] = None
        return None

    if not results:
        _NVD_AV_CACHE[cve_id] = None
        return None

    cve = results[0]

    # Extract attack vector from CVSS v3.1, v3.0, or v2.0 metrics
    av = None
    for attr in ("v31vector", "v30vector", "v2vector"):
        vec_str = None
        metrics = getattr(cve, "metrics", None)
        if metrics:
            # nvdlib exposes metrics as attributes
            for m_list_attr in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m_list = getattr(metrics, m_list_attr, None)
                if m_list:
                    for m in m_list:
                        cvss = getattr(m, "cvssData", None)
                        if cvss:
                            vec_str = getattr(cvss, "vectorString", None)
                            if vec_str:
                                break
                if vec_str:
                    break
        if vec_str:
            # Parse AV from vector string: "CVSS:3.1/AV:N/..." or "(AV:N/...)"
            if "AV:N" in vec_str or "AV:A" in vec_str:
                av = True
            elif "AV:L" in vec_str or "AV:P" in vec_str:
                av = False
            break

    _NVD_AV_CACHE[cve_id] = av
    try:
        cache_file.write_text(json.dumps({"is_remote": av}))
    except OSError:
        pass

    return av


def nvd_check_affects(cve_id: str, product_name: str,
                      pinned_version: str) -> tuple[bool, str]:
    """Check if a CVE affects a pinned version using NVD CPE data.

    Uses nvdlib to fetch structured version ranges from NVD, then
    performs a mechanical version comparison. The LLM discovers CVE
    candidates; this function decides applicability.

    Returns (affects, reason) for audit logging.
    """
    if not pinned_version or pinned_version.lower() in ("unpinned", "unknown", "latest"):
        return False, f"no pinned version to check ('{pinned_version}')"

    cpe_matches = _get_cpe_matches(cve_id)
    if not cpe_matches:
        return False, "no vulnerable CPE configurations in NVD"

    # Build product alias set
    product_lower = product_name.lower()
    product_aliases = {product_lower}
    product_aliases.update(_CPE_PRODUCT_ALIASES.get(product_lower, set()))

    # Filter to CPE entries matching the product (exact match only)
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

    # Check version ranges
    for m in relevant_matches:
        if _version_in_range(pinned_version, m):
            return True, f"pinned {pinned_version} in range: {m.get('criteria', '')}"

    return False, f"pinned {pinned_version} not in any affected range"


# ---------------------------------------------------------------------------
# 5. Z3 Encoder
# ---------------------------------------------------------------------------


class ABACEncoder:
    """Encodes a mined ABAC policy into a Z3 Fixedpoint Datalog program.

    When `vulnerabilities` are present in the policy, CVE-derived `become`
    rules model privilege escalation via exploitation:
      - Each RCE CVE on a service creates a `become(attacker, host_identity)`
        edge for anyone who can reach that service.
      - Transitive closure propagates: attacker → compromised host →
        inherits host's network position → reaches further services.
      - Queries against `effective_permit` then reflect the *effective*
        access surface including vulnerability-induced escalation.
    """

    def __init__(self, policy: dict, enable_cve_escalation: bool = True):
        validate_ir(policy)
        self.raw_attrs = policy["attributes"]
        self.raw_rules = policy["rules"]
        self.raw_vulns = policy.get("vulnerabilities", [])
        self.catalog = _extract_catalog(self.raw_attrs, self.raw_rules)
        self.cve_enabled = enable_cve_escalation and bool(self.raw_vulns)

        self._build_sorts()

        # Two-pass Fixedpoint architecture:
        #   Pass 1: become closure — compute in_group/has_clearance for
        #           all users including _attacker/_host_* via become
        #           transitive closure + group/clearance inheritance.
        #   Pass 2: policy evaluation — permit/deny with flat expanded
        #           facts from pass 1 (no recursion, no become).
        # This avoids μZ crashes caused by become transitive closure
        # interacting with permit/deny in a single Fixedpoint.
        # Initialize CVE data defaults
        self._cve_rce_list: list = []
        self._cve_pkg_to_service: dict = {}
        self._cve_alias_map: dict = {}
        self._cve_host_reach: dict = {}
        self._cve_external_services: list = []
        self.cve_triage_log: list = []

        if self.cve_enabled:
            self._prepare_cve_data()
        expanded = self._build_become_fp()  # Pass 1
        self.expanded_facts = expanded      # exposed for visualizer/audit
        self._build_policy_fp(expanded)     # Pass 2

    # ---- sorts ----

    @staticmethod
    def _make_bv_sort(name: str, values: list) -> tuple:
        """Create a BitVecSort + name→constant mapping for the Datalog engine."""
        n = len(values) if values else 1
        bits = max(1, math.ceil(math.log2(n + 1)))
        sort = BitVecSort(bits)
        consts = {v: BitVecVal(i, bits) for i, v in enumerate(values)}
        return sort, consts

    def _build_sorts(self):
        cat = self.catalog

        # Collect all action strings from rules
        actions = set()
        for r in self.raw_rules:
            actions.add(r["action"])
        actions.add("*")

        # Collect all service names from rules + catalog
        svc_names = set(cat["service_names"])
        for r in self.raw_rules:
            rc = r.get("resource_condition", {})
            s = rc.get("service", {})
            if isinstance(s, dict) and "equals" in s:
                svc_names.add(s["equals"])

        # Ensure sshd is in the sort when CVE escalation is enabled —
        # LLMs frequently extract ssh:login rules without adding sshd
        # as a catalog service. The escalation layer infers sshd from
        # ssh:login rules, but needs the sort to exist.
        if self.cve_enabled:
            svc_names.add("sshd")

        user_names = [u["name"] for u in cat["users"]]

        # Synthetic identities for CVE escalation modeling:
        #
        #   _attacker    — starts with ZERO attributes (no groups, no
        #                  clearance). Its only initial capabilities are
        #                  can_reach facts derived from externally-exposed
        #                  services in the policy. Every SAT verdict for
        #                  _attacker must trace through a become edge,
        #                  making kill-chain attribution trivial.
        #
        #   _host_<hg>   — identity of a compromised host. Receives ALL
        #                  groups and highest clearance (sound worst-case
        #                  over-approximation: models root-level compromise,
        #                  not the actual post-exploitation user like
        #                  www-data). UNSAT results are true negatives;
        #                  SAT results are upper-bound reachability.
        if self.cve_enabled:
            if "_attacker" not in user_names:
                user_names.append("_attacker")
            for hg in cat["host_groups"]:
                host_id = f"_host_{hg}"
                if host_id not in user_names:
                    user_names.append(host_id)

        group_names = cat["groups"] if cat["groups"] else ["_no_group"]
        cl = cat["clearance_levels"] if cat["clearance_levels"] else ["_none"]
        hg = cat["host_groups"] if cat["host_groups"] else ["_no_hg"]
        svc_list = sorted(svc_names) if svc_names else ["_no_svc"]
        action_names = sorted(_safe_enum_name(a) for a in actions)

        self.UserSort, self.users = self._make_bv_sort("User", user_names)
        self.GroupSort, self.groups = self._make_bv_sort("Group", group_names)
        self.ClearanceSort, self.clearances = self._make_bv_sort("Clearance", cl)
        self.HostGroupSort, self.host_groups = self._make_bv_sort("HostGroup", hg)
        self.ServiceSort, self.services = self._make_bv_sort("Service", svc_list)
        self.ActionSort, self.actions = self._make_bv_sort("Action", action_names)

        self._action_map = {a: _safe_enum_name(a) for a in actions}

    # ---- shared relation declarations ----

    def _make_relations(self):
        """Create relation Function objects (shared across both passes)."""
        self.in_group = Function("in_group", self.UserSort, self.GroupSort, BoolSort())
        self.has_clearance = Function("has_clearance", self.UserSort, self.ClearanceSort, BoolSort())
        self.permit = Function(
            "permit", self.UserSort, self.HostGroupSort, self.ServiceSort, self.ActionSort, BoolSort()
        )
        self.deny = Function(
            "deny", self.UserSort, self.HostGroupSort, self.ServiceSort, self.ActionSort, BoolSort()
        )
        self.become = Function("become", self.UserSort, self.UserSort, BoolSort())
        self.can_reach = Function(
            "can_reach", self.UserSort, self.HostGroupSort, self.ServiceSort, BoolSort()
        )

        # Shared universally quantified variables
        self.v_user = Const("u", self.UserSort)
        self.v_user2 = Const("u2", self.UserSort)
        self.v_user3 = Const("u3", self.UserSort)
        self.v_hg = Const("hg", self.HostGroupSort)
        self.v_svc = Const("svc", self.ServiceSort)
        self.v_act = Const("act", self.ActionSort)
        self.v_grp = Const("g", self.GroupSort)
        self.v_cl = Const("c", self.ClearanceSort)

    # ---- Pass 1: become closure (attack graph) ----

    def _build_become_fp(self) -> dict[str, dict]:
        """Compute become transitive closure and expand in_group/has_clearance.

        Returns {user_name: {"groups": set[str], "clearances": set[str]}}
        with all derived facts from become inheritance.
        """
        self._make_relations()

        fp1 = Fixedpoint()
        fp1.set(engine="datalog")
        fp1.register_relation(self.in_group, self.has_clearance,
                              self.become, self.can_reach)
        fp1.declare_var(self.v_user, self.v_user2, self.v_user3,
                        self.v_grp, self.v_cl, self.v_hg, self.v_svc)

        # become rules: reflexive + transitive
        fp1.rule(self.become(self.v_user, self.v_user), [],
                 name="become_refl")
        fp1.rule(self.become(self.v_user, self.v_user3),
                 [self.become(self.v_user, self.v_user2),
                  self.become(self.v_user2, self.v_user3)],
                 name="become_trans")

        # Attribute inheritance through become
        fp1.rule(self.in_group(self.v_user, self.v_grp),
                 [self.become(self.v_user, self.v_user2),
                  self.in_group(self.v_user2, self.v_grp)],
                 name="become_inherit_group")
        fp1.rule(self.has_clearance(self.v_user, self.v_cl),
                 [self.become(self.v_user, self.v_user2),
                  self.has_clearance(self.v_user2, self.v_cl)],
                 name="become_inherit_clearance")

        # Assert base EDB facts (catalog users)
        for u in self.catalog["users"]:
            name = u["name"]
            if name not in self.users:
                continue
            uc = self.users[name]
            for g in u.get("groups", []):
                if g in self.groups:
                    fp1.fact(self.in_group(uc, self.groups[g]))
            cl = u.get("clearance")
            if cl and cl in self.clearances:
                fp1.fact(self.has_clearance(uc, self.clearances[cl]))

        # Assert CVE escalation facts + rules (if enabled)
        if self.cve_enabled and self._cve_rce_list:
            attacker = self.users.get("_attacker")
            highest_cl = max(self.clearances.keys(), key=lambda c: c) if self.clearances else None

            # _host_* identities get all groups + max clearance
            for hg_name in self.catalog["host_groups"]:
                host_id = f"_host_{hg_name}"
                if host_id not in self.users:
                    continue
                hc = self.users[host_id]
                for _, gc in self.groups.items():
                    fp1.fact(self.in_group(hc, gc))
                if highest_cl:
                    fp1.fact(self.has_clearance(hc, self.clearances[highest_cl]))

            # Attacker can_reach externally-exposed services
            if attacker is not None:
                for svc_name, hg_name in set(self._cve_external_services):
                    if svc_name in self.services and hg_name in self.host_groups:
                        fp1.fact(self.can_reach(
                            attacker, self.host_groups[hg_name],
                            self.services[svc_name]))

            # CVE become rules
            for pkg, cve_id in self._cve_rce_list:
                resolved = self._cve_alias_map.get(pkg, pkg)
                targets = self._cve_pkg_to_service.get(resolved, [])
                if not targets:
                    for alias, canonical in self._cve_alias_map.items():
                        if pkg in alias or alias in pkg:
                            targets.extend(self._cve_pkg_to_service.get(canonical, []))
                            break
                for svc_name, hg_name in targets:
                    if svc_name not in self.services or hg_name not in self.host_groups:
                        continue
                    host_id = f"_host_{hg_name}"
                    if host_id not in self.users:
                        continue
                    fp1.rule(
                        self.become(self.v_user, self.users[host_id]),
                        [self.can_reach(self.v_user,
                                        self.host_groups[hg_name],
                                        self.services[svc_name])],
                        name=f"cve_{cve_id}_{svc_name}_{hg_name}")
                    # Host lateral movement
                    for reach_svc, reach_hg in self._cve_host_reach.get(hg_name, []):
                        if reach_svc in self.services and reach_hg in self.host_groups:
                            fp1.fact(self.can_reach(
                                self.users[host_id],
                                self.host_groups[reach_hg],
                                self.services[reach_svc]))

            print(f"[cve] {len(self._cve_rce_list)} escalation rules "
                  f"from {len(self._cve_rce_list)} RCE CVEs")

        # ---- Solve pass 1 and extract expanded facts ----
        expanded: dict[str, dict] = {}
        for uname, uc in self.users.items():
            groups: set[str] = set()
            clearances: set[str] = set()
            for gname, gc in self.groups.items():
                if fp1.query(self.in_group(uc, gc)) == sat:
                    groups.add(gname)
            for cname, cc in self.clearances.items():
                if fp1.query(self.has_clearance(uc, cc)) == sat:
                    clearances.add(cname)
            expanded[uname] = {"groups": groups, "clearances": clearances}

        return expanded

    # ---- Pass 2: policy evaluation (permit/deny) ----

    def _build_policy_fp(self, expanded: dict[str, dict]):
        """Build the policy Fixedpoint with flat expanded facts.

        No become, no can_reach, no recursion — just permit/deny rules
        over flat in_group/has_clearance facts.

        Creates fresh Function objects to avoid Z3 context conflicts
        with the Pass 1 Fixedpoint.
        """
        self.fp = Fixedpoint()
        self.fp.set(engine="datalog")
        # Note: `datalog.generate_explanations = True` would let
        # `fp.get_answer()` return a derivation tree for failed queries,
        # but it crashes Z3's μZ engine (SIGSEGV inside
        # Z3_fixedpoint_query) on some rule shapes — reliably reproduced
        # on kimi-k2.6's f1/f5 policies when a wildcard-action permit
        # query runs after the Pass-1 become closure populates `_host_*`
        # identities. Disabled globally: verdicts are unaffected, only
        # the `explanation` string for failed queries degrades to
        # "reachable / no permit" instead of the derivation tree.

        # Fresh relations for pass 2 (avoid sharing with pass 1 FP)
        self.in_group = Function("in_group", self.UserSort, self.GroupSort, BoolSort())
        self.has_clearance = Function("has_clearance", self.UserSort, self.ClearanceSort, BoolSort())
        self.permit = Function(
            "permit", self.UserSort, self.HostGroupSort, self.ServiceSort, self.ActionSort, BoolSort()
        )
        self.deny = Function(
            "deny", self.UserSort, self.HostGroupSort, self.ServiceSort, self.ActionSort, BoolSort()
        )

        self.fp.register_relation(self.in_group, self.has_clearance,
                                  self.permit, self.deny)

        # Fresh variables
        self.v_user = Const("u", self.UserSort)
        self.v_hg = Const("hg", self.HostGroupSort)
        self.v_svc = Const("svc", self.ServiceSort)
        self.v_act = Const("act", self.ActionSort)
        self.v_grp = Const("g", self.GroupSort)
        self.v_cl = Const("c", self.ClearanceSort)
        self.fp.declare_var(self.v_user, self.v_hg, self.v_svc, self.v_act,
                            self.v_grp, self.v_cl)

        # Assert expanded in_group/has_clearance facts (flat, no recursion)
        for uname, facts in expanded.items():
            if uname not in self.users:
                continue
            uc = self.users[uname]
            for g in facts["groups"]:
                if g in self.groups:
                    self.fp.fact(self.in_group(uc, self.groups[g]))
            for c in facts["clearances"]:
                if c in self.clearances:
                    self.fp.fact(self.has_clearance(uc, self.clearances[c]))

        # Assert ABAC permit/deny rules
        self._assert_rules()

    # ---- rule encoding ----

    def _assert_rules(self):
        for rule in self.raw_rules:
            rule_id = rule.get("id", "unknown")
            effect = rule.get("effect", "permit")
            action_raw = rule.get("action", "*")
            action_safe = self._action_map.get(action_raw, _safe_enum_name(action_raw))

            if action_safe not in self.actions:
                print(f"  [warn] skipping {rule_id}: unknown action {action_raw}")
                continue

            action_const = self.actions[action_safe]
            sc = rule.get("subject_condition", {})
            rc = rule.get("resource_condition", {})

            # Guard: skip `action: *` + `effect: permit` rules whose
            # subject condition is trivially universal (`applies_to: all`
            # or empty). These over-permissive catch-alls let synthetic
            # attacker identities satisfy any wildcard-fallback query
            # regardless of chain construction, defeating kill-chain
            # attribution. Real policy intent isn't lost — meaningful
            # `*` permits (e.g. `subject: {groups: sudo}, action: *`)
            # are kept; this only drops the catch-all variety.
            if effect == "permit" and action_raw == "*" and (
                not isinstance(sc, dict) or not sc
                or "applies_to" in sc
                or not (sc.get("groups") or sc.get("clearance"))
            ):
                continue

            # Resolve resource constants
            hg_val = rc.get("host_group", {}).get("equals") if isinstance(rc.get("host_group"), dict) else None
            svc_val = rc.get("service", {}).get("equals") if isinstance(rc.get("service"), dict) else None

            # Default to wildcard-ish if not specified
            hg_options = [self.host_groups[hg_val]] if hg_val and hg_val in self.host_groups else [self.v_hg]
            svc_options = [self.services[svc_val]] if svc_val and svc_val in self.services else [self.v_svc]

            # Build subject condition branches (expand disjunctions)
            subject_branches = self._expand_subject_condition(sc)

            # Target relation
            target_fn = self.deny if effect == "deny" else self.permit

            for branch_atoms in subject_branches:
                for hg_c, svc_c in cartesian(hg_options, svc_options):
                    head = target_fn(self.v_user, hg_c, svc_c, action_const)
                    self.fp.rule(head, branch_atoms, name=rule_id)

    def _expand_subject_condition(self, sc: dict) -> list:
        """Expand subject_condition into list of body-atom lists.

        Each entry in the returned list is one branch (conjunction of atoms).
        Multiple entries represent disjunction (one Horn clause per branch).
        """
        if not sc:
            return [[]]  # unconditional

        # Handle applies_to: all (catch-all sentinel for deny/permit)
        if "applies_to" in sc:
            return [[]]  # matches all users

        # Collect conjunctive conditions, expanding disjunctions via cartesian product
        # Each condition produces a list of alternatives
        condition_alternatives = []

        # Groups
        groups_cond = sc.get("groups", {})
        if groups_cond:
            group_atoms = self._expand_group_condition(groups_cond)
            if group_atoms:
                condition_alternatives.append(group_atoms)

        # Clearance
        clearance_cond = sc.get("clearance", {})
        if clearance_cond:
            clearance_atoms = self._expand_clearance_condition(clearance_cond)
            if clearance_atoms:
                condition_alternatives.append(clearance_atoms)

        # Source IP / network (for network-layer rules — skip for now, not user-bound)
        if "source_ip" in sc or "source_network" in sc or "source_zone" in sc:
            # Network-layer rules don't bind to User sort; skip in this encoding
            return [[]]

        if not condition_alternatives:
            return [[]]

        # Cartesian product of all condition alternatives
        # Each element of condition_alternatives is a list of alternatives
        # (each alternative is a list of Z3 atoms). The cartesian product
        # gives all combinations, one alternative per condition.
        branches = []
        for combo in cartesian(*condition_alternatives):
            branch = []
            for atom_list in combo:
                branch.extend(atom_list)
            branches.append(branch)

        return branches

    def _expand_group_condition(self, cond: dict) -> list:
        """Returns list of alternatives, each being a list of Z3 atoms."""
        if "equals" in cond:
            g = cond["equals"]
            if g in self.groups:
                return [[self.in_group(self.v_user, self.groups[g])]]
            return []
        if "any_of" in cond:
            alts = []
            for g in cond["any_of"]:
                if g in self.groups:
                    alts.append([self.in_group(self.v_user, self.groups[g])])
            return alts if alts else []
        if "all_of" in cond:
            atoms = []
            for g in cond["all_of"]:
                if g in self.groups:
                    atoms.append(self.in_group(self.v_user, self.groups[g]))
            return [atoms] if atoms else []
        if "in" in cond:
            alts = []
            for g in cond["in"]:
                if g in self.groups:
                    alts.append([self.in_group(self.v_user, self.groups[g])])
            return alts if alts else []
        return []

    def _expand_clearance_condition(self, cond: dict) -> list:
        """Returns list of alternatives, each being a list of Z3 atoms."""
        if "equals" in cond:
            c = cond["equals"]
            if c in self.clearances:
                return [[self.has_clearance(self.v_user, self.clearances[c])]]
            return []
        if "in" in cond or "any_of" in cond:
            values = cond.get("in") or cond.get("any_of")
            alts = []
            for c in values:
                if c in self.clearances:
                    alts.append([self.has_clearance(self.v_user, self.clearances[c])])
            return alts if alts else []
        return []

    # ---- CPE product pre-filter ----

    @staticmethod
    def _cpe_matches_package(cve: dict, pkg: str,
                             pkg_to_service: dict, alias_map: dict) -> bool:
        """Check if a CVE's product metadata plausibly matches the package.

        Uses the LLM-emitted product/package field from the CVE object.
        When available, checks against known service aliases. This is a
        lightweight heuristic — not a full CPE match — that catches the
        most common LLM failure mode: filing a Cisco/SonicWall/NVIDIA CVE
        under mysql/httpd/haproxy because the search query mentioned that
        product.
        """
        # Build the set of acceptable product names for this package
        acceptable = {pkg}
        # Add alias targets (e.g., "mysql-server" → "mysql")
        resolved = alias_map.get(pkg, pkg)
        acceptable.add(resolved)
        # Add reverse aliases (all aliases that map to the same canonical)
        for alias, canonical in alias_map.items():
            if canonical == resolved:
                acceptable.add(alias)
        # Add the service names themselves
        for svc_name, _ in pkg_to_service.get(resolved, []):
            acceptable.add(svc_name.lower())

        # Check the CVE's description for product-mismatch signals.
        # If the description explicitly names a different vendor product,
        # that's a strong mismatch signal.
        desc = (cve.get("description") or "").lower()
        if not desc:
            return True  # no description to check — admit conservatively

        # Known vendor products that are NOT the package in question
        mismatch_vendors = [
            ("cisco", "cisco"), ("sonicwall", "sonicwall"),
            ("nvidia", "nvidia"), ("vmware", "vmware"),
            ("sap ", "sap"), ("microsoft", "microsoft"),
            ("apple ", "apple"), ("solaris", "solaris"),
            ("influxdb", "influxdb"), ("grafana", "grafana"),
            ("wordpress", "wordpress"), ("roundcube", "roundcube"),
            ("owncloud", "owncloud"), ("dolibarr", "dolibarr"),
            ("asus ", "asus"), ("trend micro", "trend micro"),
            ("nifi", "apache nifi"),
        ]
        for trigger, vendor_name in mismatch_vendors:
            if trigger in desc and vendor_name not in acceptable:
                return False

        return True

    # ---- CVE data preparation (triage + mappings, no FP assertions) ----

    def _prepare_cve_data(self):
        """Triage CVEs and build mappings for the become closure pass.

        Sets self._cve_rce_list, self._cve_pkg_to_service,
        self._cve_alias_map, self._cve_host_reach, self._cve_external_services.
        """
        # Map package names to (service, host_group) tuples
        # ---- Derive pkg→service and lateral-movement maps from policy ----

        # 1. Build pkg_to_service from catalog: services tell us which
        #    service name runs on which host_group.
        #    e.g. {"name": "postgresql", "host_group": "dbservers"} →
        #         "postgresql" → [("postgresql", "dbservers")]
        pkg_to_service: dict[str, list[tuple[str, str]]] = {}
        for svc in self.catalog.get("hosts", []):
            pass  # hosts don't carry service info
        # Catalog services: each has (name, host_group)
        cat = self.raw_attrs.get("catalog") or {}
        svc_list = cat.get("services", [])
        if not svc_list:
            res = self.raw_attrs.get("resources", {})
            svc_list = res.get("services", []) if isinstance(res, dict) else []
        # Unwrap schema-first envelope if present
        if isinstance(svc_list, dict) and "domain" in svc_list:
            svc_list = svc_list["domain"]
        # Track services declared in catalog without host_group — we'll
        # try to resolve them from rules below.
        unresolved_svcs: list[str] = []
        for svc in svc_list:
            # LLMs sometimes emit services as bare strings instead of
            # dicts; normalize before extracting name/host_group.
            if isinstance(svc, str):
                svc_name, hg = svc, ""
            elif isinstance(svc, dict):
                svc_name = svc.get("name", "") or ""
                hg = svc.get("host_group", "") or ""
            else:
                continue
            if svc_name and hg and hg != "all":
                pkg_to_service.setdefault(svc_name.lower(), []).append((svc_name, hg))
            elif svc_name and hg == "all":
                for hg_name in self.catalog["host_groups"]:
                    pkg_to_service.setdefault(svc_name.lower(), []).append((svc_name, hg_name))
            elif svc_name:
                unresolved_svcs.append(svc_name)

        # ---- Resolve service→host_group from rules ----
        # Many LLMs emit services as bare {"name": X} without host_group.
        # The actual placement is often present in rules:
        #   permit ... resource: {service: {equals: X}, host_group: {equals: H}}
        # Harvest those mappings (also from hostname / zone references).
        rule_svc_hgs: dict[str, set[str]] = {}
        host_lookup_by_name = {h.get("hostname"): h for h in self.catalog.get("hosts", [])
                               if h.get("hostname")}
        host_lookup_by_zone: dict[str, list[dict]] = {}
        for h in self.catalog.get("hosts", []):
            zone = h.get("zone")
            if zone:
                host_lookup_by_zone.setdefault(zone, []).append(h)

        for rule in self.raw_rules:
            rc = rule.get("resource_condition", {})
            svc_cond = rc.get("service", {})
            svc_name = (svc_cond.get("equals")
                        if isinstance(svc_cond, dict) else None)
            if not svc_name:
                continue
            hgs: set[str] = set()
            hg_cond = rc.get("host_group", {})
            if isinstance(hg_cond, dict):
                if hg_cond.get("equals"):
                    hgs.add(hg_cond["equals"])
                for k in ("in", "any_of"):
                    vals = hg_cond.get(k)
                    if isinstance(vals, list):
                        hgs.update(vals)
            # hostname → inventory_group
            host_cond = rc.get("hostname", {})
            host_name = (host_cond.get("equals")
                         if isinstance(host_cond, dict) else None)
            if host_name and host_name in host_lookup_by_name:
                h = host_lookup_by_name[host_name]
                inferred = h.get("inventory_group") or h.get("host_group")
                if inferred:
                    hgs.add(inferred)
            # zone → inventory_group(s)
            zone_cond = rc.get("zone", {})
            zone = (zone_cond.get("equals")
                    if isinstance(zone_cond, dict) else None)
            if zone and zone in host_lookup_by_zone:
                for h in host_lookup_by_zone[zone]:
                    inferred = h.get("inventory_group") or h.get("host_group")
                    if inferred:
                        hgs.add(inferred)
            for hg in hgs:
                if hg in self.catalog["host_groups"]:
                    rule_svc_hgs.setdefault(svc_name.lower(), set()).add(hg)

        # Apply rule-derived placements: fill in any service that wasn't
        # already resolved via catalog metadata.
        for svc_name in list(unresolved_svcs):
            key = svc_name.lower()
            if key in pkg_to_service:
                continue  # somehow resolved already
            for hg in sorted(rule_svc_hgs.get(key, set())):
                pkg_to_service.setdefault(key, []).append((svc_name, hg))
        # Also augment partially-resolved catalog services with rule-derived
        # placements (a service may run on more host_groups than the catalog
        # declared, especially for services whose catalog lists only one tier).
        for key, hgs in rule_svc_hgs.items():
            existing_hgs = {hg for (_, hg) in pkg_to_service.get(key, [])}
            for hg in sorted(hgs - existing_hgs):
                # Find original-cased service name from catalog if present
                orig_name = next((s.get("name") for s in svc_list
                                  if s.get("name", "").lower() == key
                                  and isinstance(s, dict)), key)
                pkg_to_service.setdefault(key, []).append((orig_name, hg))

        # Derive sshd service entries when the LLM omitted sshd from the
        # services catalog (common extraction gap). Two sources:
        #   1. ssh:login rules → infer which host_groups have sshd
        #   2. If openssh CVEs are present and ssh:login rules exist,
        #      assume sshd runs on ALL host_groups (openssh is ubiquitous)
        if "sshd" not in pkg_to_service:
            sshd_hgs = set()
            for rule in self.raw_rules:
                if rule.get("action") != "ssh:login" or rule.get("effect") != "permit":
                    continue
                rc = rule.get("resource_condition", {})
                # Try host_group directly
                hg = (rc.get("host_group", {}).get("equals")
                      if isinstance(rc.get("host_group"), dict) else None)
                # Try zone → host_group mapping
                if not hg:
                    zone = (rc.get("zone", {}).get("equals")
                            if isinstance(rc.get("zone"), dict) else None)
                    if zone:
                        for h in self.catalog.get("hosts", []):
                            if h.get("zone") == zone:
                                hg = h.get("inventory_group") or h.get("host_group")
                                break
                # Try hostname → host_group mapping
                if not hg:
                    hostname = (rc.get("hostname", {}).get("equals")
                                if isinstance(rc.get("hostname"), dict) else None)
                    if hostname:
                        for h in self.catalog.get("hosts", []):
                            if h.get("hostname") == hostname:
                                hg = h.get("inventory_group") or h.get("host_group")
                                break
                if hg and hg in self.catalog["host_groups"]:
                    sshd_hgs.add(hg)

            # If ssh:login rules exist but don't cover all host_groups,
            # and openssh CVEs are present, extend to all host_groups —
            # openssh-server is typically installed everywhere.
            if sshd_hgs:
                has_openssh_vuln = any(
                    (v.get("package") or v.get("product", "")).lower()
                    in ("openssh", "openssh-server")
                    for v in self.raw_vulns
                    if isinstance(v, dict)
                )
                if has_openssh_vuln:
                    sshd_hgs = set(self.catalog["host_groups"])

            for hg in sorted(sshd_hgs):
                pkg_to_service.setdefault("sshd", []).append(("sshd", hg))
            if "sshd" in pkg_to_service:
                print(f"[cve] inferred sshd service on: "
                      f"{sorted(sshd_hgs)}")

        # Also map common package-name variants to service names
        # (e.g. "openssh-server" → "sshd", "nginx" → "nginx")
        alias_map = {}
        for svc_name_lower in pkg_to_service:
            alias_map[svc_name_lower] = svc_name_lower
        # Common aliases: package name ≠ service name
        for alias, canonical in [
            ("openssh-server", "sshd"), ("openssh", "sshd"),
            ("postgres", "postgresql"), ("postgresql-server", "postgresql"),
            ("nginx-core", "nginx"), ("nginx-server", "nginx"),
            ("apache2", "httpd"), ("httpd", "httpd"),
            ("apache_httpd", "httpd"), ("apache-httpd", "httpd"),
            ("apache", "httpd"), ("apache_http_server", "httpd"),
            ("mariadb-server", "mariadb"), ("mysql-server", "mysql"),
            ("redis-server", "redis"),
            ("haproxy", "haproxy"),
            ("log4j", "log4j"), ("log4j-core", "log4j"),
        ]:
            if canonical in pkg_to_service:
                alias_map[alias] = canonical

        # Fallback: when the catalog lists a service but no rule references
        # it AND the service appears as a CVE target, assume worst-case
        # placement on every host_group. UNSAT verdicts remain sound; SAT
        # verdicts become upper-bound (consistent with the encoder's overall
        # over-approximation stance for CVE escalation).
        cve_pkg_names: set[str] = set()
        for v in self.raw_vulns if isinstance(self.raw_vulns, list) else []:
            if not isinstance(v, dict):
                continue
            for key in ("product", "package"):
                val = v.get(key)
                if isinstance(val, str) and val:
                    cve_pkg_names.add(val.lower())
            # Nested cves[].product
            for sub in v.get("cves", []) if isinstance(v.get("cves"), list) else []:
                if isinstance(sub, dict):
                    for key in ("product", "package"):
                        val = sub.get(key)
                        if isinstance(val, str) and val:
                            cve_pkg_names.add(val.lower())

        for svc_name in unresolved_svcs:
            key = svc_name.lower()
            if pkg_to_service.get(key):
                continue
            # Resolve via aliases too (e.g. CVE pkg "apache_httpd" → svc "httpd")
            cve_resolved_keys = {alias for alias, canonical in alias_map.items()
                                 if canonical == key}
            cve_resolved_keys.add(key)
            if cve_pkg_names & cve_resolved_keys:
                for hg_name in self.catalog["host_groups"]:
                    pkg_to_service.setdefault(key, []).append(
                        (svc_name, hg_name))

        # 2. Derive host_network_reach from network:connect permit rules.
        #
        # The intended structure is:
        #     {compromised_host_group: [(target_svc, target_host_group), ...]}
        # i.e. "if host_group A is owned, which (service, host_group) pairs
        # can it reach laterally via the policy's network rules?"
        #
        # The raw rules express sources as either explicit IPs (matched
        # against catalog hosts) or subnet CIDRs (no direct host_group
        # binding). Mined policies in this campaign carry few or no host
        # entries with IPs, so the IP-matching path is usually empty.
        #
        # Fallback inference (used when no catalog IPs are available):
        # network:connect permit rules in tiered scenarios tend to appear
        # in chain order — `external → A`, then `A's-subnet → B`, then
        # `B's-subnet → C`, etc. Walk rules in their listed order and
        # bind each non-public source subnet to the previous rule's
        # target host_group. Targets missing host_group fall back to a
        # service → host_group lookup via pkg_to_service.
        host_network_reach: dict[str, list[tuple[str, str]]] = {}
        ip_to_hg: dict[str, str] = {}
        for h in self.catalog.get("hosts", []):
            ip = h.get("ip", "")
            hg = h.get("inventory_group") or h.get("host_group", "")
            if ip and hg:
                ip_to_hg[ip] = hg
                ip_to_hg[f"{ip}/32"] = hg

        import ipaddress as _ipa

        def _is_public_cidr(s: str) -> bool:
            if not isinstance(s, str):
                return False
            try:
                net = _ipa.ip_network(s, strict=False)
            except (ValueError, TypeError):
                return False
            return net.num_addresses > 1 and not net.is_private

        def _hg_for_service(svc_name: str | None) -> str | None:
            if not svc_name:
                return None
            for entries in pkg_to_service.values():
                for s, h in entries:
                    if s == svc_name and h in self.catalog.get("host_groups", []):
                        return h
            return None

        # Port → likely service names. Used when the LLM emits a
        # network:connect rule with `port` but omits `service`; we
        # cross-reference the candidate names against services
        # actually present on the rule's target host_group.
        _PORT_TO_SVC_CANDIDATES = {
            22: ("sshd", "ssh"),
            25: ("smtp", "postfix", "exim"),
            53: ("dns", "bind", "named"),
            80: ("httpd", "nginx", "apache", "http", "web"),
            443: ("httpd", "nginx", "apache", "https", "web"),
            3306: ("mysqld", "mysql", "mariadb"),
            5432: ("postgresql", "postgres", "postgresd"),
            6379: ("redis", "redis-server"),
            8080: ("app", "tomcat", "httpd", "nginx", "java"),
            8443: ("app", "tomcat", "httpd"),
            27017: ("mongodb", "mongod"),
        }

        def _svc_for_port_and_hg(port_val, hg_name: str | None) -> str | None:
            """When a network rule omits `service`, infer it from the
            port plus what services the target host_group actually has
            (per the policy's vulnerability catalog). Returns None if
            no candidate matches a service the policy actually pins to
            this host_group — we don't fabricate services."""
            try:
                port_int = int(port_val)
            except (TypeError, ValueError):
                return None
            candidates = _PORT_TO_SVC_CANDIDATES.get(port_int, ())
            if not candidates or not hg_name:
                return None
            svcs_on_hg = {
                s for entries in pkg_to_service.values()
                for (s, h) in entries if h == hg_name
            }
            for c in candidates:
                if c in svcs_on_hg:
                    return c
            return None

        def _safe_dict(v) -> dict:
            return v if isinstance(v, dict) else {}

        def _equals(d) -> str | None:
            d = _safe_dict(d)
            v = d.get("equals")
            return v if isinstance(v, str) else None

        def _target_svc_of(rule) -> str | None:
            if not isinstance(rule, dict):
                return None
            rc = _safe_dict(rule.get("resource_condition"))
            v = _equals(rc.get("service"))
            if v:
                return v
            return _svc_for_port_and_hg(
                _equals(rc.get("port")),
                _equals(rc.get("host_group")),
            )

        ordered_netrules = [
            r for r in self.raw_rules
            if r.get("action") == "network:connect"
            and r.get("effect") == "permit"
        ]

        # Pass 2a: bind each non-public source subnet to the previous
        # rule's target host_group (chain heuristic).
        subnet_to_hg: dict[str, str] = {}
        last_target_hg: str | None = None
        for rule in ordered_netrules:
            if not isinstance(rule, dict):
                continue
            sc = _safe_dict(rule.get("subject_condition"))
            rc = _safe_dict(rule.get("resource_condition"))
            src_net = _equals(sc.get("source_network")) or _equals(sc.get("source_ip"))
            target_hg = _equals(rc.get("host_group")) or _hg_for_service(_equals(rc.get("service")))
            if (src_net and not _is_public_cidr(src_net)
                    and last_target_hg and src_net not in subnet_to_hg):
                subnet_to_hg[src_net] = last_target_hg
            if target_hg:
                last_target_hg = target_hg

        # Pass 2b: build the lateral movement map. IP-bound sources go
        # through ip_to_hg; subnet-bound sources go through subnet_to_hg.
        for rule in ordered_netrules:
            if not isinstance(rule, dict):
                continue
            sc = _safe_dict(rule.get("subject_condition"))
            rc = _safe_dict(rule.get("resource_condition"))
            src_ips: list[str] = []
            for key in ("source_ip", "source_network"):
                val = sc.get(key)
                if isinstance(val, dict):
                    if isinstance(val.get("in"), list):
                        src_ips.extend(str(x) for x in val["in"])
                    elif isinstance(val.get("any_of"), list):
                        src_ips.extend(str(x) for x in val["any_of"])
                    elif isinstance(val.get("equals"), str):
                        src_ips.append(val["equals"])
            src_hgs: set[str] = set()
            for ip in src_ips:
                stripped = ip.rstrip("/32") if ip.endswith("/32") else ip
                if ip in ip_to_hg:
                    src_hgs.add(ip_to_hg[ip])
                elif stripped in ip_to_hg:
                    src_hgs.add(ip_to_hg[stripped])
                elif ip in subnet_to_hg:
                    src_hgs.add(subnet_to_hg[ip])
            target_svc = _target_svc_of(rule)
            target_hg = _equals(rc.get("host_group")) or _hg_for_service(target_svc)
            if target_svc and target_hg:
                for shg in src_hgs:
                    host_network_reach.setdefault(shg, []).append(
                        (target_svc, target_hg))

        # 3. Derive externally-exposed services. Only count services
        # whose permit rule has a publicly-routable source_network
        # (e.g. 0.0.0.0/0). Group-based SSH rules WITHOUT a public
        # source are auth-required services on internal networks, not
        # externally reachable — flagging them inflates _attacker's
        # initial reach and lets the kill-chain query trivially pass.
        external_services: list[tuple[str, str]] = []
        for rule in self.raw_rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("effect") != "permit":
                continue
            if rule.get("action") != "network:connect":
                continue
            sc = _safe_dict(rule.get("subject_condition"))
            rc = _safe_dict(rule.get("resource_condition"))
            svc_val = _target_svc_of(rule)
            hg_val = _equals(rc.get("host_group")) or _hg_for_service(svc_val)
            if not hg_val or not svc_val:
                continue
            src_net = _equals(sc.get("source_network"))
            if _is_public_cidr(src_net):
                external_services.append((svc_val, hg_val))
                if svc_val.lower() == "ssh":
                    for s_entries in pkg_to_service.values():
                        for (s, h) in s_entries:
                            if h == hg_val and s.lower() == "sshd":
                                external_services.append((s, hg_val))

        # ---- Parse CVEs with strict admission gates ----
        vulns_list = self.raw_vulns
        if isinstance(vulns_list, dict):
            vulns_list = vulns_list.get("findings", [])

        # Flatten nested package→cves structures into a flat list,
        # propagating package name and pinned version from parent.
        flat_vulns = []
        pkg_versions: dict[str, str] = {}  # package → pinned version
        for v in vulns_list:
            if "cves" in v and isinstance(v["cves"], list):
                pkg_name = v.get("package") or v.get("product", "")
                pkg_ver = v.get("version", "")
                if pkg_name and pkg_ver:
                    pkg_versions[pkg_name.lower()] = pkg_ver
                for cve in v["cves"]:
                    cve.setdefault("package", pkg_name)
                    cve.setdefault("product", pkg_name)
                    cve.setdefault("version", pkg_ver)
                    cve.setdefault("pinned_version", pkg_ver)
                    flat_vulns.append(cve)
            else:
                flat_vulns.append(v)
                pkg_name = (v.get("product") or v.get("package", "")).lower()
                pkg_ver = (v.get("pinned_version") or v.get("version", ""))
                if pkg_name and pkg_ver:
                    pkg_versions[pkg_name] = pkg_ver

        rce_cves = []
        self.cve_triage_log = []  # auditable admission log
        n_nvd_checks = 0
        for v in flat_vulns:
            cve_id = v.get("cve_id", "unknown")
            pkg = (v.get("product") or v.get("package", "")).lower()
            pinned_ver = (v.get("pinned_version") or v.get("version", "")
                          or pkg_versions.get(pkg, ""))
            # When source=="preprocessor", the deterministic preprocessor
            # has already run Gates 1 and 3 ahead of mining (see
            # rlm_agent/cve_preprocessor.py). For those entries the gates
            # run in advisory mode: a discrepancy is logged but the CVE is
            # still admitted, so a buggy preprocessor surfaces visibly
            # without silently dropping work the LLM was told to trust.
            advisory = v.get("source") == "preprocessor"

            # Gate 1: remotely exploitable (NVD CVSS attack vector).
            # Models inconsistently serialize is_remote (0-23% survival
            # rate across 5 models), so we verify mechanically from NVD
            # CVSS data instead of trusting the model's field.
            model_remote = v.get("is_remote")
            nvd_remote = nvd_is_remote(cve_id)
            is_rce = nvd_remote if nvd_remote is not None else (model_remote is True)
            if not is_rce:
                source = "nvd" if nvd_remote is not None else "model"
                decision = "admitted-advisory-not-remote" if advisory else "discarded-not-remote"
                self.cve_triage_log.append(
                    (cve_id, pkg, decision,
                     f"is_remote={is_rce} (source={source})"))
                if not advisory:
                    continue

            # Gate 2: CPE product pre-filter — reject CVEs whose
            # description names a different vendor product
            if not self._cpe_matches_package(v, pkg, pkg_to_service, alias_map):
                decision = "admitted-advisory-cpe-mismatch" if advisory else "discarded-cpe-mismatch"
                self.cve_triage_log.append(
                    (cve_id, pkg, decision,
                     f"CVE product does not match package '{pkg}'"))
                if not advisory:
                    continue

            # Gate 3: Mechanical version-range check via NVD API.
            # Replaces LLM's affects_pinned_version — the LLM should
            # discover CVE candidates, not assess version applicability.
            affects, reason = nvd_check_affects(cve_id, pkg, pinned_ver)
            n_nvd_checks += 1
            if not affects:
                decision = "admitted-advisory-version-range" if advisory else "discarded-version-range"
                self.cve_triage_log.append(
                    (cve_id, pkg, decision,
                     f"pinned={pinned_ver!r}: {reason}"))
                if not advisory:
                    continue

            self.cve_triage_log.append(
                (cve_id, pkg, "admitted", f"pinned={pinned_ver!r}: {reason}"))
            rce_cves.append((pkg, cve_id))

        # Print triage summary (counts per CVE, not per log entry: an
        # advisory-admitted CVE may produce multiple log lines).
        admitted = len(rce_cves)
        discarded = len(flat_vulns) - admitted
        advisory_overrides = sum(
            1 for *_, d, _ in self.cve_triage_log
            if isinstance(d, str) and d.startswith("admitted-advisory-")
        )
        advisory_note = (f" ({advisory_overrides} advisory gate overrides)"
                         if advisory_overrides else "")
        print(f"[cve] triage: {admitted} admitted, {discarded} discarded "
              f"out of {len(flat_vulns)} total "
              f"({n_nvd_checks} NVD version-range checks){advisory_note}")
        for cve_id, pkg, decision, reason in self.cve_triage_log:
            marker = "+" if decision == "admitted" else "-"
            print(f"  [{marker}] {cve_id} ({pkg}): {decision}"
                  + (f" — {reason}" if reason else ""))

        if not rce_cves:
            print("[cve] No RCE CVEs passed triage.")

        # Store for _build_become_fp to use
        self._cve_rce_list = rce_cves
        self._cve_pkg_to_service = pkg_to_service
        self._cve_alias_map = alias_map
        self._cve_host_reach = host_network_reach
        self._cve_external_services = external_services

    # ---- query interface ----

    def query(self, user: str, action: str, host_group: Optional[str] = None,
              service: Optional[str] = None) -> tuple:
        """Check if a user can perform an action.

        Returns (result, explanation) where result is 'sat', 'unsat', or 'unknown'.

        When the queried action is not in the policy's literal action
        vocabulary, fall back to the synthetic ``wildcard`` atom that
        represents ``action: *`` rules — so queries with ground-truth
        action tokens the LLM didn't produce (e.g. ``sudo:execute``) are
        still answered against any wildcard permit rules the policy
        defines, instead of returning an opaque ``Unknown action`` error.
        """
        if user not in self.users:
            return ("error", f"Unknown user: {user}")

        action_safe = _safe_enum_name(action)
        wildcard_fallback = False
        canonical_fallback = False
        if action_safe not in self.actions:
            # Qualified actions like 'db:login:superuser' usually capture a
            # role/level distinction the model encodes as a resource attribute
            # (e.g. resource.privilege_level=SUPERUSER) paired with the base
            # action 'db:login'. Try the base form before wildcard.
            if ":" in action:
                base = action.rsplit(":", 1)[0]
                base_safe = _safe_enum_name(base)
                if base_safe in self.actions:
                    action_safe = base_safe
                    canonical_fallback = True
            if not canonical_fallback:
                if "wildcard" not in self.actions:
                    return ("error", f"Unknown action: {action}")
                action_safe = "wildcard"
                wildcard_fallback = True

        u = self.users[user]
        a = self.actions[action_safe]

        if host_group and host_group in self.host_groups:
            hg = self.host_groups[host_group]
        else:
            hg = self.v_hg

        if service and service in self.services:
            svc = self.services[service]
        else:
            svc = self.v_svc

        # Two-pass query: check permit and deny separately, combine in
        # Python.  This avoids the stratified-negation requirement that
        # crashes μZ when become/can_reach feed back into deny via
        # inherited groups.
        permit_result = self.fp.query(self.permit(u, hg, svc, a))
        if permit_result != sat:
            if wildcard_fallback: suffix = " via wildcard fallback"
            elif canonical_fallback: suffix = f" via canonical action {action_safe!r}"
            else: suffix = ""
            return ("unsat", f"not reachable (no permit){suffix}")

        # Synthetic attack identities (_attacker, _host_*) bypass deny
        # rules. Deny rules represent network/policy enforcement intended
        # for real users; a CVE-compromised host has already breached
        # that enforcement layer. The encoder's documented stance is that
        # SAT for these identities is an upper-bound reachability claim,
        # not a policy violation. Real user identities still apply deny.
        is_synthetic_attacker = (
            user == "_attacker" or user.startswith("_host_")
        )
        if not is_synthetic_attacker:
            deny_result = self.fp.query(self.deny(u, hg, svc, a))
            if deny_result == sat:
                return ("unsat", "denied by policy")

        # permit=sat, deny!=sat → effective permit
        try:
            # Re-query permit for derivation trace
            self.fp.query(self.permit(u, hg, svc, a))
            answer = self.fp.get_answer()
            return ("sat", str(answer))
        except Exception:
            return ("sat", "reachable (no derivation available)")

    def query_permit_only(self, user: str, action: str, host_group: Optional[str] = None,
                          service: Optional[str] = None) -> tuple:
        """Check permit without deny-overrides (for debugging)."""
        if user not in self.users:
            return ("error", f"Unknown user: {user}")

        action_safe = _safe_enum_name(action)
        if action_safe not in self.actions:
            if ":" in action:
                base_safe = _safe_enum_name(action.rsplit(":", 1)[0])
                if base_safe in self.actions:
                    action_safe = base_safe
            if action_safe not in self.actions:
                if "wildcard" not in self.actions:
                    return ("error", f"Unknown action: {action}")
                action_safe = "wildcard"

        u = self.users[user]
        a = self.actions[action_safe]
        hg = self.host_groups.get(host_group, self.v_hg) if host_group else self.v_hg
        svc = self.services.get(service, self.v_svc) if service else self.v_svc

        result = self.fp.query(self.permit(u, hg, svc, a))
        if result == sat:
            try:
                answer = self.fp.get_answer()
                return ("sat", str(answer))
            except Exception:
                return ("sat", "reachable")
        elif result == unsat:
            return ("unsat", "not reachable")
        else:
            return ("unknown", str(result))


# ---------------------------------------------------------------------------
# 5. Smoke tests
# ---------------------------------------------------------------------------


def run_smoke_tests(encoder: ABACEncoder):
    """Run smoke tests showing policy-as-intended vs policy-as-effective.

    When CVE escalation is enabled, some policy-intended denials become
    effective permits — these are the kill chains the model discovers.
    """
    # (user, action, host_group, service, intended, reason)
    tests = [
        ("alice", "sudo:execute", "admin_bastion", None, "sat",
         "alice has sudo group + secret clearance → rule-002"),
        ("bob", "sudo:execute", "admin_bastion", None, "unsat",
         "bob lacks sudo group; has confidential not secret"),
        ("carol", "db:login:superuser", "dbservers", "postgresql", "sat",
         "carol has dba group → rule-005"),
        ("dave", "db:table:readwrite", "dbservers", "postgresql", "unsat",
         "dave is auditors; only gets schema:usage, not readwrite"),
    ]

    has_cve = "_attacker" in encoder.users
    attacker_tests = []
    if has_cve:
        attacker_tests = [
            ("_attacker", "ssh:login", "admin_bastion", "sshd", "sat",
             "sshd RCE → become root on bastion → ssh:login"),
            ("_attacker", "db:table:readwrite", "dbservers", "postgresql", "sat",
             "nginx/sshd RCE → become webserver → lateral to postgres"),
            ("_attacker", "sudo:execute", "admin_bastion", None, "sat",
             "sshd RCE → become root on bastion → inherits sudo+secret"),
        ]

    print("\n" + "=" * 70)
    print("POLICY VERIFICATION" + (" + CVE KILL-CHAIN ANALYSIS" if has_cve else ""))
    print("=" * 70)

    # Section 1: Policy-as-intended
    print("\n  Policy-as-intended access decisions:")
    passed = total = 0
    policy_broken = []
    for user, action, hg, svc, intended, reason in tests:
        result, explanation = encoder.query(user, action, hg, svc)
        total += 1
        if result == intended:
            passed += 1
            print(f"    [ok]    {user} + {action} on {hg}: {result}")
        else:
            # With CVE enabled, intended-deny becoming effective-sat is a FINDING
            if has_cve and intended == "unsat" and result == "sat":
                policy_broken.append((user, action, hg, svc, explanation))
                print(f"    [BREAK] {user} + {action} on {hg}: "
                      f"intended={intended} actual={result} ← CVE escalation!")
            else:
                print(f"    [FAIL]  {user} + {action} on {hg}: "
                      f"intended={intended} actual={result}")

    # Section 2: CVE kill chains
    if has_cve:
        print("\n  CVE kill-chain reachability (external attacker):")
        for user, action, hg, svc, expected, reason in attacker_tests:
            result, explanation = encoder.query(user, action, hg, svc)
            total += 1
            if result == expected:
                passed += 1
            marker = "ok" if result == expected else "FAIL"
            print(f"    [{marker:4s}] {user} + {action} on {hg}: {result}")
            if result == "sat":
                print(f"           chain: {reason}")

        # Section 3: Policy breaks summary
        if policy_broken:
            print(f"\n  ⚠ {len(policy_broken)} policy violation(s) via CVE escalation:")
            for user, action, hg, svc, expl in policy_broken:
                print(f"    • {user} gains {action} on {hg} "
                      f"(should be denied by policy)")

    print(f"\n  {passed}/{total} checks passed")
    print("=" * 70)
    return passed == total and not policy_broken


# ---------------------------------------------------------------------------
# 6. CLI
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Z3 μZ Datalog encoder for ABAC policies mined by abac_poc.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run smoke tests on a policy file
  python abac_encoder.py --policy abac_policy_all_*.md --smoke

  # Query a specific access
  python abac_encoder.py --policy abac_policy_all_*.md \\
      --query alice sudo:execute admin_bastion

  # Debug: check permit relation without deny-overrides
  python abac_encoder.py --policy abac_policy_all_*.md \\
      --query-permit alice ssh:login admin_bastion sshd
        """,
    )
    parser.add_argument("--policy", "-p", required=True, help="Path to policy .md or .json file")
    parser.add_argument("--smoke", action="store_true", help="Run canonical smoke tests")
    parser.add_argument("--no-cve", action="store_true",
                        help="Disable CVE escalation modeling (policy-as-intended only)")
    parser.add_argument("--query", "-q", nargs="+", metavar="ARG",
                        help="Query: <user> <action> [host_group] [service]")
    parser.add_argument("--query-permit", nargs="+", metavar="ARG",
                        help="Query permit only (no deny-overrides)")
    parser.add_argument("--dump-facts", action="store_true", help="Print all asserted facts")

    args = parser.parse_args()

    print(f"[+] Loading policy: {args.policy}")
    policy = load_policy(args.policy)
    print(f"[+] Attributes: {len(policy['attributes'])} top-level keys")
    print(f"[+] Rules: {len(policy['rules'])} rules")

    print("[+] Building Z3 Fixedpoint model...")
    encoder = ABACEncoder(policy, enable_cve_escalation=not args.no_cve)
    print(f"[+] Sorts: {len(encoder.users)} users, {len(encoder.groups)} groups, "
          f"{len(encoder.clearances)} clearances, {len(encoder.host_groups)} host_groups, "
          f"{len(encoder.services)} services, {len(encoder.actions)} actions")

    if args.smoke:
        all_passed = run_smoke_tests(encoder)
        sys.exit(0 if all_passed else 1)

    if args.query:
        user = args.query[0]
        action = args.query[1]
        hg = args.query[2] if len(args.query) > 2 else None
        svc = args.query[3] if len(args.query) > 3 else None
        result, explanation = encoder.query(user, action, hg, svc)
        print(f"\n  {user} + {action} on {hg or '*'}/{svc or '*'}: {result}")
        if explanation:
            print(f"  {explanation}")

    if args.query_permit:
        user = args.query_permit[0]
        action = args.query_permit[1]
        hg = args.query_permit[2] if len(args.query_permit) > 2 else None
        svc = args.query_permit[3] if len(args.query_permit) > 3 else None
        result, explanation = encoder.query_permit_only(user, action, hg, svc)
        print(f"\n  [permit-only] {user} + {action} on {hg or '*'}/{svc or '*'}: {result}")
        if explanation:
            print(f"  {explanation}")
