"""
One-time normalizer: convert all model ABAC policy outputs into the
canonical IR shape that abac_encoder.py expects.

Writes normalized JSON files to ir/ directory for side-by-side encoder
comparison across models.
"""

import ast
import json
import re
import sys
from pathlib import Path

IR_DIR = Path("ir")

# Canonical action vocabulary — map model-specific actions to canonical names
ACTION_MAP = {
    # Opus canonical (pass-through)
    "ssh:login": "ssh:login",
    "sudo:execute": "sudo:execute",
    "db:login:superuser": "db:login:superuser",
    "db:login": "db:login",
    "db:schema:usage": "db:schema:usage",
    "db:table:readwrite": "db:table:readwrite",
    "network:connect": "network:connect",
    "filesystem:read": "filesystem:read",
    "filesystem:write": "filesystem:write",
    "filesystem:execute": "filesystem:execute",
    "user:create": "user:create",
    "*": "*",
    # GPT-5.4 variants
    "sudo:all": "sudo:execute",
    "sudo:/usr/bin/systemctl restart nginx": "sudo:execute",
    "sudo:/usr/bin/systemctl reload nginx": "sudo:execute",
    "postgresql:connect": "db:login",
    "postgresql:select": "db:table:readwrite",
    "postgresql:insert": "db:table:readwrite",
    "postgresql:update": "db:table:readwrite",
    "postgresql:usage": "db:schema:usage",
    "network:ingress": "network:connect",
    # Gemini variants
    "sudo:exec": "sudo:execute",
    "db:superuser": "db:login:superuser",
    # Sonnet pre-sig variants
    "ssh:login": "ssh:login",
    "sudo:all": "sudo:execute",
    "postgresql:create_user": "db:login",
    "postgresql:usage": "db:schema:usage",
    "postgresql:select,insert,update": "db:table:readwrite",
    "postgresql:connect": "network:connect",
    "network:ingress": "network:connect",
    "filesystem:read,execute": "filesystem:read",
    "sudo:systemctl:restart,reload:nginx": "sudo:execute",
    "user:create": "user:create",
    # Qwen MoE variants
    "db:login": "db:login",
    "db:privilege": "db:schema:usage",
    "db:write": "db:table:readwrite",
    "db:read": "db:schema:usage",
    "db:network:login": "network:connect",
    "network:tcp": "network:connect",
    "implicit_deny": "*",
    # Qwen 3.5 reference
    "login": "ssh:login",
    "sudo": "sudo:execute",
    "connect": "network:connect",
    "schema_access": "db:schema:usage",
    "table_access": "db:table:readwrite",
    "filesystem_access": "filesystem:read",
    "network_access": "network:connect",
    # Other
    "db:login:superuser": "db:login:superuser",
    "database:login": "db:login",
    "database:superuser": "db:login:superuser",
    "database:usage": "db:schema:usage",
    "database:write": "db:table:readwrite",
    "database:network_access": "network:connect",
    "shell_account_provision": "user:create",
}

# Canonical host_group mapping (infer from zone/hostname when missing)
HOST_TO_GROUP = {
    "web01.corp.local": "webservers",
    "web02.corp.local": "webservers",
    "db01.corp.local": "dbservers",
    "db02.corp.local": "dbservers",
    "bastion.corp.local": "admin_bastion",
}
ZONE_TO_GROUP = {
    "dmz": "webservers",
    "internal": "dbservers",
    "mgmt": "admin_bastion",
}

# Canonical users (ground truth from fixture)
CANONICAL_USERS = [
    {"name": "alice", "uid": 1001, "groups": ["sudo", "developers"],
     "department": "engineering", "clearance": "secret"},
    {"name": "bob", "uid": 1002, "groups": ["developers"],
     "department": "engineering", "clearance": "confidential"},
    {"name": "carol", "uid": 1003, "groups": ["dba"],
     "department": "data", "clearance": "secret"},
    {"name": "dave", "uid": 1004, "groups": ["auditors"],
     "department": "compliance", "clearance": "secret"},
]
CANONICAL_GROUPS = ["sudo", "developers", "dba", "auditors"]
CANONICAL_HOSTS = [
    {"hostname": "web01.corp.local", "ip": "10.0.1.11", "role": "frontend",
     "zone": "dmz", "inventory_group": "webservers"},
    {"hostname": "web02.corp.local", "ip": "10.0.1.12", "role": "frontend",
     "zone": "dmz", "inventory_group": "webservers"},
    {"hostname": "db01.corp.local", "ip": "10.0.2.21", "role": "primary",
     "zone": "internal", "inventory_group": "dbservers"},
    {"hostname": "db02.corp.local", "ip": "10.0.2.22", "role": "replica",
     "zone": "internal", "inventory_group": "dbservers"},
    {"hostname": "bastion.corp.local", "ip": "10.0.0.5", "role": "bastion",
     "zone": "mgmt", "inventory_group": "admin_bastion"},
]
CANONICAL_SERVICES = [
    {"name": "sshd", "port": 22, "protocol": "tcp", "host_group": "all"},
    {"name": "nginx", "port": 443, "protocol": "tcp", "host_group": "webservers"},
    {"name": "postgresql", "port": 5432, "protocol": "tcp", "host_group": "dbservers"},
]
CANONICAL_PATHS = [
    {"path": "/var/lib/postgresql/data", "owner": "postgres", "group": "postgres", "mode": "0700"},
    {"path": "/var/www/app", "owner": "appuser", "group": "www-data", "mode": "0750"},
]


def _parse_json_or_pydict(raw: str) -> object:
    """Parse JSON, falling back to ast.literal_eval for Python dict repr."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        pass
    # Python dict repr: single quotes, True/False/None
    return ast.literal_eval(raw)


def _extract_blocks(md_text: str) -> list:
    """Extract code blocks from markdown."""
    # Handle double-fenced blocks (```json\n```json\n...\n```\n```)
    cleaned = md_text.replace("```json\n```json\n", "```json\n")
    cleaned = cleaned.replace("\n```\n```", "\n```")
    return re.findall(r"```json\n(.*?)```", cleaned, re.S)


def _normalize_action(action: str) -> str:
    """Map a model-specific action to the canonical vocabulary."""
    return ACTION_MAP.get(action, action)


def _normalize_subject_condition(sc: dict) -> dict:
    """Normalize subject conditions to canonical operator grammar."""
    if not sc or not isinstance(sc, dict):
        return sc or {}

    result = {}
    for key, val in sc.items():
        if key == "applies_to":
            result["applies_to"] = val if isinstance(val, dict) else {"equals": val}
        elif key in ("groups", "clearance", "department",
                     "source_ip", "source_network", "source_zone",
                     "source_cidr", "user"):
            if isinstance(val, dict):
                result[key] = val
            elif isinstance(val, str):
                result[key] = {"equals": val}
            elif isinstance(val, list):
                result[key] = {"any_of": val}
            else:
                result[key] = val
        # Map old operator names
        elif key == "groups_intersection":
            result["groups"] = {"any_of": val} if isinstance(val, list) else val
        elif key in ("clearance_in",):
            result["clearance"] = {"in": val} if isinstance(val, list) else val
        elif key == "host_group_access":
            continue  # meta-predicate, skip
        else:
            result[key] = val

    # Normalize source_cidr → source_ip
    if "source_cidr" in result:
        result["source_ip"] = result.pop("source_cidr")

    return result


def _normalize_resource_condition(rc: dict) -> dict:
    """Normalize resource conditions to canonical operator grammar."""
    if not rc or not isinstance(rc, dict):
        return rc or {}

    result = {}
    for key, val in rc.items():
        if key == "applies_to":
            result["applies_to"] = val if isinstance(val, dict) else {"equals": val}
        elif isinstance(val, dict):
            result[key] = val
        elif isinstance(val, (str, int)):
            result[key] = {"equals": val}
        elif isinstance(val, list):
            result[key] = {"in": val}
        else:
            result[key] = val

    # Ensure host_group is present (infer from hostname/zone)
    if "host_group" not in result:
        hostname = result.get("hostname", {})
        if isinstance(hostname, dict):
            hn = hostname.get("equals")
            if hn and hn in HOST_TO_GROUP:
                result["host_group"] = {"equals": HOST_TO_GROUP[hn]}
        zone = result.get("zone", {})
        if isinstance(zone, dict) and "host_group" not in result:
            z = zone.get("equals")
            if z and z in ZONE_TO_GROUP:
                result["host_group"] = {"equals": ZONE_TO_GROUP[z]}

    return result


def _normalize_env_condition(ec: dict) -> dict:
    """Ensure environment_condition exists with at least compliance_tier."""
    if not ec or not isinstance(ec, dict):
        return {"compliance_tier": {"equals": "pci"}}
    result = {}
    for key, val in ec.items():
        if isinstance(val, dict):
            result[key] = val
        elif isinstance(val, str):
            result[key] = {"equals": val}
        else:
            result[key] = val
    if "compliance_tier" not in result and "applies_to" not in result:
        result["compliance_tier"] = {"equals": "pci"}
    return result


def normalize_rule(rule: dict) -> dict:
    """Normalize a single rule to canonical IR."""
    normalized = {
        "id": rule.get("id", "rule-???"),
        "subject_condition": _normalize_subject_condition(
            rule.get("subject_condition", {})
        ),
        "resource_condition": _normalize_resource_condition(
            rule.get("resource_condition", {})
        ),
        "environment_condition": _normalize_env_condition(
            rule.get("environment_condition", {})
        ),
        "action": _normalize_action(rule.get("action", "*")),
        "effect": rule.get("effect", "permit").lower(),
        "source": rule.get("source") or rule.get("provenance") or {},
    }
    # Carry through optional fields
    if "nopassword" in rule:
        normalized["nopassword"] = rule["nopassword"]
    if "obligations" in rule and rule["obligations"]:
        normalized["obligations"] = rule["obligations"]
    return normalized


def normalize_attributes(attrs: dict) -> dict:
    """Normalize attributes to canonical IR, filling gaps from ground truth."""
    # Try to extract users from whatever shape we have
    users = None
    groups = None

    # Opus catalog shape
    cat = attrs.get("catalog") or attrs.get("subjects_catalog")
    if cat and isinstance(cat, dict) and cat.get("users"):
        users = cat["users"]
        groups = cat.get("groups", [])
        hosts = cat.get("hosts", CANONICAL_HOSTS)
        services = cat.get("services", CANONICAL_SERVICES)
        paths = cat.get("paths", CANONICAL_PATHS)
    # Flat subjects shape
    elif "subjects" in attrs and isinstance(attrs["subjects"], dict):
        subj = attrs["subjects"]
        users = subj.get("users", [])
        groups = subj.get("groups", [])
        res = attrs.get("resources", {})
        hosts = res.get("hosts", CANONICAL_HOSTS) if isinstance(res, dict) else CANONICAL_HOSTS
        services = res.get("services", CANONICAL_SERVICES) if isinstance(res, dict) else CANONICAL_SERVICES
        paths = res.get("paths", CANONICAL_PATHS) if isinstance(res, dict) else CANONICAL_PATHS
    # Gemini: subjects is a list of user records
    elif "subjects" in attrs and isinstance(attrs["subjects"], list):
        users = attrs["subjects"]
        groups = []
        hosts = CANONICAL_HOSTS
        services = CANONICAL_SERVICES
        paths = CANONICAL_PATHS
    # Old format with 'subjects' as top-level key containing user/resource/env dicts
    elif "subjects" in attrs:
        s = attrs["subjects"]
        if isinstance(s, dict) and "users" in s:
            users = s["users"]
            groups = s.get("groups", [])

    # Fall back to canonical users if extraction failed
    if not users:
        users = CANONICAL_USERS
    if not groups:
        groups = sorted({g for u in users for g in u.get("groups", [])})

    # Normalize groups to flat strings
    if groups and isinstance(groups[0], dict):
        groups = [g["name"] if isinstance(g, dict) and "name" in g else str(g) for g in groups]

    # Ensure hosts have inventory_group
    for h in hosts:
        if isinstance(h, dict) and not (h.get("inventory_group") or h.get("host_group")):
            hn = h.get("hostname") or h.get("name")
            if hn and hn in HOST_TO_GROUP:
                h["inventory_group"] = HOST_TO_GROUP[hn]

    return {
        "subjects": {
            "users": users,
            "groups": groups if isinstance(groups, list) else CANONICAL_GROUPS,
            "clearance_levels": sorted({u["clearance"] for u in users if u.get("clearance")}),
            "departments": sorted({u["department"] for u in users if u.get("department")}),
        },
        "resources": {
            "hosts": hosts,
            "services": services,
            "paths": paths,
        },
        "environment": {
            "org": "acme-corp",
            "environment": "production",
            "compliance_tier": "pci",
        },
    }


def normalize_policy(md_path: str) -> dict:
    """Load a policy .md file and normalize to canonical IR."""
    text = Path(md_path).read_text()
    blocks = _extract_blocks(text)

    if len(blocks) < 2:
        raise ValueError(f"Need at least 2 JSON blocks in {md_path}")

    attrs = _parse_json_or_pydict(blocks[0])
    rules_raw = _parse_json_or_pydict(blocks[1])

    if not isinstance(rules_raw, list):
        raise ValueError(f"Rules block is not a list in {md_path}")

    attrs_norm = normalize_attributes(attrs)
    rules_norm = [normalize_rule(r) for r in rules_raw]

    return {
        "attributes": attrs_norm,
        "rules": rules_norm,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

POLICY_FILES = {
    "sonnet_presig":     "abac_policy_all_20260420_202143.md",
    "qwen35_v2":         "abac_policy_all_20260421_081247.md",
    "qwen36_q6":         "abac_policy_all_20260421_082110.md",
    "qwen35_moe":        "abac_policy_all_20260421_083540.md",
    "opus_old":          "old.OPUS-4-7_abac_policy_all_20260421_084219.md",
    "gemini_flash":      "GEMINI_FLASH.abac_policy_all_20260421_090331.md",
    "gpt54":             "gpt54.abac_policy_all_20260421_092320.md",
    "opus_new":          "new_OPUS-47_abac_policy_all_20260421_092849.md",
}

if __name__ == "__main__":
    IR_DIR.mkdir(exist_ok=True)

    for label, path in POLICY_FILES.items():
        if not Path(path).exists():
            print(f"  [{label}] SKIP — file not found: {path}")
            continue
        try:
            normalized = normalize_policy(path)
            out_path = IR_DIR / f"{label}.json"
            out_path.write_text(json.dumps(normalized, indent=2, ensure_ascii=False))
            n_rules = len(normalized["rules"])
            n_users = len(normalized["attributes"]["subjects"]["users"])
            n_hg = len({
                h.get("inventory_group") or h.get("host_group")
                for h in normalized["attributes"]["resources"]["hosts"]
                if isinstance(h, dict) and (h.get("inventory_group") or h.get("host_group"))
            })
            print(f"  [{label}] OK — {n_rules} rules, {n_users} users, {n_hg} host_groups → {out_path}")
        except Exception as e:
            print(f"  [{label}] ERROR — {e}")
