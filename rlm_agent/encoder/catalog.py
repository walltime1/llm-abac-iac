"""Catalog extractor — normalize different model output shapes."""


def _extract_catalog(attrs: dict) -> dict:
    """Extract the catalog from the attributes block.

    Expects the canonical IR shape — attributes MUST have either:
      (a) a top-level `catalog` key (Opus dual-layer), or
      (b) a `subjects` dict with `users` and `groups` keys (flat shape).
    """
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
    else:
        raise ValueError(
            "Non-conforming attributes shape. Expected `catalog.users` "
            "(Opus dual-layer) or `subjects.users` (flat)."
        )

    if not users:
        raise ValueError("Empty user catalog — cannot build Z3 model.")
    if not groups or not isinstance(groups[0], str):
        raise ValueError(
            f"groups must be a flat list of strings, got: "
            f"{type(groups[0]) if groups else 'empty'}."
        )

    clearance_levels = sorted({u["clearance"] for u in users if u.get("clearance")})
    departments = sorted({u["department"] for u in users if u.get("department")})
    host_groups = sorted({
        h.get("inventory_group") or h.get("host_group")
        for h in hosts
        if h.get("inventory_group") or h.get("host_group")
    })
    service_names = sorted({s["name"] for s in services if s.get("name")})
    path_strs = sorted({
        p["path"] if isinstance(p, dict) else p
        for p in paths
        if (isinstance(p, dict) and p.get("path")) or isinstance(p, str)
    })

    if not clearance_levels:
        clearance_levels = ["_none"]
    if not host_groups:
        raise ValueError(
            "No host_groups found in hosts catalog. Each host needs "
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


def _safe_enum_name(s: str) -> str:
    """Replace characters invalid in Z3 enum names."""
    return (s.replace(":", "_").replace("/", "_").replace(".", "_")
             .replace("*", "wildcard").replace(" ", "_"))
