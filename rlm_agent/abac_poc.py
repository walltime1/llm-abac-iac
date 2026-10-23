"""
DSPy RLM PoC — ABAC Policy Miner from Ansible IaC.

Reads the Ansible directory pointed at by RLM_ANSIBLE_DIR, discovers
inventory/playbooks/vars/roles via tools, and emits a structured ABAC
policy (subject/resource/environment attributes + rules).

Shares LM/tracing/TUI/interpreter infrastructure with poc.py.
"""

import os
import sys
from typing import Optional

import dspy

from rlm_agent.ansible_tools import ANSIBLE_DIR_ENV, ANSIBLE_TOOLS
from rlm_agent.poc import (
    LiveCallback,
    MODEL_ALIASES,
    REASONING_CHOICES,
    VULNX_TOOLS,
    _WrappedInterpreter,
    _detect_provider,
    build_interpreter,
    build_lm,
    flush_tracing,
    live_view,
    run_with_adapter_retries,
    setup_tracing,
)


# ---------------------------------------------------------------------------
# 1. Signature
# ---------------------------------------------------------------------------


class ABACPolicyMiningSignature(dspy.Signature):
    """
    Mine an ABAC policy from the Ansible configuration rooted at the
    RLM_ANSIBLE_DIR environment variable. Directory contents are NOT in
    your prompt — discover files via list_ansible_files() and read each
    via read_ansible_file(path). Both return native Python objects.

    ## Workflow (four phases, in order)

    ### Phase 1 — Catalog (BEFORE any rule extraction)
    Read `inventory.ini` and every file under `group_vars/` FIRST. From
    these, populate the attribute catalog:
      - Subjects: `users` list (name, uid, groups, clearance, department,
        source), plus `groups` list (distinct group names) and enumerated
        `clearance_levels` and `departments`.
      - Resources: `hosts` (hostname, ip, role, zone, inventory_group),
        `services` (name, port, protocol, host_group), `paths` (path,
        owner, group, mode, service), `networks` (cidr, zone, label).
      - Environment: org, environment, compliance_tier, retention settings.
    Every attribute entry MUST include a `domain` (enumerated list of
    allowed values for enum-typed attrs; omit for free-form types like
    cidr/ip) and a `source` file path.

    ### Phase 1.5 — Vulnerability Assessment (CHEAP — do this early)
    You already have the package versions from Phase 1 (group_vars).
    For each pinned software package found (e.g. nginx, postgresql,
    openssh-server), call the vulnx tools in ONE code step:
      1. `search_critical_remote(product, limit=5)` for each package.
      2. `search_kev_vulnerabilities(product, limit=5)` for each package.
      3. Evaluate `affects_pinned_version` (true/false) per CVE.
         Discard CVEs for unrelated products.
      4. Add `recommendation` per CVE.
    This takes ONE iteration. Do it now before rule extraction consumes
    the remaining budget.
    If no package versions are found in the Ansible config, note that
    in the report under Ambiguities and skip to Phase 2.

    ### Phase 1.6 — Security Scope (ONE step, by filename only)
    Call `list_ansible_files()` and classify files by PATH PATTERN only.
    Do NOT read file contents here — just look at the file path:
      - inventory*, group_vars/* → already read in Phase 1
      - roles/*/tasks/* → read in Phase 2 (all roles are relevant)
      - *iptables*, *firewall*, *sshd*, *sudoers*, *pg_hba*, *my.cnf*,
        *haproxy*, *nginx*, *nagios*, *selinux* → security templates
      - handlers/* → skip (not access-relevant)
    Print the list of security-relevant files. This is ONE code step,
    not multiple. Do NOT read any files here.

    ### Phase 2 — Focused Rule Extraction
    Read the security-relevant files identified in Phase 1.6 and extract
    ABAC rules. ONLY extract rules from what you actually see in the
    files — do NOT invent users, groups, or permissions that are not
    explicitly defined in the Ansible configuration. If a file has no
    access-relevant tasks, skip it.

    Emit one rule per distinct subject-privilege combination. Every rule
    MUST include a `source` dict with keys `file`, `task`, and `lines`
    (line range in the source file). This is non-optional provenance.

    Key extraction patterns (not exhaustive — extract others too):
      - access_control: AllowGroups → ssh:login, sudoers → sudo:execute.
        Preserve `nopassword` (true/false).
      - database_auth: mysql_user/postgresql_user → db:login. Emit
        SEPARATE rules per privilege level (SUPERUSER vs NOSUPERUSER,
        ALL vs SELECT-only). pg_hba/my.cnf → network:connect + explicit
        DENY for implicit deny-defaults.
      - network_policy: firewalld/ufw/iptables → network:connect. Pay
        attention to per-host-group conditionals in Jinja2 templates
        ({% if inventory_hostname in groups.X %} → scoped rules).
      - filesystem_acl: owner/group/mode → filesystem:read/write/execute.
      - identity: user creation with `when:` → user:create.
      - selinux: seboolean → selinux:policy rules.
      - load_balancer: backend definitions → topology/routing rules.
      - monitoring_access: service check configs → monitoring rules.
      - credentials: flag in the report Ambiguities section.
      - Session logging / audit scripts → obligations attached to
        the relevant access rule, NOT free-standing rules.

    ### Phase 3 — Normalize
      - Every attribute name referenced in any rule MUST exist in the
        Phase-1 catalog. If a rule needs a new attribute, add it to the
        catalog before emitting the rule.
      - Assign stable IDs: `rule-001`, `rule-002`, ...
      - One rule per subject-privilege combination.

    ### Phase 4 — Validate
    Both `attributes` and `rules` MUST be valid JSON (double-quoted strings,
    `true`/`false`/`null` — NOT Python's `True`/`False`/`None`). `report`
    MUST be Markdown, not a dict literal or JSON blob.

    ### Code hygiene
    Build attributes and rules in SEPARATE code steps — do not write one
    monolithic block that constructs the entire policy. Long code blocks
    get truncated. Emit attributes first, then rules, then validate.

    ### How to submit output (IMPORTANT)
    When you have all four outputs ready, call SUBMIT() to finish:
      SUBMIT(
        attributes = json.dumps(attrs_dict),
        rules = json.dumps(rules_list),
        vulnerabilities = json.dumps(vulns_list),
        report = report_markdown_string
      )
    All four values must be JSON-serializable strings. SUBMIT ends the
    run immediately — verify your output before calling it.

    ## Operator grammar (the ONLY operators allowed in conditions)

    Exactly these four, one level of nesting only:
      - {"equals": <literal>}          — attribute equals one value
      - {"in": [<literal>, ...]}       — scalar attribute in a set
      - {"any_of": [<literal>, ...]}   — set-valued attribute intersects set
      - {"all_of": [<literal>, ...]}   — set-valued attribute is superset

    FORBIDDEN: natural-language strings ("groups in [sudo]"), MongoDB-style
    operators ($in/$contains/$or), nested operators, free-form subject
    strings. subject_condition / resource_condition / environment_condition
    MUST be dicts, never strings.

    Use `{"equals": <v>}` for single-value matches — do NOT use
    `{"in": [<v>]}` with a one-element list when `equals` suffices.

    effect MUST be lowercase: "permit" or "deny" (not "PERMIT"/"DENY").

    ## Default-deny rule
    The default-deny rule has a special form:
      subject_condition: {"applies_to": {"equals": "all"}}
      resource_condition: {"applies_to": {"equals": "all"}}
      action: "*"
      effect: "deny"
    Do NOT use empty dicts or empty lists for the catch-all.

    ## Namespace discipline

    subject / resource / environment condition keys are DISJOINT:
      - subject_condition: only subject attribute names (user, groups,
        clearance, department). Set-valued: `groups`.
      - resource_condition: only resource attribute names (hostname, zone,
        role, host_group, service, port, path, owner, group, mode, database,
        schema).
      - environment_condition: only environment attribute names
        (environment, compliance_tier, org).
    Network-layer rules (firewalld, pg_hba): the "subject" is a SOURCE HOST,
    not a user. Use {source_ip, source_network, source_zone} on
    subject_condition. Do not put source_ip under resource_condition.

    When `environment.compliance_tier` or `environment.environment` is in
    the catalog, every rule MUST include either `environment_condition` or
    the explicit sentinel {"applies_to": {"equals": "all"}}.

    ## Filesystem rule convention

    File owner/group/mode are RESOURCE attributes of the path, not subject
    predicates. Filesystem rule shape:
      - subject_condition: predicate over real subjects, e.g.
        {"groups": {"any_of": ["sudo"]}} — NOT {"user": {"equals": "appuser"}}.
      - resource_condition: {"path": {"equals": <p>}, "owner": {"equals": <u>},
        "group": {"equals": <g>}, "mode": {"equals": <m>}}.
      - action: "filesystem:read" | "filesystem:write" | "filesystem:execute".

    ## Obligations

    Session logging, profile.d audit scripts, and similar "enforce but don't
    permit or deny" entries are OBLIGATIONS, not access rules. Attach them
    to the appropriate access rule via an `obligations` field (list of
    dicts). Do NOT emit them as rules with effect="enforce".
    """

    policy_goal: str = dspy.InputField(
        desc=(
            "Which slice to mine: 'all' (default), 'ssh', 'sudo', 'db-access', "
            "'firewall', 'filesystem'. 'all' requests full coverage."
        )
    )
    attributes: str = dspy.OutputField(
        desc=(
            "VALID JSON object (double quotes, lowercase true/false/null) with "
            "exactly three top-level keys: "
            "`subjects` (object with: `users` list of full user records, "
            "`groups` as a FLAT list of strings like [\"sudo\",\"developers\","
            "\"dba\",\"auditors\"] — NOT a list of dicts, "
            "`clearance_levels` list, `departments` list), "
            "`resources` (object with: `hosts`, `services`, `paths`, "
            "`networks` lists), "
            "`environment` (object with: org, environment, compliance_tier, "
            "retention settings). "
            "Each attribute entry in lists has: name (str), type "
            "('enum'|'string'|'integer'|'cidr'|'ip'), domain (list of allowed "
            "literals — REQUIRED for type='enum', optional otherwise), source "
            "(file path relative to ansible dir). "
            "Never leave users or groups empty. "
            "EXAMPLE (follow this shape EXACTLY): "
            '{"subjects": {"users": ['
            '{"name": "alice", "uid": 1001, "groups": ["sudo", "developers"], '
            '"clearance": "secret", "department": "engineering", "source": "group_vars/all.yml"}'
            '], '
            '"groups": ["sudo", "developers"], '
            '"clearance_levels": ["secret", "confidential"], '
            '"departments": ["engineering", "data"]}, '
            '"resources": {"hosts": ['
            '{"hostname": "web01", "ip": "10.0.1.10", "role": "frontend", '
            '"zone": "dmz", "inventory_group": "webservers", "source": "inventory.ini"}'
            '], "services": ['
            '{"name": "nginx", "port": 443, "protocol": "tcp", '
            '"host_group": "webservers", "source": "group_vars/webservers.yml"}'
            '], "paths": [], "networks": []}, '
            '"environment": {"org": "acme-corp", "environment": "production", '
            '"compliance_tier": "pci", "source": "group_vars/all.yml"}}.'
        )
    )
    rules: str = dspy.OutputField(
        desc=(
            "VALID JSON array (double quotes, lowercase true/false/null). Each "
            "rule has REQUIRED keys: id (str, 'rule-NNN'), subject_condition "
            "(DICT using only {equals,in,any_of,all_of}), resource_condition "
            "(DICT), action (str like 'ssh:login', 'postgresql:connect', "
            "'sudo:all', 'filesystem:read', 'user:create'), effect "
            "(LOWERCASE 'permit' or 'deny'), environment_condition (DICT — "
            "REQUIRED on every rule, not optional; use the environment "
            "attributes from the catalog e.g. compliance_tier, environment), "
            "source (DICT with keys: file, task, lines — lines is the line "
            "range in the source file, e.g. '15-22'). source is NOT optional "
            "— every rule must have it. "
            "Optional keys: obligations (list of dicts), nopassword (bool, "
            "for sudo rules only). "
            "subject_condition / resource_condition / environment_condition "
            "MUST be dicts, NEVER strings. "
            "EXAMPLE rule: "
            '{"id": "rule-001", "subject_condition": {"groups": {"any_of": '
            '["sudo", "auditors", "dba"]}}, "resource_condition": {"zone": '
            '{"equals": "mgmt"}, "service": {"equals": "ssh"}}, "action": '
            '"ssh:login", "effect": "permit", "environment_condition": '
            '{"compliance_tier": {"equals": "pci"}, "environment": '
            '{"equals": "production"}}, "source": {"file": '
            '"roles/bastion/tasks/main.yml", "task": "Restrict bastion logins '
            'to auditors and sudo", "lines": "1-6"}}.'
        )
    )
    vulnerabilities: str = dspy.OutputField(
        desc=(
            "VALID JSON array of vulnerability findings from Phase 2.5. "
            "Each entry: {package (str), version (str from Ansible vars), "
            "cves (list of {cve_id, severity, cvss, description, is_kev, "
            "is_remote, affects_pinned_version (REQUIRED bool — true only "
            "if the installed version falls in the affected range; false if "
            "patched or unrelated product), recommendation (str — 'Upgrade "
            "to >= X' if affected, or 'Not affected; document exclusion')}), "
            "affected_rules (list of rule IDs)}. "
            "IMPORTANT: discard CVEs for unrelated products (e.g. Cisco, SAP "
            "results from a nginx search). Only include CVEs that genuinely "
            "target the package in question. "
            "If no package tasks found, emit []."
        )
    )
    report: str = dspy.OutputField(
        desc=(
            "Markdown document (NOT a dict literal, NOT JSON). Complete this "
            "skeleton verbatim as section headings:\n\n"
            "# ABAC Policy Mining Report\n\n"
            "## Overview\nSource dir, policy goal, files analyzed.\n\n"
            "## Environment\nOrg, environment, compliance tier, retention.\n\n"
            "## Subject Attributes\nTable of users and their attributes.\n\n"
            "## Resource Attributes\nHosts by zone, services, networks, paths.\n\n"
            "## Rules by Facet\nGrouped by ssh / sudo / db / firewall / "
            "filesystem / audit.\n\n"
            "## Vulnerability Assessment\nPer-package CVE findings from "
            "Phase 2.5, with severity counts and affected rules.\n\n"
            "## Ambiguities & Gaps\nJudgement calls made, facets absent from "
            "the config, attributes referenced in rules but missing from the "
            "catalog (should be empty after Phase 3).\n\n"
            "## Coverage\nRule count per facet."
        )
    )


# ---------------------------------------------------------------------------
# 1b. Lazy-ordering signature (Phase 2.5 CVEs — after rule extraction)
# ---------------------------------------------------------------------------


class ABACPolicyMiningSignatureLazy(ABACPolicyMiningSignature):
    """
    Mine an ABAC policy from the Ansible configuration rooted at the
    RLM_ANSIBLE_DIR environment variable. Directory contents are NOT in
    your prompt — discover files via list_ansible_files() and read each
    via read_ansible_file(path). Both return native Python objects.

    ## Workflow (four phases, in order)

    ### Phase 1 — Catalog (BEFORE any rule extraction)
    Read `inventory.ini` and every file under `group_vars/` FIRST. From
    these, populate the attribute catalog:
      - Subjects: `users` list (name, uid, groups, clearance, department,
        source), plus `groups` list (distinct group names) and enumerated
        `clearance_levels` and `departments`.
      - Resources: `hosts` (hostname, ip, role, zone, inventory_group),
        `services` (name, port, protocol, host_group), `paths` (path,
        owner, group, mode, service), `networks` (cidr, zone, label).
      - Environment: org, environment, compliance_tier, retention settings.
    Every attribute entry MUST include a `domain` (enumerated list of
    allowed values for enum-typed attrs; omit for free-form types like
    cidr/ip) and a `source` file path.

    ### Phase 1.5 — Security Scope (ONE step, by filename only)
    Call `list_ansible_files()` and classify files by PATH PATTERN only.
    Do NOT read file contents here — just look at the file path:
      - inventory*, group_vars/* → already read in Phase 1
      - roles/*/tasks/* → read in Phase 2 (all roles are relevant)
      - *iptables*, *firewall*, *sshd*, *sudoers*, *pg_hba*, *my.cnf*,
        *haproxy*, *nginx*, *nagios*, *selinux* → security templates
      - handlers/* → skip (not access-relevant)
    Print the list of security-relevant files. This is ONE code step,
    not multiple. Do NOT read any files here.

    ### Phase 2 — Focused Rule Extraction
    Read the security-relevant files identified in Phase 1.5 and extract
    ABAC rules. ONLY extract rules from what you actually see in the
    files — do NOT invent users, groups, or permissions that are not
    explicitly defined in the Ansible configuration. If a file has no
    access-relevant tasks, skip it.

    Emit one rule per distinct subject-privilege combination. Every rule
    MUST include a `source` dict with keys `file`, `task`, and `lines`
    (line range in the source file). This is non-optional provenance.

    Key extraction patterns (not exhaustive — extract others too):
      - access_control: AllowGroups → ssh:login, sudoers → sudo:execute.
        Preserve `nopassword` (true/false).
      - database_auth: mysql_user/postgresql_user → db:login. Emit
        SEPARATE rules per privilege level (SUPERUSER vs NOSUPERUSER,
        ALL vs SELECT-only). pg_hba/my.cnf → network:connect + explicit
        DENY for implicit deny-defaults.
      - network_policy: firewalld/ufw/iptables → network:connect. Pay
        attention to per-host-group conditionals in Jinja2 templates
        ({% if inventory_hostname in groups.X %} → scoped rules).
      - filesystem_acl: owner/group/mode → filesystem:read/write/execute.
      - identity: user creation with `when:` → user:create.
      - selinux: seboolean → selinux:policy rules.
      - load_balancer: backend definitions → topology/routing rules.
      - monitoring_access: service check configs → monitoring rules.
      - credentials: flag in the report Ambiguities section.
      - Session logging / audit scripts → obligations attached to
        the relevant access rule, NOT free-standing rules.

    ### Phase 2.5 — Vulnerability Assessment
    You have the package versions from Phase 1 (group_vars).
    For each pinned software package found (e.g. nginx, postgresql,
    openssh-server), call the vulnx tools in ONE code step:
      1. `search_critical_remote(product, limit=5)` for each package.
      2. `search_kev_vulnerabilities(product, limit=5)` for each package.
      3. Evaluate `affects_pinned_version` (true/false) per CVE.
         Discard CVEs for unrelated products.
      4. Add `recommendation` per CVE.
    This takes ONE iteration.
    If no package versions are found in the Ansible config, note that
    in the report under Ambiguities and emit an empty vulnerabilities list.

    ### Phase 3 — Normalize
      - Every attribute name referenced in any rule MUST exist in the
        Phase-1 catalog. If a rule needs a new attribute, add it to the
        catalog before emitting the rule.
      - Assign stable IDs: `rule-001`, `rule-002`, ...
      - One rule per subject-privilege combination.

    ### Phase 4 — Validate
    Both `attributes` and `rules` MUST be valid JSON (double-quoted strings,
    `true`/`false`/`null` — NOT Python's `True`/`False`/`None`). `report`
    MUST be Markdown, not a dict literal or JSON blob.

    ### Code hygiene
    Build attributes and rules in SEPARATE code steps — do not write one
    monolithic block that constructs the entire policy. Long code blocks
    get truncated. Emit attributes first, then rules, then validate.

    ### How to submit output (IMPORTANT)
    When you have all four outputs ready, call SUBMIT() to finish:
      SUBMIT(
        attributes = json.dumps(attrs_dict),
        rules = json.dumps(rules_list),
        vulnerabilities = json.dumps(vulns_list),
        report = report_markdown_string
      )
    All four values must be JSON-serializable strings. SUBMIT ends the
    run immediately — verify your output before calling it.
    """
    pass  # inherits all fields from ABACPolicyMiningSignature


# ---------------------------------------------------------------------------
# 2. Build the RLM
# ---------------------------------------------------------------------------


ABAC_TOOLS = ANSIBLE_TOOLS + VULNX_TOOLS

_PHASE_ORDER_SIGNATURES = {
    "eager": ABACPolicyMiningSignature,
    "lazy": ABACPolicyMiningSignatureLazy,
}


def build_abac_rlm(
    max_iterations: int = 15,
    interpreter_mode: str = "local",
    view=None,
    phase_order: str = "eager",
) -> dspy.RLM:
    sig_class = _PHASE_ORDER_SIGNATURES.get(phase_order, ABACPolicyMiningSignature)
    interpreter = build_interpreter(interpreter_mode, ABAC_TOOLS)
    if view is not None:
        interpreter = _WrappedInterpreter(interpreter, view)
    return dspy.RLM(
        sig_class,
        tools=ABAC_TOOLS,
        max_iterations=max_iterations,
        interpreter=interpreter,
    )


# ---------------------------------------------------------------------------
# 3. Runner
# ---------------------------------------------------------------------------


def mine_policy(
    policy_goal: str = "all",
    ansible_dir: Optional[str] = None,
    output_file: Optional[str] = None,
    model: str = "claude-sonnet",
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    max_iterations: int = 15,
    interpreter_mode: str = "local",
    trace: bool = False,
    phoenix_endpoint: str = "http://localhost:6006/v1/traces",
    phoenix_project: str = "rlm-abac-poc",
    reasoning: str = "auto",
    live: bool = False,
    retries: int = 5,
    max_tokens: int = 16000,
    cache: bool = True,
    phase_order: str = "eager",
) -> dict:
    # Resolve ANSIBLE dir: CLI flag > env var. Fail fast if neither is set.
    if ansible_dir:
        os.environ[ANSIBLE_DIR_ENV] = ansible_dir
    if not os.environ.get(ANSIBLE_DIR_ENV):
        raise ValueError(
            f"{ANSIBLE_DIR_ENV} is not set. Pass --ansible-dir or export it:\n"
            f"  export {ANSIBLE_DIR_ENV}=$(pwd)/ansible_configs"
        )

    if interpreter_mode == "docker":
        print(
            "[!] interpreter=docker does not auto-mount the Ansible dir. "
            "Prefer 'local' or 'deno' for ABAC mining."
        )

    lm = build_lm(
        model=model,
        api_key=api_key,
        base_url=base_url,
        reasoning=reasoning,
        num_retries=retries,
        max_tokens=max_tokens,
        cache=cache,
    )

    if trace or os.environ.get("PHOENIX_ENABLED"):
        resolved_model = MODEL_ALIASES.get(model, model)
        provider = _detect_provider(resolved_model)
        api_base = lm.kwargs.get("api_base") or base_url or ""
        setup_tracing(
            endpoint=phoenix_endpoint,
            project_name=phoenix_project,
            resource_attrs={
                "rlm.kind": "abac-miner",
                "rlm.model": resolved_model,
                "rlm.model_alias": model,
                "rlm.provider": provider,
                "rlm.api_base": api_base,
                "rlm.interpreter": interpreter_mode,
                "rlm.reasoning": reasoning,
                "rlm.ansible_dir": os.environ[ANSIBLE_DIR_ENV],
                "rlm.policy_goal": policy_goal,
            },
        )

    print(f"[+] Ansible dir : {os.environ[ANSIBLE_DIR_ENV]}")
    print(f"[+] Policy goal : {policy_goal}")
    print(f"[+] Phase order : {phase_order}")
    print(f"[+] Interpreter : {interpreter_mode}")
    if live:
        print("[+] Live TUI enabled — press Ctrl+C to abort.")

    with live_view(target=f"abac:{policy_goal}", enabled=live) as view:
        callbacks = [LiveCallback(view)] if view is not None else []
        dspy.configure(lm=lm, callbacks=callbacks)

        rlm = build_abac_rlm(
            max_iterations=max_iterations,
            interpreter_mode=interpreter_mode,
            view=view,
            phase_order=phase_order,
        )

        if view is None:
            print("[+] Starting RLM…\n")
        else:
            view.log("info", "ABAC miner started")
        result = run_with_adapter_retries(
            lambda: rlm(policy_goal=policy_goal), attempts=retries, view=view
        )
        if view is not None:
            view.log("info", "ABAC miner finished")

    # ---- print trajectory summary ----------------------------------------
    print("\n" + "=" * 60)
    print("AGENT TRAJECTORY SUMMARY")
    print("=" * 60)
    for i, step in enumerate(result.trajectory, 1):
        reasoning_txt = step.get("reasoning", "")[:120].replace("\n", " ")
        code_preview = step.get("code", "")[:80].replace("\n", " ")
        print(f"  Step {i:02d}: {reasoning_txt}...")
        if code_preview:
            print(f"          > {code_preview}...")
    print("=" * 60)

    # ---- normalise DSPy output to valid JSON --------------------------------
    # DSPy's RLM returns Python repr strings (single quotes, True/False/None).
    # Convert to real JSON so downstream tooling (Z3 encoder, metrics) can
    # consume the output without extra parsing.
    import ast
    import json as _json

    def _to_json(raw) -> str:
        if raw is None:
            return "{}"
        if not isinstance(raw, str):
            return _json.dumps(raw, indent=2, ensure_ascii=False)
        try:
            return _json.dumps(_json.loads(raw), indent=2, ensure_ascii=False)
        except (ValueError, _json.JSONDecodeError):
            pass
        # Trailing garbage (extra braces, whitespace after valid JSON)
        try:
            decoder = _json.JSONDecoder()
            obj, end = decoder.raw_decode(raw.strip())
            return _json.dumps(obj, indent=2, ensure_ascii=False)
        except (ValueError, _json.JSONDecodeError):
            pass
        # Python repr (single quotes, True/False/None)
        try:
            obj = ast.literal_eval(raw)
            return _json.dumps(obj, indent=2, ensure_ascii=False)
        except (ValueError, SyntaxError):
            return raw  # give up — emit as-is

    def _flatten_enum_lists(obj):
        """Flatten list-of-dicts like [{"clearance": "secret"}] → ["secret"]."""
        if not isinstance(obj, dict):
            return obj
        subj = obj.get("subjects")
        if not isinstance(subj, dict):
            return obj  # non-standard shape — skip flattening
        for key in ("clearance_levels", "departments"):
            val = subj.get(key)
            if isinstance(val, list) and val and isinstance(val[0], dict):
                flat = []
                for item in val:
                    if isinstance(item, dict) and len(item) == 1:
                        flat.append(next(iter(item.values())))
                    else:
                        flat.append(item)
                subj[key] = flat
        # groups: [{"name": "sudo", ...}] → ["sudo", ...]
        grps = subj.get("groups")
        if isinstance(grps, list) and grps and isinstance(grps[0], dict):
            subj["groups"] = [g["name"] for g in grps if isinstance(g, dict) and "name" in g]
        return obj

    # ---- deterministic post-processor ----------------------------------------
    from rlm_agent.normalize_to_ir import ACTION_MAP

    def _normalize_single_any_of(obj):
        """Recursively replace {"any_of": [x]} → {"equals": x} in conditions."""
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                if isinstance(v, dict):
                    if "any_of" in v and isinstance(v["any_of"], list) and len(v["any_of"]) == 1:
                        obj[k] = {"equals": v["any_of"][0]}
                    elif "in" in v and isinstance(v["in"], list) and len(v["in"]) == 1:
                        obj[k] = {"equals": v["in"][0]}
                    else:
                        _normalize_single_any_of(v)
        return obj

    def _canonicalize_actions(rules):
        for r in rules:
            r["action"] = ACTION_MAP.get(r.get("action", ""), r.get("action", ""))
            r["effect"] = r.get("effect", "permit").lower()
        return rules

    def _ensure_host_inventory_group(attrs):
        """Add inventory_group to hosts that lack it, derived from catalog."""
        hosts = []
        subj = attrs.get("subjects")
        cat = attrs.get("catalog")
        if cat and isinstance(cat, dict):
            hosts = cat.get("hosts", [])
        elif subj and isinstance(subj, dict):
            hosts = attrs.get("resources", {}).get("hosts", [])

        # Build zone→group mapping from hosts that already have inventory_group
        zone_map = {}
        for h in hosts:
            if not isinstance(h, dict):
                continue
            ig = h.get("inventory_group") or h.get("host_group")
            z = h.get("zone")
            if ig and z:
                zone_map[z] = ig

        for h in hosts:
            if not isinstance(h, dict):
                continue
            if not (h.get("inventory_group") or h.get("host_group")):
                z = h.get("zone")
                if z and z in zone_map:
                    h["inventory_group"] = zone_map[z]
        return attrs

    def _decompose_filesystem_mode(rules):
        """Expand filesystem rules by UNIX permission bits."""
        new_rules = []
        max_id = 0
        for r in rules:
            m = _re.match(r"rule-(\d+)", r.get("id", ""))
            if m:
                max_id = max(max_id, int(m.group(1)))

        for r in list(rules):
            rc = r.get("resource_condition", {})
            mode_v = rc.get("mode", {}).get("equals") if isinstance(rc.get("mode"), dict) else None
            if not mode_v or r.get("action", "") not in ("filesystem:read", "filesystem:write", "filesystem:execute"):
                continue
            if r.get("effect") == "deny":
                continue

            # Parse mode (e.g., "0700" → owner=7, group=0, other=0)
            try:
                bits = int(mode_v, 8)
            except (ValueError, TypeError):
                continue
            owner_bits = (bits >> 6) & 0o7
            group_bits = (bits >> 3) & 0o7

            # Check if a deny counterpart already exists
            deny_exists = any(
                dr.get("effect") == "deny"
                and dr.get("resource_condition", {}).get("path") == rc.get("path")
                and dr.get("action") in ("filesystem:read", "filesystem:write")
                for dr in rules
            )
            if deny_exists:
                continue

            # owner-only (group=0, other=0): emit non-owner deny
            if group_bits == 0:
                max_id += 1
                new_rules.append({
                    "id": f"rule-{max_id:03d}",
                    "subject_condition": {"applies_to": {"equals": "all"}},
                    "resource_condition": dict(rc),
                    "environment_condition": r.get("environment_condition", {}),
                    "action": "filesystem:read",
                    "effect": "deny",
                    "source": {"file": "postprocessor", "task": f"mode {mode_v} non-owner deny", "lines": "N/A"},
                })
            # group has read (r-x = 5, r-- = 4): emit group-permit-read if not already covered
            elif group_bits & 0o4:
                owner_val = rc.get("owner", {}).get("equals")
                group_val = rc.get("group", {}).get("equals")
                if owner_val and group_val:
                    group_read_exists = any(
                        gr.get("subject_condition", {}).get("groups", {}).get("any_of") == [group_val]
                        or gr.get("subject_condition", {}).get("groups", {}).get("equals") == group_val
                        for gr in rules
                        if gr.get("resource_condition", {}).get("path") == rc.get("path")
                        and gr.get("action") == "filesystem:read"
                    )
                    if not group_read_exists:
                        max_id += 1
                        new_rules.append({
                            "id": f"rule-{max_id:03d}",
                            "subject_condition": {"groups": {"equals": group_val}},
                            "resource_condition": dict(rc),
                            "environment_condition": r.get("environment_condition", {}),
                            "action": "filesystem:read",
                            "effect": "permit",
                            "source": {"file": "postprocessor", "task": f"mode {mode_v} group read", "lines": "N/A"},
                        })

        rules.extend(new_rules)
        return rules

    def _emit_network_explicit_deny(rules):
        """Add explicit deny for network:connect permits scoped to specific IPs."""
        new_rules = []
        max_id = 0
        for r in rules:
            m = _re.match(r"rule-(\d+)", r.get("id", ""))
            if m:
                max_id = max(max_id, int(m.group(1)))

        for r in rules:
            if r.get("action") != "network:connect" or r.get("effect") != "permit":
                continue
            sc = r.get("subject_condition", {})
            if not (sc.get("source_ip") or sc.get("source_network")):
                continue
            rc = r.get("resource_condition", {})
            # Check if deny counterpart exists
            deny_exists = any(
                dr.get("effect") == "deny"
                and dr.get("action") == "network:connect"
                and dr.get("resource_condition", {}).get("service") == rc.get("service")
                and dr.get("resource_condition", {}).get("host_group") == rc.get("host_group")
                for dr in rules
            )
            if deny_exists:
                continue
            max_id += 1
            deny_rc = {k: v for k, v in rc.items() if k in ("service", "port", "host_group", "database")}
            new_rules.append({
                "id": f"rule-{max_id:03d}",
                "subject_condition": {"applies_to": {"equals": "all"}},
                "resource_condition": deny_rc,
                "environment_condition": r.get("environment_condition", {}),
                "action": "network:connect",
                "effect": "deny",
                "source": {"file": "postprocessor", "task": "implicit network deny-default", "lines": "N/A"},
            })

        rules.extend(new_rules)
        return rules

    def _inject_missing_env_condition(attrs, rules):
        """Fill empty environment_condition from catalog."""
        env = attrs.get("environment", {})
        if isinstance(env, dict):
            # Handle Opus shape where env values are dicts with "value" key
            default_ec = {}
            for k in ("compliance_tier", "environment"):
                v = env.get(k)
                if isinstance(v, dict) and "value" in v:
                    default_ec[k] = {"equals": v["value"]}
                elif isinstance(v, str):
                    default_ec[k] = {"equals": v}
            if not default_ec:
                return rules
            for r in rules:
                ec = r.get("environment_condition")
                if not ec or ec == {}:
                    r["environment_condition"] = dict(default_ec)
                # Don't overwrite applies_to sentinel
        return rules

    def _postprocess_policy(attrs, rules):
        """Apply all deterministic normalizations."""
        # 1. Normalize single-element any_of/in → equals
        for r in rules:
            for cond_key in ("subject_condition", "resource_condition", "environment_condition"):
                if cond_key in r:
                    _normalize_single_any_of(r[cond_key])
        # 2. Canonicalize actions
        rules = _canonicalize_actions(rules)
        # 3. Ensure host inventory_group
        attrs = _ensure_host_inventory_group(attrs)
        # 4. Inject missing environment_condition
        rules = _inject_missing_env_condition(attrs, rules)
        # 5. Decompose filesystem modes
        rules = _decompose_filesystem_mode(rules)
        # 6. Emit network explicit deny
        rules = _emit_network_explicit_deny(rules)
        return attrs, rules

    import re as _re

    attrs_json = _to_json(result.attributes)
    rules_json = _to_json(result.rules)
    vulns_json = _to_json(result.vulnerabilities)

    # Apply post-processing pipeline
    try:
        attrs_obj = _json.loads(attrs_json)
        rules_obj = _json.loads(rules_json)
        attrs_obj = _flatten_enum_lists(attrs_obj)
        if isinstance(attrs_obj, dict) and isinstance(rules_obj, list):
            attrs_obj, rules_obj = _postprocess_policy(attrs_obj, rules_obj)
        attrs_json = _json.dumps(attrs_obj, indent=2, ensure_ascii=False)
        rules_json = _json.dumps(rules_obj, indent=2, ensure_ascii=False)
    except (ValueError, _json.JSONDecodeError, ImportError) as e:
        print(f"[warn] post-processing skipped: {e}")

    # ---- save report -------------------------------------------------------
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_goal = policy_goal.replace(" ", "_").replace("/", "-")[:40]
    filename = output_file or f"abac_policy_{safe_goal}_{timestamp}.md"

    n_steps = len(result.trajectory)
    try:
        n_rules = len(_json.loads(rules_json)) if rules_json else "?"
    except Exception:
        n_rules = "?"

    with open(filename, "w") as f:
        f.write(f"# ABAC Policy Mining — goal: {policy_goal}\n")
        f.write(
            f"_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_  \n"
            f"_Model: `{model}`_  \n"
            f"_Interpreter: `{interpreter_mode}`_  \n"
            f"_Max tokens: {max_tokens} | Max iterations: {max_iterations} | "
            f"Steps used: {n_steps} | Rules: {n_rules}_  \n"
            f"_Reasoning: `{reasoning}` | Retries: {retries}_  \n"
            f"_Source: `{os.environ[ANSIBLE_DIR_ENV]}`_\n\n"
        )
        f.write("## Attributes\n\n```json\n")
        f.write(attrs_json)
        f.write("\n```\n\n## Rules\n\n```json\n")
        f.write(rules_json)
        f.write("\n```\n\n## Vulnerabilities\n\n```json\n")
        f.write(vulns_json)
        f.write("\n```\n\n## Report\n\n")
        f.write(result.report)

    print(f"\n[+] Policy saved → {filename}")
    flush_tracing()
    return {
        "policy_goal": policy_goal,
        "policy_file": filename,
        "trajectory_steps": len(result.trajectory),
    }


# ---------------------------------------------------------------------------
# 4. CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="DSPy RLM — ABAC policy miner over an Ansible directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Quick start:
  export RLM_ANSIBLE_DIR=$(pwd)/ansible_configs
  python abac_poc.py --model or-sonnet --live --trace

Focus a slice:
  python abac_poc.py --goal ssh --model claude-sonnet
  python abac_poc.py --goal db-access --interpreter deno
        """,
    )
    parser.add_argument(
        "--goal",
        "-g",
        default="all",
        help="Policy slice to mine: all|ssh|sudo|db-access|firewall|filesystem",
    )
    parser.add_argument(
        "--ansible-dir",
        "-d",
        default=None,
        help=(
            "Path to the Ansible directory. Overrides RLM_ANSIBLE_DIR. "
            "Falls back to that env var if omitted."
        ),
    )
    parser.add_argument("--model", "-m", default="claude-sonnet")
    parser.add_argument("--api-key", "-k", default=None)
    parser.add_argument("--base-url", "-u", default=None)
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("-i", "--iterations", type=int, default=15)
    parser.add_argument(
        "--interpreter",
        choices=["docker", "local", "deno"],
        default="local",
        help="Local is recommended; docker would need volume mounts.",
    )
    parser.add_argument("--trace", action="store_true")
    parser.add_argument(
        "--phoenix-endpoint", default="http://localhost:6006/v1/traces"
    )
    parser.add_argument(
        "--phoenix-project", default="rlm-abac-poc",
        help="Phoenix project name for trace grouping.",
    )
    parser.add_argument("--live", action="store_true")
    parser.add_argument(
        "--phase-order",
        choices=["eager", "lazy"],
        default="eager",
        help="Phase ordering: eager = CVEs before rules, lazy = CVEs after rules.",
    )
    parser.add_argument(
        "--reasoning", choices=list(REASONING_CHOICES), default="auto"
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=5,
        help=(
            "How many times to retry on LiteLLM transport errors or DSPy "
            "adapter parse failures. Default: 5."
        ),
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=16000,
        help="Max tokens per LM response. Default: 16000 (up from 8000).",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable DSPy response caching. Every LLM call hits the API.",
    )
    args = parser.parse_args()

    try:
        meta = mine_policy(
            policy_goal=args.goal,
            ansible_dir=args.ansible_dir,
            output_file=args.output,
            model=args.model,
            api_key=args.api_key,
            base_url=args.base_url,
            max_iterations=args.iterations,
            interpreter_mode=args.interpreter,
            trace=args.trace,
            phoenix_endpoint=args.phoenix_endpoint,
            phoenix_project=args.phoenix_project,
            reasoning=args.reasoning,
            live=args.live,
            retries=args.retries,
            max_tokens=args.max_tokens,
            cache=not args.no_cache,
            phase_order=args.phase_order,
        )
    except ValueError as e:
        print(f"[!] Configuration error: {e}")
        sys.exit(1)

    print(f"\n✓ Done in {meta['trajectory_steps']} agent steps.")
