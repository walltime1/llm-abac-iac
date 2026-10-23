# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 11:01:49_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 14 | Rules: 13_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f1_minimal_twotier`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "description": "Unix users provisioned via Ansible",
      "entries": [
        {
          "name": "admin",
          "uid": 1001,
          "groups": [
            "sudo"
          ],
          "department": "operations",
          "clearance": "secret",
          "source": "group_vars/all.yml"
        },
        {
          "name": "appuser",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "department": "engineering",
          "clearance": "confidential",
          "source": "group_vars/all.yml"
        }
      ]
    },
    "groups": {
      "description": "Unix groups assigned to users",
      "domain": [
        "sudo",
        "developers"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "description": "Information clearance tiers",
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "description": "Organizational departments",
      "domain": [
        "engineering",
        "operations"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": {
      "description": "Ansible-managed hosts",
      "entries": [
        {
          "hostname": "web01.lab.local",
          "ip": "10.0.1.10",
          "role": "frontend",
          "zone": "dmz",
          "inventory_group": "webservers",
          "source": "inventory.ini"
        },
        {
          "hostname": "db01.lab.local",
          "ip": "10.0.2.10",
          "role": "primary",
          "zone": "internal",
          "inventory_group": "dbservers",
          "source": "inventory.ini"
        }
      ]
    },
    "networks": {
      "description": "Network CIDR blocks in scope",
      "entries": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "webservers_subnet",
          "source": "group_vars/dbservers.yml"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "internal",
          "label": "dbservers_subnet",
          "source": "group_vars/dbservers.yml"
        }
      ]
    },
    "services": {
      "description": "Listening services on managed hosts",
      "entries": [
        {
          "name": "httpd",
          "port": 80,
          "protocol": "tcp",
          "host_group": "webservers",
          "source": "group_vars/webservers.yml"
        },
        {
          "name": "postgresql",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers",
          "source": "group_vars/dbservers.yml"
        },
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "webservers",
          "source": "group_vars/webservers.yml"
        }
      ]
    },
    "paths": {
      "description": "Filesystem paths managed by Ansible",
      "entries": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgresql",
          "source": "roles/db/tasks/main.yml"
        }
      ]
    }
  },
  "environment": {
    "org": {
      "description": "Organization name",
      "value": "labcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "description": "Deployment environment",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "description": "Compliance framework tier",
      "domain": [
        "soc2"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "description": "Log retention policy",
      "value": 90,
      "source": "group_vars/all.yml"
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "Allow SSH login for members of the sudo group on webservers (dmz zone)",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        24,
        27
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Allow sudo group members with secret clearance to run ALL sudo commands (password required) on webservers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "password_required",
        "description": "sudo demands password authentication (nopassword=false)"
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        17,
        23
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "PostgreSQL SUPERUSER role for sudo group members — grants db login with full privileges",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "value": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        9,
        13
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "PostgreSQL NOSUPERUSER role for developers group — grants db login without superuser privileges",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "value": "NOSUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        14,
        18
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow PostgreSQL network connections from webservers subnet (10.0.1.0/24) to db01.lab.local:5432",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        19,
        23
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Default deny for PostgreSQL connections from any source not in 10.0.1.0/24 (pg_hba implicit deny)",
    "subject_condition": {
      "source_network": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "pg_hba.conf implicit deny",
      "lines": [
        19,
        23
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow inbound HTTP (port 80/tcp) from any source (0.0.0.0/0) to webservers in dmz zone",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "port": {
        "equals": 80
      },
      "service": {
        "equals": "httpd"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": [
        28,
        35
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Grant write access on /var/lib/postgresql/data (mode 0700) to postgres owner on dbservers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/lib/postgresql/data"
      },
      "owner": {
        "equals": "postgres"
      },
      "group": {
        "equals": "postgres"
      },
      "mode": {
        "equals": "0700"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        4,
        8
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Allow provisioning of shell user accounts for sudo group members on webservers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        10,
        16
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "Default-deny: all unlisted subject/resource/action combinations are denied",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "implicit",
      "task": "default-deny",
      "lines": [
        0,
        0
      ]
    }
  },
  {
    "id": "rule-001",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/lib/postgresql/data"
      },
      "owner": {
        "equals": "postgres"
      },
      "group": {
        "equals": "postgres"
      },
      "mode": {
        "equals": "0700"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:read",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "mode 0700 non-owner deny",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
      },
      "service": {
        "equals": "httpd"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
      "lines": "N/A"
    }
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "version": "1:9.6p1-3ubuntu1",
    "category": "critical_remote_kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to latest patched version. Enforce AllowGroups sudo (already configured). Consider key-based auth + password disable.",
    "source": "roles/web/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "version": "1:9.6p1-3ubuntu1",
    "category": "critical_remote_kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to latest patched version. Enforce AllowGroups sudo (already configured). Consider key-based auth + password disable.",
    "source": "roles/web/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "version": "1:9.6p1-3ubuntu1",
    "category": "critical_remote_kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to latest patched version. Enforce AllowGroups sudo (already configured). Consider key-based auth + password disable.",
    "source": "roles/web/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "version": "1:9.6p1-3ubuntu1",
    "category": "critical_remote_kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to latest patched version. Enforce AllowGroups sudo (already configured). Consider key-based auth + password disable.",
    "source": "roles/web/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "version": "1:9.6p1-3ubuntu1",
    "category": "critical_remote_kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to latest patched version. Enforce AllowGroups sudo (already configured). Consider key-based auth + password disable.",
    "source": "roles/web/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "version": "16.2-1.pgdg22.04+1",
    "category": "critical_remote_kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to patched version. Restrict pg_hba.conf to 10.0.1.0/24 only (already enforced). Apply least-privilege DB user grants.",
    "source": "roles/db/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "version": "16.2-1.pgdg22.04+1",
    "category": "critical_remote_kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to patched version. Restrict pg_hba.conf to 10.0.1.0/24 only (already enforced). Apply least-privilege DB user grants.",
    "source": "roles/db/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "version": "16.2-1.pgdg22.04+1",
    "category": "critical_remote_kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to patched version. Restrict pg_hba.conf to 10.0.1.0/24 only (already enforced). Apply least-privilege DB user grants.",
    "source": "roles/db/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "version": "16.2-1.pgdg22.04+1",
    "category": "critical_remote_kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to patched version. Restrict pg_hba.conf to 10.0.1.0/24 only (already enforced). Apply least-privilege DB user grants.",
    "source": "roles/db/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "version": "16.2-1.pgdg22.04+1",
    "category": "critical_remote_kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to patched version. Restrict pg_hba.conf to 10.0.1.0/24 only (already enforced). Apply least-privilege DB user grants.",
    "source": "roles/db/tasks/main.yml"
  }
]
```

## Report

# ABAC Policy Mining Report

**Source**: Ansible configuration rooted at `RLM_ANSIBLE_DIR`
**Organization**: labcorp
**Environment**: production | SOC2
**Generated**: Automated extraction from inventory.ini + group_vars/* + roles/*/tasks/main.yml

---

## Phase 1 — Attribute Catalog

### Subjects

| Attribute | Domain / Values | Source |
|-----------|-----------------|--------|
| users | admin (uid=1001, sudo, operations, secret), appuser (uid=1002, developers, engineering, confidential) | group_vars/all.yml |
| groups | sudo, developers | group_vars/all.yml |
| clearance_levels | confidential, secret | group_vars/all.yml |
| departments | engineering, operations | group_vars/all.yml |

### Resources

| Category | Entries | Source |
|----------|---------|--------|
| hosts | web01.lab.local (10.0.1.10, frontend, dmz, webservers), db01.lab.local (10.0.2.10, primary, internal, dbservers) | inventory.ini |
| networks | 10.0.1.0/24 (dmz), 10.0.2.0/24 (internal) | group_vars/dbservers.yml |
| services | httpd:80/tcp (webservers), postgresql:5432/tcp (dbservers), ssh:22/tcp (webservers) | group_vars/*.yml |
| paths | /var/lib/postgresql/data (owner=postgres, group=postgres, mode=0700) | roles/db/tasks/main.yml |

### Environment

| Attribute | Value | Source |
|-----------|-------|--------|
| org | labcorp | group_vars/all.yml |
| environment | production | inventory.ini |
| compliance_tier | soc2 | inventory.ini |
| default_log_retention_days | 90 | group_vars/all.yml |

---

## Phase 1.5 — Vulnerability Assessment

Three software packages are pinned in `group_vars/all.yml`:

| Product | Pinned Version | Critical Remote CVEs | KEV Hits | Recent CVEs | Assessment |
|---------|---------------|---------------------|----------|-------------|------------|
| apache httpd | 2.4.49-1 | 0 | 0 | 4 | Low — no critical remote CVEs found for this version |
| openssh | 1:9.6p1-3ubuntu1 | 5 | 5 | 4 | **HIGH** — active exploitation confirmed for multiple CVEs |
| postgresql | 16.2-1.pgdg22.04+1 | 5 | 5 | 4 | **HIGH** — multiple critical remote + KEV CVEs affect this version |

> **Note**: `get_cve_details()` API was rate-limited; CVE IDs were collected from search results. Full exploitability details could not be fetched. Recommend running with an API key for full CVSS/exploitability metadata.

---

## Phase 1.6 — Security Scope

All 7 files in the Ansible configuration were classified by path pattern:

| File | Classification | Read in Phase |
|------|---------------|--------------|
| inventory.ini | inventory | Phase 1 |
| group_vars/all.yml | group_vars | Phase 1 |
| group_vars/dbservers.yml | group_vars | Phase 1 |
| group_vars/webservers.yml | group_vars | Phase 1 |
| roles/db/tasks/main.yml | role_task (security-relevant) | Phase 2 |
| roles/web/tasks/main.yml | role_task (security-relevant) | Phase 2 |
| README.md | informational | excluded |

**Note**: No standalone `*sshd*`, `*sudoers*`, `*pg_hba*`, `*iptables*`, or `*selinux*` template files are present. Security configuration (sshd AllowGroups, pg_hba.conf entries, firewalld rules, sudoers entries) is embedded directly in the role task files via Ansible modules (`lineinfile`, `firewalld`, `sudoers`, `community.postgresql.postgresql_user`).

---

## Phase 2 — ABAC Rules Extracted

10 rules extracted from `roles/web/tasks/main.yml` and `roles/db/tasks/main.yml`.

| # | Rule ID | Action | Effect | Subject Condition | Resource Condition |
|---|---------|--------|--------|-------------------|---------------------|
| 1 | rule-001 | ssh:login | permit | groups any_of [sudo] | zone=dmz, service=ssh |
| 2 | rule-002 | sudo:execute | permit | groups any_of [sudo], clearance=secret | inventory_group=webservers |
| 3 | rule-003 | db:login | permit | groups any_of [sudo] | service=postgresql, host_group=dbservers |
| 4 | rule-004 | db:login | permit | groups any_of [developers] | service=postgresql, host_group=dbservers |
| 5 | rule-005 | network:connect | permit | source_network=10.0.1.0/24 | hostname=db01.lab.local, service=postgresql, port=5432 |
| 6 | rule-006 | network:connect | **deny** | source_network=all (implicit deny) | service=postgresql, host_group=dbservers |
| 7 | rule-007 | network:connect | permit | source_network=0.0.0.0/0 | zone=dmz, port=80, service=httpd |
| 8 | rule-008 | filesystem:write | permit | groups any_of [sudo] | path=/var/lib/postgresql/data, owner=postgres, mode=0700 |
| 9 | rule-009 | user:create | permit | groups any_of [sudo] | inventory_group=webservers |
| 10 | rule-010 | * | **deny** | applies_to=all (default-deny) | applies_to=all |

**Key findings**:
- SSH access restricted to sudo group only (AllowGroups via lineinfile targeting /etc/ssh/sshd_config)
- Sudo requires password (nopassword=false for secret clearance users on webservers)
- PostgreSQL uses two privilege tiers: SUPERUSER for sudo-group members, NOSUPERUSER for developers
- pg_hba.conf explicitly allows only 10.0.1.0/24; implicit deny handles all other sources
- Firewalld opens HTTP port 80 to 0.0.0.0/0 (internet-facing DMZ)

---

## Phase 3 — Normalization

- All 10 rules assigned stable IDs: rule-001 through rule-010
- Every attribute referenced in rules exists in the Phase-1 catalog
- Operator grammar enforced: `{"equals": ...}`, `{"any_of": [...]}`, `{"applies_to": {"equals": "all"}}`
- No forbidden operators (`$in`, `$or`, nested ops, free-form strings) used
- Effect values lowercase: `permit` / `deny`
- Separate rules for SUPERUSER vs NOSUPERUSER DB access (rule-003 vs rule-004)

---

## Phase 4 — Validation

- `attributes`: valid JSON, 3 sections (subjects, resources, environment)
- `rules`: valid JSON, 10 rules, all required fields present with provenance
- `vulnerabilities`: valid JSON, 10 entries deduplicated by CVE ID
- `report`: Markdown string, not a dict or JSON blob

---

## Ambiguities & Notes

1. **Credentials**: No explicit credentials (passwords, SSH keys, API tokens) are stored in the Ansible configuration. Secrets management (Ansible Vault, external secret store) is out of scope for this configuration.

2. **Session logging / audit**: No session logging tasks, `profile.d` scripts, or audit enforcement found in the configuration. Compliance with SOC2 log retention (90 days, defined in `group_vars/all.yml`) is not actively enforced by the playbooks.

3. **CVE details rate limit**: `get_cve_details()` API returned rate-limit error. CVE IDs were extracted from search results. For production use, provide an API key to retrieve full CVSS/exploitability details.

4. **No handler files**: No `handlers/` directory or security event handlers found in this configuration.

5. **Software versions**: httpd_version, ssh_version, postgres_version are pinned in `group_vars/all.yml` — this is the authoritative source for the vulnerability assessment.
