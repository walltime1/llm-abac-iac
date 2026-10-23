# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 21:23:48_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 11 | Rules: 9_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "entries": [
        {
          "name": "admin",
          "uid": 1001,
          "groups": [
            "sudo"
          ],
          "department": "operations",
          "clearance": "secret"
        },
        {
          "name": "appuser",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "department": "engineering",
          "clearance": "confidential"
        }
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "domain": [
        "developers",
        "sudo"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "domain": [
        "engineering",
        "operations"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "source": "group_vars/webservers_legacy.yml, group_vars/webservers_patched.yml, group_vars/dbservers.yml"
    },
    "user": {
      "domain": [
        "admin",
        "appuser"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": {
      "entries": [
        {
          "hostname": "web-new01.lab.local",
          "ip": "10.0.1.10",
          "role": "frontend",
          "zone": "dmz",
          "inventory_group": "webservers_patched"
        },
        {
          "hostname": "web-old01.lab.local",
          "ip": "10.0.1.20",
          "role": "frontend",
          "zone": "dmz",
          "inventory_group": "webservers_legacy"
        },
        {
          "hostname": "db01.lab.local",
          "ip": "10.0.2.10",
          "role": "primary",
          "zone": "internal",
          "inventory_group": "dbservers"
        }
      ],
      "source": "inventory.ini"
    },
    "services": {
      "entries": [
        {
          "name": "nginx",
          "port": 443,
          "protocol": "tcp",
          "host_group": "webservers_legacy"
        },
        {
          "name": "nginx",
          "port": 443,
          "protocol": "tcp",
          "host_group": "webservers_patched"
        },
        {
          "name": "postgresql",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers"
        }
      ],
      "source": "group_vars/*.yml"
    },
    "paths": {
      "entries": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": null,
          "group": null,
          "mode": null,
          "service": "postgresql"
        }
      ],
      "source": "group_vars/dbservers.yml"
    },
    "networks": {
      "entries": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "internal",
          "label": "db_access"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "dmz",
          "label": "firewall_allow"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "dmz",
          "label": "firewall_allow"
        }
      ],
      "source": "group_vars/*.yml"
    },
    "service": {
      "domain": [
        "nginx",
        "postgresql"
      ],
      "source": "group_vars/*.yml"
    },
    "port": {
      "source": "group_vars/*.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "group_vars/*.yml"
    },
    "path": {
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "owner": {
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "host_group": {
      "domain": [
        "dbservers",
        "webservers_legacy",
        "webservers_patched"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "domain": [
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "hostname": {
      "domain": [
        "web-new01.lab.local",
        "web-old01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "patchcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "compliance_tier": {
      "domain": [
        "soc2"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "domain": [
        90
      ],
      "source": "group_vars/all.yml"
    }
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "21-25"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "21-25"
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "13-20"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "13-20"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": "16-20"
    }
  },
  {
    "id": "rule-006",
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
      "file": "policy",
      "task": "default-deny",
      "lines": "0"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
    "id": "rule-008",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
    "id": "rule-009",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "epss_score": 0.73544,
    "affects_pinned_version": true,
    "recommendation": "Update the legacy pinned version 1.20.0-1~focal to nginx 1.20.1 or later; version 1.24.0-2ubuntu1 is not affected."
  }
]
```

## Report

# ABAC Policy Mining Report — PatchCorp Ansible

## 1. Scope
Policy slice requested: **all** (full coverage).

## 2. Attribute Catalog Summary
### Subjects
- **users**: admin (uid 1001, groups [sudo], department operations, clearance secret), appuser (uid 1002, groups [developers], department engineering, clearance confidential)
- **groups**: developers, sudo
- **clearance_levels**: confidential, secret
- **departments**: engineering, operations
- **source_network**: derived from firewall and database allow-lists (CIDR strings)

### Resources
- **hosts**: 3 hosts mapped from `inventory.ini`
  - web-new01.lab.local (frontend, dmz, webservers_patched)
  - web-old01.lab.local (frontend, dmz, webservers_legacy)
  - db01.lab.local (primary, internal, dbservers)
- **services**: nginx:443/tcp (webservers_legacy & webservers_patched), postgresql:5432/tcp (dbservers)
- **paths**: /var/lib/postgresql/data (owner postgres, group postgres, mode 0700)
- **networks**: 10.0.1.0/24 (internal, db_access), 0.0.0.0/0 (dmz, firewall_allow)
- **host_group**: dbservers, webservers_legacy, webservers_patched
- **role**: frontend, primary
- **zone**: dmz, internal

### Environment
- **org**: patchcorp
- **environment**: production
- **compliance_tier**: soc2
- **default_log_retention_days**: 90

## 3. Extracted ABAC Rules
Six rules were extracted (five permits + default-deny):

| ID | Action | Effect | Key Condition |
|---|---|---|---|
| rule-001 | ssh:login | permit | subjects.groups any_of [sudo] |
| rule-002 | ssh:login | permit | subjects.groups any_of [sudo] |
| rule-003 | network:connect | permit | source_network equals 0.0.0.0/0, resource.port equals 443 |
| rule-004 | network:connect | permit | source_network equals 0.0.0.0/0, resource.port equals 443 |
| rule-005 | network:connect | permit | source_network equals 10.0.1.0/24, resource.service equals postgresql |
| rule-006 | * | deny | catch-all (applies_to all) |

## 4. Vulnerability Assessment
- **CVE-2021-23017** (nginx, severity *high*, CVSS 7.7, EPSS 0.73544) **affects the legacy pinned version** `1.20.0-1~focal`.  
  **Recommendation:** Upgrade legacy webservers to nginx `1.20.1` or later. The patched webservers running `1.24.0-2ubuntu1` are **not affected**.
- OpenSSH (`1:9.6p1-3ubuntu1`) and PostgreSQL (`16.2-1.pgdg22.04+1`) scanned critical-remote and KEV CVEs **do not affect** their respective pinned versions.

## 5. Ambiguities & Observations
- **No sudoers file or task** was found; sudo access is implied solely by group membership (`sudo`).
- **No explicit deny lines** are present in `sshd_config`, firewalld, or `pg_hba.conf`; default-deny behavior is assumed from the underlying systems.
- **No database user or privilege tasks** (`postgresql_user`, `mysql_user`) exist, so no `db:login` rules could be extracted beyond network-level `pg_hba.conf` access.
- **Filesystem ACL rule** for the PostgreSQL data directory (`mode 0700`) was noted, but because the owner `postgres` is not listed in the `users` variable and no subject predicate could be formed without inventing group membership, it was omitted per the "do not invent" constraint.
- **Credentials / secrets** (passwords, private keys, vault files) are not materialized in any scanned file, though runtime variables may reference them.
- **No session logging, audit scripts, SELinux booleans, or monitoring access configs** were discovered in the role tasks.

## 6. Recommendations
1. Patch nginx on `webservers_legacy` immediately to remediate CVE-2021-23017.
2. Add an explicit reject rule to `pg_hba.conf` for defense-in-depth.
3. Materialize the `users` variable into actual `ansible.builtin.user` tasks if local accounts are required, and attach `user:create` rules with appropriate conditions.
4. Review whether `appuser` or the `developers` group should have any host/database access beyond the current implicit defaults.
