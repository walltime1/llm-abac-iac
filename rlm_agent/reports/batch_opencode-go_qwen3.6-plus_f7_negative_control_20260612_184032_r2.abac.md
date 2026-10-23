# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:45:13_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 8 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "admin": {
        "name": "admin",
        "uid": 1001,
        "groups": [
          "sudo"
        ],
        "clearance": "secret",
        "department": "operations",
        "source": "roles/web"
      },
      "appuser": {
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "roles/web"
      }
    },
    "groups": {
      "sudo": {
        "name": "sudo",
        "source": "group_vars/all.yml"
      },
      "developers": {
        "name": "developers",
        "source": "group_vars/all.yml"
      },
      "postgres": {
        "name": "postgres",
        "source": "roles/db/tasks/main.yml"
      }
    },
    "clearance_levels": {
      "secret": {
        "value": "secret",
        "domain": [
          "top_secret",
          "secret",
          "confidential",
          "public"
        ],
        "source": "group_vars/all.yml"
      },
      "confidential": {
        "value": "confidential",
        "domain": [
          "top_secret",
          "secret",
          "confidential",
          "public"
        ],
        "source": "group_vars/all.yml"
      }
    },
    "departments": {
      "operations": {
        "value": "operations",
        "domain": [
          "operations",
          "engineering",
          "security",
          "management"
        ],
        "source": "group_vars/all.yml"
      },
      "engineering": {
        "value": "engineering",
        "domain": [
          "operations",
          "engineering",
          "security",
          "management"
        ],
        "source": "group_vars/all.yml"
      }
    },
    "source_networks": {
      "0.0.0.0/0": {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "public",
        "source": "group_vars/webservers.yml"
      },
      "10.0.1.0/24": {
        "cidr": "10.0.1.0/24",
        "zone": "internal",
        "label": "webservers-subnet",
        "source": "group_vars/dbservers.yml"
      }
    },
    "system_accounts": {
      "postgres": {
        "name": "postgres",
        "uid": null,
        "groups": [
          "postgres"
        ],
        "clearance": null,
        "department": "database",
        "source": "roles/db/tasks/main.yml"
      }
    },
    "network_sources": {
      "0.0.0.0/0": {
        "source_network": "0.0.0.0/0",
        "source_zone": "internet",
        "source": "group_vars/webservers.yml"
      },
      "10.0.1.0/24": {
        "source_network": "10.0.1.0/24",
        "source_zone": "internal",
        "source": "group_vars/dbservers.yml"
      }
    }
  },
  "resources": {
    "hosts": {
      "web01.lab.local": {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers",
        "source": "inventory.ini"
      },
      "db01.lab.local": {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      }
    },
    "services": {
      "nginx": {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      },
      "postgresql": {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "roles/db/tasks/main.yml"
      },
      "openssh-server": {
        "name": "openssh-server",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      }
    },
    "paths": {
      "/var/lib/postgresql/data": {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      },
      "/etc/postgresql/pg_hba.conf": {
        "path": "/etc/postgresql/pg_hba.conf",
        "owner": "root",
        "group": "root",
        "mode": "0600",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      },
      "/etc/ssh/sshd_config": {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0600",
        "service": "openssh-server",
        "source": "roles/web/tasks/main.yml"
      },
      "/var/www/html": {
        "path": "/var/www/html",
        "owner": "root",
        "group": "root",
        "mode": "0755",
        "service": "nginx",
        "source": "group_vars/webservers.yml"
      }
    },
    "networks": {
      "10.0.1.0/24": {
        "cidr": "10.0.1.0/24",
        "zone": "internal",
        "label": "webservers-subnet",
        "source": "group_vars/dbservers.yml"
      },
      "0.0.0.0/0": {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "public",
        "source": "group_vars/webservers.yml"
      }
    },
    "databases": {
      "all": {
        "database": "all",
        "schema": "public",
        "source": "roles/db/tasks/main.yml"
      }
    }
  },
  "environment": {
    "org": {
      "value": "labcorp",
      "domain": null,
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "domain": [
        "production",
        "staging",
        "development",
        "test"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "domain": [
        "soc2",
        "pci_dss",
        "hipaa",
        "iso27001",
        "none"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "value": 90,
      "domain": null,
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
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        12,
        17
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "nopassword": false,
    "obligations": [],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        19,
        24
      ]
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "openssh-server"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        33,
        36
      ]
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "openssh-server"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "deny",
    "obligations": [],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        33,
        36
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "service": {
        "equals": "nginx"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        26,
        31
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privileges": [
      "LOGIN",
      "SUPERUSER"
    ],
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        14,
        19
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privileges": [
      "LOGIN",
      "NOSUPERUSER"
    ],
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        21,
        26
      ]
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        28,
        31
      ]
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        28,
        31
      ]
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "groups": {
        "equals": "postgres"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        7,
        12
      ]
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "groups": {
        "equals": "postgres"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        7,
        12
      ]
    }
  },
  {
    "id": "rule-012",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "*",
    "effect": "deny",
    "obligations": [],
    "source": {
      "file": "implicit",
      "task": "Default deny rule",
      "lines": [
        0,
        0
      ]
    }
  },
  {
    "id": "rule-013",
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
      "applies_to": {
        "equals": "all"
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
    "id": "rule-014",
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
      "applies_to": {
        "equals": "all"
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
    "id": "rule-015",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "service": {
        "equals": "nginx"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "pinned_version": "1.27.0-1~noble",
    "reason_not_affected": "Vulnerability affects nginx 0.6.18-1.8.0 and 1.9.x before 1.9.10; pinned version 1.27.0 is not in affected range",
    "recommendation": "No action required; pinned version is not affected"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "njs (nginx module)",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "pinned_version": "nginx 1.27.0-1~noble",
    "reason_not_affected": "Vulnerability is in the njs scripting module, not core nginx; njs version not pinned separately",
    "recommendation": "Monitor njs module version if njs is used; ensure njs is updated to latest if deployed"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql_jdbc_driver",
    "severity": "high",
    "cvss_score": 7.1,
    "affects_pinned_version": false,
    "pinned_version": "postgresql 16.4-1.pgdg24.04+1",
    "reason_not_affected": "Vulnerability is in PostgreSQL JDBC Driver (Java client library), not the PostgreSQL server",
    "recommendation": "Ensure any Java applications using pgjdbc are updated to >= 42.2.26 or 42.4.1"
  }
]
```

## Report

# ABAC Policy Report — LabCorp Infrastructure

## Summary
Mined ABAC policy from Ansible configuration (`RLM_ANSIBLE_DIR`) for scope: **all**

### Catalog
- **Subjects**: 2 users (admin, appuser), 3 groups (sudo, developers, postgres)
- **Resources**: 2 hosts, 3 services, 4 filesystem paths, 2 network ranges, 1 database
- **Environment**: org=labcorp, environment=production, compliance_tier=soc2

### Rules Extracted: 12
| ID | Action | Effect | Subject Predicate | Task Source |
|----|--------|--------|-------------------|-------------|
| rule-001 | user:create | permit | groups ∈ [sudo] | Provision shell users |
| rule-002 | sudo:execute | permit | groups ∈ [sudo] ∧ clearance=secret | Grant sudo to admin users |
| rule-003 | ssh:login | permit | groups ∈ [sudo] | Restrict SSH to sudo group |
| rule-004 | ssh:login | deny | groups ∈ [developers] | Restrict SSH to sudo group |
| rule-005 | network:connect | permit | source_network=0.0.0.0/0 | Firewall — allow HTTPS from internet |
| rule-006 | db:login | permit | groups ∈ [sudo] | Create DB superuser role |
| rule-007 | db:login | permit | groups ∈ [developers] | Create DB read-only role |
| rule-008 | network:connect | permit | source_network=10.0.1.0/24 | Allow postgres from webservers subnet |
| rule-009 | network:connect | deny | source_network=0.0.0.0/0 | Implicit deny for postgres |
| rule-010 | filesystem:read | permit | groups ∈ [postgres] | Ensure postgres data dir |
| rule-011 | filesystem:write | permit | groups ∈ [postgres] | Ensure postgres data dir |
| rule-012 | * | deny | applies_to=all | Default deny |

## Vulnerabilities
All 3 CVEs found via search were evaluated against pinned versions:
- **CVE-2016-0746** (nginx, CVSS 9.8): Does **not** affect pinned nginx 1.27.0; vulnerability is in versions ≤1.8.0 and 1.9.x < 1.9.10.
- **CVE-2021-46461** (nginx njs module, CVSS 9.8): Affects the njs scripting engine, not core nginx. No njs version is pinned separately.
- **CVE-2022-31197** (PostgreSQL JDBC Driver, CVSS 7.1): Affects the Java client driver, not the PostgreSQL 16.4 server.

**Result**: No applicable CVEs against the pinned software stack.

## Ambiguities
1. **SSH version pinning**: `ssh_version` is set to `1:9.9p1-3ubuntu1` but `openssh-server` package pinning is in `roles/web/tasks/main.yml` — the actual version string uses the Ubuntu epoch prefix.
2. **njs module**: Not explicitly pinned or referenced in Ansible config; if nginx njs module is deployed, its version is unknown.
3. **PostgreSQL JDBC Driver**: Not referenced in Ansible configuration; client-side version is not managed here.
4. **Implicit firewall deny**: No explicit deny rule in firewalld configuration; the default-deny is provided by the policy default-deny rule, not by an Ansible-managed iptables/firewalld deny.
5. **Sudoers NOPASSWD**: Sudo is configured with `nopassword: false` (password required); no NOPASSWD ambiguity detected.
6. **pg_hba.conf**: Only allows connections from `10.0.1.0/24`; all other access is implicitly denied by PostgreSQL's default-deny in pg_hba.conf processing order.
7. **No credentials flagged**: No plaintext passwords or API keys detected in the Ansible configuration.

## Compliance Notes
- Environment is `production` with `soc2` compliance tier — all rules include environment conditions.
- SSH access restricted to sudo group with AllowGroups directive.
- PostgreSQL superuser limited to sudo group members; developers get NOSUPERUSER.
- PostgreSQL network access restricted to webservers subnet only.
- Postgres data directory is mode 0700, owned by postgres:postgres.
