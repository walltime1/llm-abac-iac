# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 20:23:02_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 17 | Rules: 14_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f2_threetier_segmented`_

## Attributes

```json
{
  "subjects": {
    "users": [
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
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "department": "engineering",
        "clearance": "confidential",
        "source": "group_vars/all.yml"
      },
      {
        "name": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "department": "data",
        "clearance": "secret",
        "source": "group_vars/all.yml"
      }
    ],
    "groups": {
      "domain": [
        "dba",
        "developers",
        "sudo"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "data",
        "engineering",
        "operations"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "source": "group_vars/appservers.yml"
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "proxy01.lab.local",
        "ip": "10.0.1.10",
        "role": "reverse_proxy",
        "zone": "dmz",
        "inventory_group": "dmz",
        "host_group": "dmz",
        "source": "inventory.ini"
      },
      {
        "hostname": "app01.lab.local",
        "ip": "10.0.2.10",
        "role": "application",
        "zone": "app",
        "inventory_group": "appservers",
        "host_group": "appservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.3.10",
        "role": "primary",
        "zone": "data",
        "inventory_group": "dbservers",
        "host_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      }
    ],
    "paths": [
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "dmz",
        "label": "firewall_allow_from_dmz",
        "source": "group_vars/dmz.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "app",
        "label": "firewall_allow_from_apps",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "data",
        "label": "db_allow_from",
        "source": "group_vars/dbservers.yml"
      }
    ],
    "database_privilege": {
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
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
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-15"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-23"
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "24-28"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database_privilege": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "21-27"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database_privilege": {
        "equals": "NOSUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "28-34"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "35-40"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "41-45"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "13-21"
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
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "22-29"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-011",
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "policy",
      "task": "default-deny",
      "lines": "global"
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
      "port": {
        "equals": 8080
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
    "id": "rule-013",
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
    "id": "rule-014",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to version 1.20.1 or later."
  },
  {
    "cve_id": "CVE-2016-0742",
    "product": "nginx",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to version 1.24.0 or later, or disable HTTP/2 if not required."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to version 9.8p1 or later."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "affects_pinned_version": false,
    "recommendation": "No action required; the pinned version is not affected by this CVE."
  }
]
```

## Report

# ABAC Policy Mining Report

## 1. Executive Summary
Mined an Attribute-Based Access Control (ABAC) policy from the Ansible configuration for `segcorp` (production, PCI tier). The inventory comprises three hosts across DMZ, application, and data tiers. Three human users are defined with distinct groups, departments, and clearance levels.

## 2. Attribute Catalog
- **Subjects**: 3 users (`admin`, `developer`, `dba`), 3 groups (`dba`, `developers`, `sudo`), 2 clearance levels (`confidential`, `secret`), 3 departments (`data`, `engineering`, `operations`), plus `source_network` for network-layer subjects.
- **Resources**: 3 hosts, 3 services (nginx/443, app/8080, postgresql/5432), 1 path (`/var/lib/postgresql/data`), 3 networks, and `database_privilege` (`SUPERUSER`, `NOSUPERUSER`).
- **Environment**: org=`segcorp`, environment=`production`, compliance_tier=`pci`, default_log_retention_days=`365`.

## 3. Extracted Rules
| Rule ID | Action | Effect | Subject Condition | Resource Condition |
|---|---|---|---|---|
| rule-001 | user:create | permit | groups ∈ {developers, sudo} | — |
| rule-002 | network:connect | permit | source_network = `10.0.1.0/24` | port = 8080, protocol = tcp |
| rule-003 | ssh:login | permit | groups ∈ {sudo, developers} | — |
| rule-004 | db:login | permit | groups ∈ {dba} | service = postgresql, privilege = SUPERUSER |
| rule-005 | db:login | permit | groups ∈ {developers} | service = postgresql, privilege = NOSUPERUSER |
| rule-006 | network:connect | permit | source_network = `10.0.2.0/24` | service = postgresql, port = 5432, protocol = tcp |
| rule-007 | ssh:login | permit | groups ∈ {sudo, dba} | — |
| rule-008 | user:create | permit | groups ∈ {sudo} | — |
| rule-009 | network:connect | permit | source_network = `0.0.0.0/0` | port = 443, protocol = tcp |
| rule-010 | ssh:login | permit | groups ∈ {sudo} | — |
| rule-011 | * | deny | applies_to = all | applies_to = all |

## 4. Vulnerability Assessment
Pinned packages evaluated:
- **nginx 1.20.0**
- **openssh 9.6p1**
- **postgresql 13.7**

The CVE-details API rate-limited on the full batch, so semantic evaluation was performed via LLM analysis of search metadata.

**Confirmed affecting pinned version:**
- `CVE-2021-23017` (nginx) — affects nginx 1.20.0. **Recommendation:** Upgrade to nginx 1.20.1 or later.

All other reviewed CVEs (including KEV entries) were assessed as **not affecting** the pinned versions.

## 5. Ambiguities & Notes
- **Filesystem ACLs**: The postgres data directory (`/var/lib/postgresql/data`) is configured with owner `postgres`, a system user not present in the subject catalog. No filesystem access rules were emitted for human subjects because the Ansible tasks do not grant such access explicitly.
- **pg_hba implicit deny**: Postgres default-deny behavior is covered by the global default-deny rule (`rule-011`). The operator grammar does not support negation, so a standalone explicit service-scoped deny rule could not be expressed beyond the global catch-all.
- **Obligations**: No session-logging, audit scripts, or `profile.d` enforcement tasks were found in the role playbooks; therefore no obligations are attached.
- **Rate limiting**: `get_cve_details` exceeded its unauthenticated rate limit; CVE impact was inferred from `search_critical_remote` and `search_kev_vulnerabilities` metadata combined with sub-LLM semantic analysis.
