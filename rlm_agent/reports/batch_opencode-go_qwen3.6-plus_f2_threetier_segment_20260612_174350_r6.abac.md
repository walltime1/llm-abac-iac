# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:49:37_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 14_  
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
        "clearance": "secret",
        "department": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "group_vars/all.yml"
      },
      {
        "name": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "clearance": "secret",
        "department": "data",
        "source": "group_vars/all.yml"
      }
    ],
    "groups": {
      "values": [
        "sudo",
        "developers",
        "dba"
      ],
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "values": [
        "secret",
        "confidential"
      ],
      "domain": [
        "top_secret",
        "secret",
        "confidential",
        "unclassified"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "values": [
        "operations",
        "engineering",
        "data"
      ],
      "domain": [
        "operations",
        "engineering",
        "data",
        "finance",
        "hr"
      ],
      "source": "group_vars/all.yml"
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
        "source": "inventory.ini"
      },
      {
        "hostname": "app01.lab.local",
        "ip": "10.0.2.10",
        "role": "application",
        "zone": "app",
        "inventory_group": "appservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.3.10",
        "role": "primary",
        "zone": "data",
        "inventory_group": "dbservers",
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
        "name": "application",
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
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "DMZ subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "App subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "Internet (any)",
        "source": "group_vars/dmz.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "segcorp",
      "domain": [
        "segcorp",
        "acme",
        "globex"
      ],
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
      "value": "pci",
      "domain": [
        "pci",
        "hipaa",
        "sox",
        "fedramp",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "value": 365,
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
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        21,
        25
      ]
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
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        13,
        19
      ]
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        38,
        42
      ]
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
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        20,
        25
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "description": "SUPERUSER privilege requires audit logging"
      }
    ]
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
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        26,
        31
      ]
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
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        32,
        36
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        27,
        31
      ]
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        19,
        25
      ]
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        7,
        11
      ]
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        12,
        17
      ]
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
    "environment_condition": {
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
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to >= 1.21.4 to resolve HTTP request smuggling vulnerability"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 7.7,
    "severity": "high",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to >= 1.21.0 to fix resolver vulnerability"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Verify nginx build includes upstream patch for server directive buffer overflow"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to latest 13.x patch release (>= 13.14) to fix extension script injection"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Historical vulnerability affecting PostgreSQL 9.x; current 13.7 may be patched. Verify changelog."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Historical vulnerability affecting PostgreSQL 9.x; current 13.7 may be patched. Verify changelog."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
Mined ABAC policy from Ansible configuration (RLM_ANSIBLE_DIR) with `policy_goal: all`.
Extracted **11 rules** covering SSH access, firewall rules, database authentication, user provisioning, and default-deny across 3 host zones (dmz, app, data).

## Catalog Summary
- **Subjects**: 3 users (admin, developer, dba), 3 groups (sudo, developers, dba)
- **Resources**: 3 hosts, 3 services (nginx:443, app:8080, postgresql:5432), 1 protected path
- **Environment**: org=segcorp, environment=production, compliance_tier=pci

## Rules Overview
| ID | Action | Subject | Resource Zone | Effect |
|----|--------|---------|---------------|--------|
| rule-001 | ssh:login | sudo, developers | app | permit |
| rule-002 | network:connect | 10.0.1.0/24 | app:8080 | permit |
| rule-003 | ssh:login | sudo, dba | data | permit |
| rule-004 | db:login | dba | postgresql (SUPERUSER) | permit |
| rule-005 | db:login | developers | postgresql (NOSUPERUSER) | permit |
| rule-006 | network:connect | 10.0.2.0/24 | postgresql:5432 | permit |
| rule-007 | ssh:login | sudo | dmz | permit |
| rule-008 | network:connect | 0.0.0.0/0 | dmz:443 | permit |
| rule-009 | user:create | sudo, developers | app | permit |
| rule-010 | user:create | sudo | dmz | permit |
| rule-011 | * | all | all | deny |

## Vulnerability Assessment
| CVE | Product | Pinned Version | Affects | Severity | Recommendation |
|-----|---------|---------------|---------|----------|----------------|
| CVE-2021-46461 | nginx | 1.20.0 | YES | 9.8 critical | Upgrade >= 1.21.4 |
| CVE-2021-23017 | nginx | 1.20.0 | YES | 7.7 high | Upgrade >= 1.21.0 |
| CVE-2024-1597 | postgresql | 13.7 | YES | 10.0 critical | Upgrade to latest 13.x patch |
| CVE-2017-20005 | nginx | 1.20.0 | NO | 9.8 critical | Verify patch status |
| CVE-2013-1902 | postgresql | 13.7 | NO | 10.0 critical | Historical (9.x) |
| CVE-2013-1903 | postgresql | 13.7 | NO | 10.0 critical | Historical (9.x) |

Openssh-server (9.6p1) returned 0 critical/remote CVEs; 1 KEV CVE found but lacked actionable detail.

## Ambiguities & Notes
1. **PostgreSQL data directory** (`/var/lib/postgresql/data`, mode 0700): Owner is system account `postgres`, which is not in the user catalog. Filesystem access is effectively restricted to the postgres system user only.
2. **CVE version matching**: Detailed version-range analysis was limited by API rate limits on `get_cve_details`. `affects_pinned_version` assessments are based on general CVE knowledge and should be verified.
3. **No sudoers tasks found**: The configuration does not define explicit sudoers rules (e.g., `/etc/sudoers.d/` entries). SSH AllowGroups restricts login, but sudo privilege escalation rules are not captured in this Ansible config.
4. **No SELinux rules**: No SELinux boolean or policy tasks were found in the role files.
5. **Credentials**: No credential management tasks (e.g., vault, secrets) were observed in the scanned files.
6. **Line numbers**: Source line ranges are approximate based on YAML task structure; minor offsets may exist.

## Compliance Notes
- Environment is tagged `compliance_tier: pci` — all rules include environment_condition per policy requirements.
- Database access rules include obligation for session logging on SUPERUSER privileges (rule-004).
- Default-deny rule (rule-011) ensures implicit deny for all unmatched access attempts.
