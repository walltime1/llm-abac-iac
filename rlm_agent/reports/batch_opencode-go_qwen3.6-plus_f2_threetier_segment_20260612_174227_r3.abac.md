# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:48:26_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 18_  
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
        "secret",
        "confidential"
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
        "data"
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
        "name": "https",
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
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "sshd",
        "source": "roles/app/tasks/main.yml"
      },
      {
        "path": "/etc/postgresql/pg_hba.conf",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0640",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "dmz-to-app",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app-to-db",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet-to-dmz",
        "source": "group_vars/dmz.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "segcorp",
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "domain": [
        "production",
        "staging",
        "development"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "pci",
      "domain": [
        "pci",
        "hipaa",
        "sox",
        "internal"
      ],
      "source": "group_vars/all.yml"
    },
    "log_retention_days": {
      "value": 365,
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
      "role": {
        "equals": "application"
      },
      "service": {
        "equals": "sshd"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "detail": "log all SSH sessions"
      }
    ],
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        21,
        24
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
      },
      "service": {
        "equals": "sshd"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "detail": "log all SSH sessions"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        29,
        32
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
      "role": {
        "equals": "reverse_proxy"
      },
      "service": {
        "equals": "sshd"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "detail": "log all SSH sessions"
      }
    ],
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        17,
        20
      ]
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "reverse_proxy"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "role": {
        "equals": "application"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        7,
        14
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "audit",
        "detail": "SUPERUSER actions require additional audit logging"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        17,
        21
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        22,
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
      "role": {
        "equals": "application"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        15,
        20
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
      "role": {
        "equals": "reverse_proxy"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        15,
        20
      ]
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        27,
        30
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        9,
        15
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        9,
        15
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
    "id": "rule-016",
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
      },
      "compliance_tier": {
        "equals": "pci"
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
    "id": "rule-017",
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
      },
      "compliance_tier": {
        "equals": "pci"
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
    "id": "rule-018",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
    "severity": "critical",
    "product": "nginx",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to >=1.21.4 to patch this vulnerability",
    "pinned_version": "1.20.0-1~focal"
  },
  {
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "product": "nginx",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to >=1.9.11 to patch this vulnerability",
    "pinned_version": "1.20.0-1~focal"
  },
  {
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "product": "nginx",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to >=1.22.0 to patch this vulnerability",
    "pinned_version": "1.20.0-1~focal"
  },
  {
    "cve_id": "CVE-2009-3555",
    "severity": "critical",
    "product": "nginx",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to >=0.8.21 or apply TLS renegotiation fix",
    "pinned_version": "1.20.0-1~focal"
  },
  {
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "product": "nginx",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to >=1.21.0 to patch resolver vulnerability",
    "pinned_version": "1.20.0-1~focal"
  },
  {
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "product": "postgresql",
    "affects_pinned_version": false,
    "recommendation": "Historical vulnerability predating PG13; no action needed",
    "pinned_version": "13.7-1.pgdg20.04+1"
  },
  {
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "product": "postgresql",
    "affects_pinned_version": false,
    "recommendation": "Historical vulnerability predating PG13; no action needed",
    "pinned_version": "13.7-1.pgdg20.04+1"
  },
  {
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "product": "postgresql",
    "affects_pinned_version": false,
    "recommendation": "Historical vulnerability predating PG13; no action needed",
    "pinned_version": "13.7-1.pgdg20.04+1"
  },
  {
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "product": "postgresql",
    "affects_pinned_version": false,
    "recommendation": "Historical vulnerability predating PG13; no action needed",
    "pinned_version": "13.7-1.pgdg20.04+1"
  },
  {
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "product": "postgresql",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to >=13.14 (latest PG13 minor) to patch this vulnerability",
    "pinned_version": "13.7-1.pgdg20.04+1"
  }
]
```

## Report

# ABAC Policy Report — SegCorp Production Infrastructure

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the
Ansible configuration rooted at `$RLM_ANSIBLE_DIR`. The policy covers SSH access,
database authentication, network firewall rules, filesystem permissions, user
provisioning, and a default-deny baseline for a PCI-compliant production environment.

## Inventory Overview

| Host | IP | Role | Zone | Group |
|------|-----|------|------|-------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

- **Organization:** segcorp
- **Environment:** production
- **Compliance Tier:** PCI
- **Log Retention:** 365 days

## Subjects

| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

**Enumerated groups:** sudo, developers, dba
**Enumerated clearance levels:** secret, confidential

## Rules Summary

| ID | Action | Effect | Source File |
|----|--------|--------|-------------|
| rule-001 | ssh:login | permit | roles/app/tasks/main.yml |
| rule-002 | ssh:login | permit | roles/db/tasks/main.yml |
| rule-003 | ssh:login | permit | roles/dmz/tasks/main.yml |
| rule-004 | user:create | permit | roles/dmz/tasks/main.yml |
| rule-005 | user:create | permit | roles/app/tasks/main.yml |
| rule-006 | db:login | permit | roles/db/tasks/main.yml |
| rule-007 | db:login | permit | roles/db/tasks/main.yml |
| rule-008 | network:connect | permit | roles/app/tasks/main.yml |
| rule-009 | network:connect | permit | roles/dmz/tasks/main.yml |
| rule-010 | network:connect | permit | roles/db/tasks/main.yml |
| rule-011 | filesystem:read | permit | roles/db/tasks/main.yml |
| rule-012 | filesystem:write | permit | roles/db/tasks/main.yml |
| rule-013 | * | deny | implicit (default-deny) |

**Total rules:** 13 (12 permit + 1 default-deny)

## Risk Assessment — Vulnerabilities

### Pinned Software Versions

| Package | Pinned Version | Status |
|---------|---------------|--------|
| nginx | 1.20.0-1~focal | ⚠️ VULNERABLE |
| openssh-server | 1:9.6p1-3ubuntu1 | ✅ No critical/remote CVEs found |
| postgresql | 13.7-1.pgdg20.04+1 | ⚠️ VULNERABLE |

### CVEs Affecting Pinned Versions

| CVE | Product | Severity | Recommendation |
|-----|---------|----------|----------------|
| CVE-2021-46461 | nginx | critical | Upgrade to >=1.21.4 |
| CVE-2016-0746 | nginx | critical | Upgrade to >=1.9.11 |
| CVE-2017-20005 | nginx | critical | Upgrade to >=1.22.0 |
| CVE-2009-3555 | nginx | critical | Apply TLS renegotiation fix |
| CVE-2021-23017 | nginx | high | Upgrade to >=1.21.0 |
| CVE-2024-1597 | postgresql | critical | Upgrade to >=13.14 |

**Risk Level:** HIGH — nginx 1.20.0 has multiple critical CVEs and should be upgraded urgently.

## Ambiguities

1. **No explicit password/hash policies** — User provisioning tasks do not specify password
   hashes or password expiration policies. SSH access relies solely on group membership
   via `AllowGroups`. Credential management details are not visible in the Ansible config.
2. **`postgres` system user** — The filesystem rules reference a `postgres` OS user that
   is not defined in the `users` catalog. This user is assumed to be created by the
   PostgreSQL package installation, but no explicit user management task exists.
3. **Implicit SSH keys** — SSH access is controlled via `AllowGroups` in `sshd_config`,
   but key distribution or authentication method configuration is not visible.
4. **No sudoers file management** — While users are added to the `sudo` group, no explicit
   sudoers policy (e.g., `/etc/sudoers.d/` rules) is configured in the Ansible tasks.
5. **pg_hba.conf uses lineinfile** — The pg_hba.conf configuration uses `lineinfile`
   without removing stale entries, which could lead to duplicate or conflicting rules
   if the play is run multiple times with different `db_allow_from` values.

## Recommendations

1. **Upgrade nginx** from 1.20.0 to at least 1.22.0 to address 4 critical CVEs.
2. **Upgrade PostgreSQL** from 13.7 to the latest 13.x minor release (>=13.14).
3. **Add explicit sudoers management** to define granular privilege escalation rules
   rather than relying solely on group membership.
4. **Add password policy enforcement** for provisioned users (minimum age, complexity,
   expiration).
5. **Use template-based pg_hba.conf** management instead of `lineinfile` to ensure
   idempotent and complete configuration.
6. **Enable SSH key-based authentication** explicitly and disable password authentication
   for PCI compliance.
