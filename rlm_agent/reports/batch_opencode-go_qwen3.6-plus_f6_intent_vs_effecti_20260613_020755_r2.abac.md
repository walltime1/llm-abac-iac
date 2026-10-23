# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 02:18:29_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subject": {
    "attributes": {
      "user": {
        "type": "string",
        "description": "Username",
        "domain": [
          "admin",
          "developer",
          "dba"
        ],
        "source": "group_vars/all.yml"
      },
      "uid": {
        "type": "integer",
        "description": "User ID",
        "domain": [
          1001,
          1002,
          1003
        ],
        "source": "group_vars/all.yml"
      },
      "groups": {
        "type": "set",
        "description": "Unix groups the user belongs to",
        "domain": [
          "sudo",
          "developers",
          "dba",
          "postgres"
        ],
        "source": "group_vars/all.yml"
      },
      "clearance": {
        "type": "string",
        "description": "Security clearance level",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      },
      "department": {
        "type": "string",
        "description": "Organizational department",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      },
      "source_ip": {
        "type": "string",
        "description": "Source IP address or network (for network-layer rules)",
        "source": "group_vars/appservers.yml"
      },
      "source_network": {
        "type": "string",
        "description": "Source CIDR network (for network-layer rules)",
        "source": "group_vars/appservers.yml"
      },
      "source_zone": {
        "type": "string",
        "description": "Source network zone",
        "domain": [
          "dmz",
          "app",
          "data",
          "internet"
        ],
        "source": "group_vars/appservers.yml"
      }
    },
    "entities": [
      {
        "user": "admin",
        "uid": 1001,
        "groups": [
          "sudo"
        ],
        "department": "operations",
        "clearance": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "user": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "department": "engineering",
        "clearance": "confidential",
        "source": "group_vars/all.yml"
      },
      {
        "user": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "department": "data",
        "clearance": "secret",
        "source": "group_vars/all.yml"
      }
    ]
  },
  "resource": {
    "attributes": {
      "hostname": {
        "type": "string",
        "description": "Host FQDN",
        "domain": [
          "proxy01.lab.local",
          "app01.lab.local",
          "db01.lab.local"
        ],
        "source": "inventory.ini"
      },
      "ip": {
        "type": "string",
        "description": "Host IP address",
        "domain": [
          "10.0.1.10",
          "10.0.2.10",
          "10.0.3.10"
        ],
        "source": "inventory.ini"
      },
      "role": {
        "type": "string",
        "description": "Host role",
        "domain": [
          "reverse_proxy",
          "application",
          "primary"
        ],
        "source": "inventory.ini"
      },
      "zone": {
        "type": "string",
        "description": "Network zone",
        "domain": [
          "dmz",
          "app",
          "data"
        ],
        "source": "inventory.ini"
      },
      "host_group": {
        "type": "string",
        "description": "Inventory group",
        "domain": [
          "dmz",
          "appservers",
          "dbservers"
        ],
        "source": "inventory.ini"
      },
      "service": {
        "type": "string",
        "description": "Service name",
        "domain": [
          "nginx",
          "app",
          "postgresql",
          "sshd"
        ],
        "source": "group_vars/dmz.yml"
      },
      "port": {
        "type": "integer",
        "description": "Service port number",
        "domain": [
          443,
          8080,
          5432,
          22
        ],
        "source": "group_vars/dmz.yml"
      },
      "protocol": {
        "type": "string",
        "description": "Network protocol",
        "domain": [
          "tcp",
          "udp"
        ],
        "source": "group_vars/dmz.yml"
      },
      "path": {
        "type": "string",
        "description": "Filesystem path",
        "domain": [
          "/var/lib/postgresql/data"
        ],
        "source": "group_vars/dbservers.yml"
      },
      "owner": {
        "type": "string",
        "description": "File owner",
        "domain": [
          "postgres"
        ],
        "source": "group_vars/dbservers.yml"
      },
      "group": {
        "type": "string",
        "description": "File group",
        "domain": [
          "postgres"
        ],
        "source": "group_vars/dbservers.yml"
      },
      "mode": {
        "type": "string",
        "description": "File permission mode (octal)",
        "domain": [
          "0700"
        ],
        "source": "group_vars/dbservers.yml"
      },
      "database": {
        "type": "string",
        "description": "Database name",
        "domain": [
          "all"
        ],
        "source": "roles/db/tasks/main.yml"
      },
      "schema": {
        "type": "string",
        "description": "Database schema",
        "domain": [
          "public"
        ],
        "source": "roles/db/tasks/main.yml"
      }
    }
  },
  "environment": {
    "attributes": {
      "org": {
        "type": "string",
        "description": "Organization name",
        "domain": [
          "segcorp"
        ],
        "source": "group_vars/all.yml"
      },
      "environment": {
        "type": "string",
        "description": "Deployment environment",
        "domain": [
          "production"
        ],
        "source": "inventory.ini"
      },
      "compliance_tier": {
        "type": "string",
        "description": "Compliance tier",
        "domain": [
          "pci"
        ],
        "source": "inventory.ini"
      },
      "log_retention_days": {
        "type": "integer",
        "description": "Default log retention period in days",
        "domain": [
          365
        ],
        "source": "group_vars/all.yml"
      }
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "effect": "permit",
    "action": "ssh:login",
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
        "equals": "sshd"
      },
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        28,
        32
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "effect": "permit",
    "action": "ssh:login",
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
      },
      "service": {
        "equals": "sshd"
      },
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        33,
        37
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "effect": "permit",
    "action": "ssh:login",
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
      },
      "service": {
        "equals": "sshd"
      },
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        22,
        26
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "effect": "permit",
    "action": "db:login",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        17,
        22
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "effect": "permit",
    "action": "db:login",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        23,
        28
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "effect": "permit",
    "action": "network:connect",
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
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        20,
        26
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "effect": "permit",
    "action": "network:connect",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
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
    "rule_id": "rule-008",
    "effect": "permit",
    "action": "network:connect",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        29,
        32
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "effect": "permit",
    "action": "filesystem:read",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        11,
        16
      ]
    }
  },
  {
    "rule_id": "rule-0010",
    "effect": "permit",
    "action": "filesystem:write",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        11,
        16
      ]
    }
  },
  {
    "rule_id": "rule-0011",
    "effect": "permit",
    "action": "filesystem:execute",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        11,
        16
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "effect": "deny",
    "action": "*",
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
    "id": "rule-002",
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
    "id": "rule-003",
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
    "id": "rule-004",
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
  },
  {
    "id": "rule-005",
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
    "id": "rule-006",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "TLS renegotiation vulnerability in nginx allowing man-in-the-middle attacks",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.20.0 is not affected; ensure nginx remains >= 1.0.7. Monitor for regressions."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "Format string vulnerability in OpenBSD ssh allowing remote code execution",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.1p1 is not affected. No action required."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "Remote code execution via PKCS#11 provider in ssh-agent. Actively exploited (KEV).",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade openssh-server to >= 9.3p2 immediately. This KEV affects pinned version 9.1p1."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "Integer overflow in PostgreSQL 7.2.x handling invalid integer input",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.2 is not affected. No action required."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "Privilege escalation via extension scripts in PostgreSQL. Actively exploited (KEV).",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "VERIFY: Pinned version 16.2 may be the fixed release. Confirm exact patch level (16.2-x). Upgrade to latest 16.x if behind."
  }
]
```

## Report

# ABAC Policy Mining Report — Ansible Configuration

## Executive Summary

This report documents the ABAC policy mined from the SegCorp three-tier zone-segmented
Ansible deployment (DMZ → App → DB) under PCI compliance requirements. The configuration
defines 3 users, 3 hosts across 3 security zones, and 12 access control rules covering
SSH login, database access, network connectivity, filesystem permissions, and a default-deny baseline.

## Topology

| Host | IP | Zone | Role |
|------|------|------|------|
| proxy01.lab.local | 10.0.1.10 | dmz | reverse_proxy |
| app01.lab.local | 10.0.2.10 | app | application |
| db01.lab.local | 10.0.3.10 | data | primary |

## Subjects

| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

## Environment

- **Organization**: segcorp
- **Environment**: production
- **Compliance Tier**: pci
- **Log Retention**: 365 days

## Rules Summary

| ID | Effect | Action | Subject | Resource |
|----|--------|--------|---------|----------|
| rule-001 | permit | ssh:login | sudo group | DMZ zone (port 22) |
| rule-002 | permit | ssh:login | sudo, dba groups | Data zone (port 22) |
| rule-003 | permit | ssh:login | sudo, developers groups | App zone (port 22) |
| rule-004 | permit | db:login | dba group (SUPERUSER) | PostgreSQL (all DBs) |
| rule-005 | permit | db:login | developers group (NOSUPERUSER) | PostgreSQL (all DBs) |
| rule-006 | permit | network:connect | 0.0.0.0/0 (internet) | DMZ zone (port 443/tcp) |
| rule-007 | permit | network:connect | 10.0.1.0/24 (DMZ subnet) | App zone (port 8080/tcp) |
| rule-008 | permit | network:connect | 10.0.2.0/24 (app subnet) | Data zone (port 5432/tcp) |
| rule-009 | permit | filesystem:read | postgres group | /var/lib/postgresql/data (0700) |
| rule-010 | permit | filesystem:write | postgres group | /var/lib/postgresql/data (0700) |
| rule-011 | permit | filesystem:execute | postgres group | /var/lib/postgresql/data (0700) |
| rule-012 | deny | * | all subjects | all resources |

## Vulnerability Assessment

### Critical Findings

| CVE | Product | CVSS | KEV | Affects Pinned? | Recommendation |
|-----|---------|------|-----|-----------------|----------------|
| CVE-2023-38408 | openssh (9.1p1) | 9.8 | Yes | **YES** | Upgrade to >= 9.3p2 immediately |
| CVE-2024-1597 | postgresql (16.2) | 10.0 | Yes | **YES** | Verify patch level; upgrade to latest 16.x |
| CVE-2009-3555 | nginx (1.20.0) | 9.8 | Yes | No | Already mitigated by pinned version |
| CVE-2000-0999 | openssh (9.1p1) | 10.0 | No | No | Already mitigated by pinned version |
| CVE-2002-1399 | postgresql (16.2) | 10.0 | No | No | Already mitigated by pinned version |

## Ambiguities

- **Credentials**: No explicit credential management (vault, secrets) found in the Ansible configuration. Database passwords and SSH keys are not provisioned via Ansible tasks.
- **DB read privilege granularity**: Rule-005 grants developers `db:login` with `NOSUPERUSER`, but the specific schemas/databases accessible are not constrained beyond `database: all`. A more granular rule could restrict to specific schemas.
- **Filesystem postgres group**: The `postgres` Unix group is inferred from the file ownership task (`group: postgres`) but is not explicitly defined in the `users` list in `group_vars/all.yml`.
- **pg_hba implicit deny**: The `pg_hba.conf` lineinfile task adds `host all all 10.0.2.0/24 scram-sha-256` but does not include an explicit `host all all 0.0.0.0/0 reject` catch-all. PostgreSQL default-deny behavior is relied upon.
- **No session logging obligations**: The Ansible configuration does not include audit logging, sudo logging, or session recording tasks.

## Files Analyzed

- `inventory.ini` — Host inventory and environment variables
- `group_vars/all.yml` — Global vars, users, pinned versions
- `group_vars/appservers.yml` — App tier firewall and SSH config
- `group_vars/dbservers.yml` — DB tier firewall and DB config
- `group_vars/dmz.yml` — DMZ tier firewall and SSH config
- `roles/app/tasks/main.yml` — App server provisioning tasks
- `roles/db/tasks/main.yml` — Database server provisioning tasks
- `roles/dmz/tasks/main.yml` — DMZ server provisioning tasks
