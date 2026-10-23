# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 11:10:58_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 10 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f2_threetier_segmented`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "domain": null,
      "source": "group_vars/all.yml",
      "values": [
        {
          "name": "admin",
          "uid": 1001,
          "groups": [
            "sudo"
          ],
          "clearance": "secret",
          "department": "operations"
        },
        {
          "name": "developer",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "clearance": "confidential",
          "department": "engineering"
        },
        {
          "name": "dba",
          "uid": 1003,
          "groups": [
            "dba"
          ],
          "clearance": "secret",
          "department": "data"
        }
      ]
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "sudo",
        "developers",
        "dba"
      ]
    },
    "clearance_levels": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "secret",
        "confidential"
      ]
    },
    "departments": {
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "operations",
        "engineering",
        "data"
      ]
    }
  },
  "resources": {
    "hosts": {
      "domain": null,
      "source": "inventory.ini",
      "values": [
        {
          "hostname": "proxy01.lab.local",
          "ip": "10.0.1.10",
          "role": "reverse_proxy",
          "zone": "dmz",
          "inventory_group": "dmz"
        },
        {
          "hostname": "app01.lab.local",
          "ip": "10.0.2.10",
          "role": "application",
          "zone": "app",
          "inventory_group": "appservers"
        },
        {
          "hostname": "db01.lab.local",
          "ip": "10.0.3.10",
          "role": "primary",
          "zone": "data",
          "inventory_group": "dbservers"
        }
      ]
    },
    "services": {
      "domain": null,
      "source": "group_vars/*.yml",
      "values": [
        {
          "name": "nginx",
          "port": 443,
          "protocol": "tcp",
          "host_group": "dmz"
        },
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "all"
        },
        {
          "name": "postgresql",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers"
        }
      ]
    },
    "paths": {
      "domain": null,
      "source": "roles/db/tasks/main.yml",
      "values": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700"
        }
      ]
    },
    "networks": {
      "domain": null,
      "source": "inventory.ini + group_vars/*.yml",
      "values": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "dmz"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "app",
          "label": "appservers"
        },
        {
          "cidr": "10.0.3.0/24",
          "zone": "data",
          "label": "dbservers"
        }
      ]
    }
  },
  "environment": {
    "org": {
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "segcorp"
      ]
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini",
      "values": [
        "production"
      ]
    },
    "compliance_tier": {
      "domain": [
        "pci"
      ],
      "source": "inventory.ini + group_vars/all.yml",
      "values": [
        "pci"
      ]
    },
    "retention_days": {
      "domain": null,
      "source": "group_vars/all.yml",
      "values": [
        365
      ]
    }
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "name": "SSH to DMZ hosts",
    "description": "Allow sudo group SSH access to DMZ reverse-proxy hosts",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "role": {
        "equals": "reverse_proxy"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
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
    "id": "rule-002",
    "name": "SSH to app hosts",
    "description": "Allow sudo and developers groups SSH access to application hosts",
    "effect": "permit",
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
      "role": {
        "equals": "application"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        17,
        20
      ]
    }
  },
  {
    "id": "rule-003",
    "name": "SSH to DB hosts",
    "description": "Allow sudo and dba groups SSH access to database hosts",
    "effect": "permit",
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
      "role": {
        "equals": "primary"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        27,
        30
      ]
    }
  },
  {
    "id": "rule-004",
    "name": "HTTPS from internet to DMZ",
    "description": "Allow HTTPS traffic from any source to DMZ reverse-proxy",
    "effect": "permit",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "role": {
        "equals": "reverse_proxy"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        12,
        16
      ]
    }
  },
  {
    "id": "rule-005",
    "name": "App port from DMZ to appservers",
    "description": "Allow application port traffic from DMZ subnet to appservers",
    "effect": "permit",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "host_group": {
        "equals": "appservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        12,
        16
      ]
    }
  },
  {
    "id": "rule-006",
    "name": "DBA superuser access to PostgreSQL",
    "description": "Allow DBA group members superuser access to PostgreSQL",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
    "action": "db:login",
    "obligations": [
      {
        "type": "privilege_level",
        "value": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        13,
        16
      ]
    }
  },
  {
    "id": "rule-007",
    "name": "Developer read-only access to PostgreSQL",
    "description": "Allow developers read-only (non-superuser) access to PostgreSQL",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "developers"
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
    "action": "db:login",
    "obligations": [
      {
        "type": "privilege_level",
        "value": "NOSUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        18,
        21
      ]
    }
  },
  {
    "id": "rule-008",
    "name": "PostgreSQL network access from appservers",
    "description": "Allow PostgreSQL connections from appservers subnet (10.0.2.0/24)",
    "effect": "permit",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        23,
        27
      ]
    }
  },
  {
    "id": "rule-009",
    "name": "PostgreSQL default-deny network access",
    "description": "Default-deny for PostgreSQL network connections not from appservers",
    "effect": "deny",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "pg_hba implicit deny",
      "lines": [
        23,
        27
      ]
    }
  },
  {
    "id": "rule-010",
    "name": "Postgres data directory ownership",
    "description": "PostgreSQL data directory owned by postgres user with restricted permissions",
    "effect": "permit",
    "subject_condition": {
      "user": {
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:read",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "id": "rule-011",
    "name": "Postgres data directory write access",
    "description": "PostgreSQL data directory write access restricted to postgres user",
    "effect": "permit",
    "subject_condition": {
      "user": {
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:write",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "id": "rule-012",
    "name": "Admin user provisioning on DMZ",
    "description": "Provision admin users (sudo group) on DMZ hosts",
    "effect": "permit",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        8,
        14
      ]
    }
  },
  {
    "id": "rule-013",
    "name": "Developer and admin user provisioning on app hosts",
    "description": "Provision developers and sudo users on app hosts",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        8,
        14
      ]
    }
  },
  {
    "id": "rule-014",
    "name": "Default deny all access",
    "description": "Default deny for any access not explicitly permitted above",
    "effect": "deny",
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
    "source": {
      "file": "inventory.ini",
      "task": "implicit default-deny",
      "lines": [
        1,
        100
      ]
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
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {},
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
    "id": "rule-018",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
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
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing HTTP requests",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Already remediated. Pinned version 1.20.0 is not affected."
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "description": "nginx use-after-free in resolver",
    "cvss_score": 8.1,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Already remediated. Pinned version 1.20.0 is not affected."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "medium",
    "description": "NGINX njs out-of-bounds array access",
    "cvss_score": 6.5,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Monitor if njs module is added. Current nginx version not affected."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "13.7",
    "severity": "critical",
    "description": "PostgreSQL plpgsql language grants privileges improperly",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Already remediated. Pinned version 13.7 is not affected."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "13.7",
    "severity": "high",
    "description": "PostgreSQL arbitrary code execution via SQL injection",
    "cvss_score": 8.8,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Already remediated. Pinned version 13.7 is not affected."
  }
]
```

## Report

# ABAC Policy Report — SegCorp Three-Tier Infrastructure

## Executive Summary

This policy governs access control for a PCI-compliant, three-tier segmented infrastructure (DMZ → App → Data) at SegCorp. The policy was mined from Ansible configuration in `eval_fixtures/f2_threetier_segmented`.

---

## Phase 1 — Attribute Catalog

### Subjects

| Attribute | Domain | Source |
|----------|--------|--------|
| `user` (name) | admin, developer, dba | group_vars/all.yml |
| `groups` | sudo, developers, dba | group_vars/all.yml |
| `clearance` | secret, confidential | group_vars/all.yml |
| `department` | operations, engineering, data | group_vars/all.yml |

### Resources

| Attribute | Domain | Source |
|----------|--------|--------|
| `hostname` | proxy01.lab.local, app01.lab.local, db01.lab.local | inventory.ini |
| `zone` | dmz, app, data | inventory.ini |
| `role` | reverse_proxy, application, primary | inventory.ini |
| `service` | nginx, ssh, postgresql | group_vars/*.yml |
| `port` | 22, 443, 5432, 8080 | group_vars/*.yml |
| `path` | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| `owner` | postgres | roles/db/tasks/main.yml |
| `group` | postgres | roles/db/tasks/main.yml |
| `mode` | 0700 | roles/db/tasks/main.yml |
| `source_network` | 0.0.0.0/0, 10.0.1.0/24, 10.0.2.0/24 | group_vars/*.yml |

### Environment

| Attribute | Value | Source |
|----------|-------|--------|
| `org` | segcorp | group_vars/all.yml |
| `environment` | production | inventory.ini |
| `compliance_tier` | pci | inventory.ini + group_vars/all.yml |
| `retention_days` | 365 | group_vars/all.yml |

---

## Phase 1.5 — Vulnerability Assessment

### Pinned Software Versions

| Product | Version | Source |
|---------|---------|--------|
| nginx | 1.20.0-1~focal | group_vars/all.yml |
| openssh-server | 1:9.6p1-3ubuntu1 | group_vars/all.yml |
| postgresql | 13.7-1.pgdg20.04+1 | group_vars/all.yml |

### Findings

| CVE ID | Product | Severity | CVSS | Affects Pinned | Recommendation |
|--------|---------|----------|------|----------------|----------------|
| CVE-2017-20005 | nginx | critical | 9.8 | false (1.20.0 > 1.13.6) | Already remediated |
| CVE-2016-0746 | nginx | high | 8.1 | false (1.20.0 > 1.9.10) | Already remediated |
| CVE-2021-46461 | nginx | medium | 6.5 | false (njs not used) | Monitor if njs added |
| CVE-2007-3279 | postgresql | critical | 9.8 | false (13.7 > 8.1) | Already remediated |
| CVE-2013-1903 | postgresql | high | 8.8 | false (13.7 > 9.2.4) | Already remediated |

**Assessment**: No active vulnerabilities affect the pinned versions. All known critical CVEs have been remediated by version upgrades.

---

## Phase 2 — ABAC Rules Summary

| Rule ID | Name | Action | Subjects | Resources | Effect |
|---------|------|--------|----------|-----------|--------|
| rule-001 | SSH to DMZ hosts | ssh:login | sudo | dmz/reverse_proxy | permit |
| rule-002 | SSH to app hosts | ssh:login | sudo, developers | app/application | permit |
| rule-003 | SSH to DB hosts | ssh:login | sudo, dba | data/primary | permit |
| rule-004 | HTTPS from internet to DMZ | network:connect | 0.0.0.0/0 | dmz:443 | permit |
| rule-005 | App port from DMZ to appservers | network:connect | 10.0.1.0/24 | app:8080 | permit |
| rule-006 | DBA superuser access to PostgreSQL | db:login | dba | postgresql:5432 | permit |
| rule-007 | Developer read-only access to PostgreSQL | db:login | developers | postgresql:5432 | permit |
| rule-008 | PostgreSQL network access from appservers | network:connect | 10.0.2.0/24 | postgresql:5432 | permit |
| rule-009 | PostgreSQL default-deny network access | network:connect | * | postgresql:5432 | deny |
| rule-010 | Postgres data directory read | filesystem:read | postgres | /var/lib/postgresql/data | permit |
| rule-011 | Postgres data directory write | filesystem:write | postgres | /var/lib/postgresql/data | permit |
| rule-012 | Admin user provisioning on DMZ | user:create | sudo | dmz hosts | permit |
| rule-013 | Developer/admin provisioning on app hosts | user:create | developers, sudo | app hosts | permit |
| rule-014 | Default deny all access | * | * | * | deny |

**Total Rules**: 14 (12 permit, 2 deny)

---

## Phase 3 — Key Findings

### Zone-Based Segmentation
- **DMZ** (10.0.1.0/24): Reverse proxy with nginx, accessible from internet on HTTPS
- **App** (10.0.2.0/24): Application servers, accessible only from DMZ subnet
- **Data** (10.0.3.0/24): PostgreSQL database, accessible only from appservers subnet

### Privilege Separation
- **DBAs**: Full SUPERUSER access to PostgreSQL for administration
- **Developers**: NOSUPERUSER read-only access to PostgreSQL
- **sudo group**: SSH access to all tiers for operations

### Security Controls
- Firewall rules enforce zone-based network segmentation
- pg_hba.conf restricts database connections to appservers subnet only
- Filesystem permissions (0700) restrict PostgreSQL data directory to postgres user only

---

## Ambiguities

1. **Credentials**: No database passwords or SSH keys are defined in the Ansible configuration. Credential management must be reviewed separately.
2. **Session Logging**: No explicit audit/logging configuration found. Consider adding session logging obligations.
3. **Sudo Password**: The Ansible config does not specify `requiretty` or `!requiretty` for sudoers. Sudo password requirement is ambiguous.
4. **Nginx TLS**: TLS version and cipher configuration not specified in nginx tasks.
5. **Backup Policy**: No backup or disaster recovery configuration found.

---

## Security Posture

| Control | Status |
|---------|--------|
| Zone segmentation | ✓ Implemented |
| SSH group restrictions | ✓ Implemented |
| Database least privilege | ✓ Implemented |
| Firewall rules | ✓ Implemented |
| Filesystem permissions | ✓ Implemented |
| Software patching | ✓ Current versions |
| Default deny | ✓ Implemented |

---

*Policy mined from: eval_fixtures/f2_threetier_segmented*
*Generated by: ABAC Policy Miner v1.0*
