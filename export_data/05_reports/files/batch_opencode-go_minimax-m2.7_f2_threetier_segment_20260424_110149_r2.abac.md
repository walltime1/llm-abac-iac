# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 11:16:28_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 7 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f2_threetier_segmented`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "type": "string",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "domain": [
        1001,
        1002,
        1003
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "enum",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hostname": {
      "type": "string",
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "ip",
      "domain": [
        "10.0.1.10",
        "10.0.2.10",
        "10.0.3.10"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "type": "enum",
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "inventory_group": {
      "type": "enum",
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "string",
      "domain": [
        "nginx",
        "app",
        "postgresql"
      ],
      "source": "group_vars/dmz.yml, group_vars/appservers.yml, group_vars/dbservers.yml"
    },
    "port": {
      "type": "integer",
      "domain": [
        443,
        8080,
        5432
      ],
      "source": "group_vars/dmz.yml, group_vars/appservers.yml, group_vars/dbservers.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp"
      ],
      "source": "group_vars/*.yml"
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "dmz",
        "appservers",
        "dbservers"
      ],
      "source": "group_vars/*.yml"
    },
    "cidr": {
      "type": "network",
      "domain": null,
      "source": "group_vars/*.yml"
    },
    "source_ip": {
      "type": "ip",
      "domain": null,
      "source": "roles/*/tasks/main.yml"
    },
    "source_network": {
      "type": "network",
      "domain": null,
      "source": "roles/*/tasks/main.yml"
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data",
        "any"
      ],
      "source": "group_vars/*.yml"
    },
    "database": {
      "type": "string",
      "domain": [
        "postgresql"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "path": {
      "type": "string",
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "owner": {
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "group": {
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "mode": {
      "type": "string",
      "domain": [
        "0700"
      ],
      "source": "group_vars/dbservers.yml"
    }
  },
  "environment": {
    "org": {
      "type": "string",
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "enum",
      "domain": [
        "pci"
      ],
      "source": "inventory.ini, group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "integer",
      "domain": [
        365
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
    "description": "SSH login to DMZ reverse proxy hosts restricted to sudo group members",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dmz"
      },
      "role": {
        "equals": "reverse_proxy"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        12,
        16
      ]
    }
  },
  {
    "id": "rule-002",
    "description": "SSH login to application hosts allowed for sudo and developers groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      },
      "role": {
        "equals": "application"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        11,
        15
      ]
    }
  },
  {
    "id": "rule-003",
    "description": "SSH login to database hosts restricted to sudo and dba groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "role": {
        "equals": "primary"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        26,
        28
      ]
    }
  },
  {
    "id": "rule-004",
    "description": "HTTPS traffic from any source allowed to DMZ reverse proxy",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dmz"
      },
      "zone": {
        "equals": "dmz"
      },
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "id": "rule-005",
    "description": "Application port 8080 accessible only from DMZ subnet (10.0.1.0/24)",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      },
      "zone": {
        "equals": "app"
      },
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        7,
        11
      ]
    }
  },
  {
    "id": "rule-006",
    "description": "PostgreSQL accessible from app tier subnet (10.0.2.0/24)",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        22,
        25
      ]
    }
  },
  {
    "id": "rule-007",
    "description": "DBA group members get PostgreSQL SUPERUSER privileges",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "database": {
        "equals": "postgresql"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "attribute",
        "name": "role_attr_flags",
        "value": "SUPERUSER"
      }
    ],
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        12,
        15
      ]
    }
  },
  {
    "id": "rule-008",
    "description": "Developers get PostgreSQL NOSUPERUSER (read-only) privileges",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "database": {
        "equals": "postgresql"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "attribute",
        "name": "role_attr_flags",
        "value": "NOSUPERUSER"
      }
    ],
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        17,
        20
      ]
    }
  },
  {
    "id": "rule-009",
    "description": "PostgreSQL data directory owned by postgres user with mode 0700",
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
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
    "id": "rule-010",
    "description": "Users with sudo group membership can be provisioned on DMZ hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dmz"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        3,
        8
      ]
    }
  },
  {
    "id": "rule-011",
    "description": "Users with developers or sudo group membership can be provisioned on app hosts",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        4,
        9
      ]
    }
  },
  {
    "id": "rule-012",
    "description": "Default deny all unspecified access",
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
      "applies_to": {
        "equals": "all"
      }
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
    "id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {
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
    "id": "rule-015",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {
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
    "id": "rule-016",
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "Use-after-free in resolver during CNAME processing",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 1.20.0 is not affected.",
    "kev": true
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cvss_score": 8.1,
    "severity": "high",
    "description": "regreSSHion - race condition in sshd allowing RCE as root",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade openssh-server to 9.8p1 or later to patch regreSSHion RCE vulnerability.",
    "kev": true
  },
  {
    "cve_id": "CVE-2024-6384",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cvss_score": 9.0,
    "severity": "critical",
    "description": "Signal handler race condition in sshd",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade openssh-server to 9.8p1 or later.",
    "kev": true
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "SQL injection in pgjdbc driver (PreferQueryMode=SIMPLE)",
    "affects_pinned_version": false,
    "recommendation": "Verify that application JDBC drivers are updated to 42.7.2+ if using PreferQueryMode=SIMPLE.",
    "kev": true
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

Policy mined from Ansible configuration at `RLM_ANSIBLE_DIR` (three-tier segmented architecture).

**Organization:** segcorp  
**Environment:** production  
**Compliance Tier:** PCI DSS  

## Phase 1 — Attribute Catalog

### Subjects (3 users, 3 groups)

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| user | string | admin, developer, dba | group_vars/all.yml |
| uid | integer | 1001, 1002, 1003 | group_vars/all.yml |
| groups | set | sudo, developers, dba | group_vars/all.yml |
| clearance | enum | secret, confidential | group_vars/all.yml |
| department | enum | operations, engineering, data | group_vars/all.yml |

### Resources (3 hosts, 3 services, 4 networks)

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| hostname | string | proxy01, app01, db01 | inventory.ini |
| ip | ip | 10.0.1.10, 10.0.2.10, 10.0.3.10 | inventory.ini |
| role | enum | reverse_proxy, application, primary | inventory.ini |
| zone | enum | dmz, app, data | inventory.ini |
| inventory_group | enum | dmz, appservers, dbservers, prod | inventory.ini |
| service | string | nginx, app, postgresql | group_vars/*.yml |
| port | integer | 443, 8080, 5432 | group_vars/*.yml |
| source_network | network | 10.0.1.0/24, 10.0.2.0/24, 0.0.0.0/0 | roles/*/tasks/main.yml |

### Environment

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| org | string | segcorp | group_vars/all.yml |
| environment | enum | production | inventory.ini |
| compliance_tier | enum | pci | inventory.ini, group_vars/all.yml |
| default_log_retention_days | integer | 365 | group_vars/all.yml |

## Phase 1.5 — Vulnerability Assessment

### Pinned Software Versions
- **nginx:** 1.20.0-1~focal
- **openssh-server:** 1:9.6p1-3ubuntu1
- **postgresql-13:** 13.7-1.pgdg20.04+1

### CVE Analysis

| CVE | Product | CVSS | Severity | Affects Pinned? | Recommendation |
|-----|---------|------|----------|-----------------|----------------|
| CVE-2016-0746 | nginx | 9.8 | critical | **NO** (fixed in 1.9.10) | No action required |
| CVE-2024-6387 | openssh | 8.1 | high | **YES** (<9.8p1) | URGENT: Upgrade to 9.8p1+ |
| CVE-2024-6384 | openssh | 9.0 | critical | **YES** (<9.8p1) | URGENT: Upgrade to 9.8p1+ |
| CVE-2024-1597 | postgresql | 9.8 | critical | **NO** (pgjdbc driver issue) | Verify JDBC driver versions |

### Summary
- **Critical CVEs affecting pinned versions:** 2 (openssh)
- **High priority:** Upgrade openssh-server immediately (regreSSHion RCE)

## Phase 1.6 — Security Scope

Security-relevant files identified:
- `roles/dmz/tasks/main.yml` — firewall, SSH restrictions, user provisioning
- `roles/app/tasks/main.yml` — firewall, SSH restrictions, user provisioning
- `roles/db/tasks/main.yml` — pg_hba, PostgreSQL users, SSH restrictions, filesystem ACLs

## Phase 2 — Rules Extracted (12 rules)

| Rule ID | Action | Subject | Resource | Effect | Source |
|---------|--------|---------|----------|--------|--------|
| rule-001 | ssh:login | groups:sudo | dmz hosts | permit | roles/dmz/tasks/main.yml:12-16 |
| rule-002 | ssh:login | groups:sudo,developers | app hosts | permit | roles/app/tasks/main.yml:11-15 |
| rule-003 | ssh:login | groups:sudo,dba | db hosts | permit | roles/db/tasks/main.yml:26-28 |
| rule-004 | network:connect | any (0.0.0.0/0) | dmz:443 | permit | roles/dmz/tasks/main.yml:8-12 |
| rule-005 | network:connect | dmz (10.0.1.0/24) | app:8080 | permit | roles/app/tasks/main.yml:7-11 |
| rule-006 | network:connect | app (10.0.2.0/24) | db:5432 | permit | roles/db/tasks/main.yml:22-25 |
| rule-007 | db:login | groups:dba | postgresql | permit | roles/db/tasks/main.yml:12-15 |
| rule-008 | db:login | groups:developers | postgresql | permit | roles/db/tasks/main.yml:17-20 |
| rule-009 | filesystem:write | user:postgres | /var/lib/postgresql/data | permit | roles/db/tasks/main.yml:7-12 |
| rule-010 | user:create | groups:sudo | dmz hosts | permit | roles/dmz/tasks/main.yml:3-8 |
| rule-011 | user:create | groups:developers,sudo | app hosts | permit | roles/app/tasks/main.yml:4-9 |
| rule-012 | * | all | all | **deny** | Default |

## Phase 3 — Normalization

All attribute names referenced in rules exist in the Phase 1 catalog.

## Ambiguities

1. **Database credentials:** The Ansible configuration creates PostgreSQL users but does not define initial passwords. Password provisioning is not captured in the rules — credential management should be reviewed separately.

2. **JDBC driver version:** PostgreSQL 13.7 server is configured but pgjdbc driver version is not specified in the Ansible inventory. CVE-2024-1597 affects the driver, not the server.

3. **pg_hba implicit deny:** The `lineinfile` module adds entries to pg_hba.conf. Default PostgreSQL behavior is `md5` authentication. The configuration explicitly sets `scram-sha-256` for permitted networks but does not explicitly deny other networks — this relies on PostgreSQL's implicit deny behavior.

4. **SSH configuration scope:** SSH AllowGroups is configured per-role but does not explicitly restrict to key-based authentication only. PAM/two-factor configuration is not defined in these files.

## Recommendations

1. **Immediate:** Patch openssh-server to 9.8p1+ (2 CVEs with CVSS 8.1-9.0 affect current version)
2. **Review:** Verify all application hosts using PostgreSQL have pgjdbc 42.7.2+ if using PreferQueryMode=SIMPLE
3. **Audit:** Confirm password-based SSH is disabled on all production hosts
4. **Document:** Create separate credential management policy for database passwords
