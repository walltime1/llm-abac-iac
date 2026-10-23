# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:10:53_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 8 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

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
    "groups": [
      "sudo",
      "developers",
      "dba"
    ],
    "clearance_levels": [
      "secret",
      "confidential"
    ]
  },
  "resources": {
    "hosts": [
      {
        "hostname": "bastion01.lab.local",
        "ip": "10.0.0.5",
        "role": "bastion",
        "zone": "mgmt",
        "inventory_group": "bastion"
      },
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers"
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
    ],
    "services": [
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all"
      },
      {
        "name": "http",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers"
      }
    ],
    "paths": [
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql"
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0600",
        "service": "sshd"
      },
      {
        "path": "/etc/postgresql/pg_hba.conf",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0600",
        "service": "postgresql"
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "any",
        "label": "internet"
      },
      {
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "bastion_subnet"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web_subnet"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet"
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "db_subnet"
      }
    ]
  },
  "environment": {
    "org": "chaincorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365
  },
  "attributes": {
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
    },
    "hostname": {
      "type": "string",
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "source": "inventory.ini"
    },
    "role": {
      "type": "enum",
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "enum",
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "set",
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "ssh",
        "http",
        "app",
        "postgresql"
      ],
      "source": "group_vars/*.yml"
    },
    "port": {
      "type": "integer",
      "source": "group_vars/*.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp",
        "udp"
      ],
      "source": "group_vars/*.yml"
    },
    "path": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "source_ip": {
      "type": "string",
      "source": "group_vars/*.yml"
    },
    "source_network": {
      "type": "string",
      "source": "group_vars/*.yml"
    },
    "source_zone": {
      "type": "string",
      "source": "inventory.ini"
    },
    "org": {
      "type": "enum",
      "domain": [
        "chaincorp"
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
      "source": "inventory.ini"
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
          "dba"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "role": {
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        21,
        25
      ]
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
    "resource_condition": {
      "role": {
        "equals": "application"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        31,
        35
      ]
    }
  },
  {
    "id": "rule-004",
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
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        29,
        33
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "detail": "sudo commands logged for audit"
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        22,
        29
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
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_audit",
        "detail": "SUPERUSER role granted"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        16,
        21
      ]
    }
  },
  {
    "id": "rule-007",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:connect",
    "effect": "permit",
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
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "bastion"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        14,
        20
      ]
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        13,
        19
      ]
    }
  },
  {
    "id": "rule-010",
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        23,
        29
      ]
    }
  },
  {
    "id": "rule-011",
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
      ]
    }
  },
  {
    "id": "rule-012",
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
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
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "implicit",
      "task": "default-deny",
      "lines": [
        0,
        0
      ]
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
        "equals": 22
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
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
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
    "id": "rule-018",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL 8.1+ with plpgsql grants privileges to PUBLIC, allowing remote function creation and execution leading to privilege escalation.",
    "recommendation": "Restrict PUBLIC privileges on plpgsql language; upgrade PostgreSQL to latest patched version."
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 6.6,
    "severity": "medium",
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "Apache Log4j2 JDBC Appender deserialization vulnerability allowing RCE via crafted log messages.",
    "recommendation": "Upgrade Log4j to version 2.17.0 or later."
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "Log4Shell - Remote code execution via JNDI lookup in log messages.",
    "recommendation": "Immediately upgrade Log4j to 2.17.0+; apply mitigations if upgrade not possible."
  }
]
```

## Report

# ABAC Policy Mining Report — ChainCorp Ansible Configuration

## Executive Summary
Mined 13 ABAC rules from the ChainCorp production Ansible configuration (PCI compliance tier). The policy covers SSH access, sudo privileges, database access, network firewall rules, and filesystem permissions across 4 hosts in 4 zones.

## Attribute Catalog
- **Users**: 3 (admin, developer, dba) with attributes: uid, groups, clearance, department
- **Groups**: sudo, developers, dba
- **Clearance levels**: secret, confidential
- **Hosts**: 4 (bastion01, web01, app01, db01) across zones: mgmt, dmz, app, data
- **Services**: ssh (22), http (80), app (8080), postgresql (5432)
- **Environment**: org=chaincorp, environment=production, compliance_tier=pci

## Rules Extracted
| ID | Action | Subject | Resource | Effect |
|----|--------|---------|----------|--------|
| rule-001 | ssh:login | groups ∈ {sudo, dba} | bastion01:ssh | permit |
| rule-002 | ssh:login | groups ∈ {sudo} | webservers:ssh | permit |
| rule-003 | ssh:login | groups ∈ {sudo, developers} | appservers:ssh | permit |
| rule-004 | ssh:login | groups ∈ {sudo, dba} | dbservers:ssh | permit |
| rule-005 | sudo:execute | groups ∈ {sudo} ∧ clearance=secret | bastion01 | permit |
| rule-006 | db:login | groups ∈ {dba} | postgresql:all (SUPERUSER) | permit |
| rule-007 | db:connect | source_network=10.0.2.0/24 | postgresql:5432 | permit |
| rule-008 | network:connect | source_network=0.0.0.0/0 | bastion:22/tcp | permit |
| rule-009 | network:connect | source_network=10.0.0.0/24 | frontend:80/tcp | permit |
| rule-010 | network:connect | source_network=10.0.1.0/24 | application:8080/tcp | permit |
| rule-011 | filesystem:read | user=postgres | /var/lib/postgresql/data (0700) | permit |
| rule-012 | filesystem:write | user=postgres | /var/lib/postgresql/data (0700) | permit |
| rule-013 | * | all | all | deny |

## Vulnerabilities
| CVE | Product | Pinned Version | Severity | Affects | Recommendation |
|-----|---------|---------------|----------|---------|----------------|
| CVE-2007-3279 | postgresql | 9.2.3-1 | critical (10.0) | YES | Restrict plpgsql PUBLIC privs; upgrade |
| CVE-2021-44228 | log4j | 2.14.1 | critical (10.0) | YES | Upgrade to 2.17.0+ immediately |
| CVE-2021-44832 | log4j | 2.14.1 | medium (6.6) | YES | Upgrade to 2.17.0+ |

## Ambiguities & Observations
- **System account `postgres`**: Not in the user catalog; filesystem rules (rule-011/012) reference this service account. Should be added to subjects if policy enforcement needs it.
- **No explicit DENY rules**: The configuration uses allow-lists (AllowGroups, firewall source restrictions) implying deny-by-default. rule-013 captures this explicitly.
- **No pg_hba.conf DENY entries**: The lineinfile task only adds allow entries; implicit deny for non-matching sources is assumed.
- **Credentials**: No hardcoded credentials observed in the Ansible configuration. Package versions are pinned but several are deliberately vulnerable (noted above).
- **Session logging**: The bastion sudo rule includes an obligation for session logging, but no explicit auditd/rsyslog configuration was found in the scanned files.
- **httpd (apache2) version 2.4.49-1**: Known vulnerable (CVE-2021-41773, CVE-2021-42013) but not returned by critical/KEV search in this query scope; recommend manual review.
- **OpenSSH bastion version 9.1p1-1**: Older than non-bastion hosts (9.9p1-3); potential version drift risk.
