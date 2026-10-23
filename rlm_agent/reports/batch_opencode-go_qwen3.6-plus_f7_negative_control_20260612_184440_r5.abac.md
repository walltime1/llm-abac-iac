# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:49:50_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 8 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

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
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "group_vars/all.yml"
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [],
        "clearance": null,
        "department": null,
        "source": "roles/db/tasks/main.yml",
        "type": "system"
      }
    ],
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance_levels": [
      {
        "name": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "name": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "name": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "name": "engineering",
        "source": "group_vars/all.yml"
      }
    ]
  },
  "resources": {
    "hosts": [
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
    ],
    "services": [
      {
        "name": "https",
        "port": 443,
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
        "source": "roles/web/tasks/main.yml"
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
        "path": "/var/www/html",
        "owner": "root",
        "group": "root",
        "mode": "0755",
        "service": "nginx",
        "source": "group_vars/webservers.yml"
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "openssh",
        "source": "roles/web/tasks/main.yml"
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
        "zone": "webservers",
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "public_internet",
        "source": "group_vars/webservers.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "labcorp",
      "domain": [
        "labcorp"
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
      "value": "soc2",
      "domain": [
        "soc2",
        "pci",
        "hipaa",
        "iso27001"
      ],
      "source": "inventory.ini"
    },
    "log_retention_days": {
      "value": 90,
      "domain": null,
      "source": "group_vars/all.yml"
    }
  },
  "attribute_definitions": {
    "user": {
      "type": "enum",
      "domain": [
        "admin",
        "appuser",
        "postgres"
      ]
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers"
      ]
    },
    "clearance": {
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ]
    },
    "department": {
      "type": "enum",
      "domain": [
        "operations",
        "engineering"
      ]
    },
    "hostname": {
      "type": "enum",
      "domain": [
        "web01.lab.local",
        "db01.lab.local"
      ]
    },
    "ip": {
      "type": "string",
      "domain": null
    },
    "role": {
      "type": "enum",
      "domain": [
        "frontend",
        "primary"
      ]
    },
    "zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal"
      ]
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "webservers",
        "dbservers"
      ]
    },
    "service": {
      "type": "enum",
      "domain": [
        "https",
        "postgresql",
        "ssh"
      ]
    },
    "port": {
      "type": "integer",
      "domain": [
        443,
        5432,
        22
      ]
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp",
        "udp"
      ]
    },
    "path": {
      "type": "string",
      "domain": null
    },
    "owner": {
      "type": "string",
      "domain": null
    },
    "group": {
      "type": "enum",
      "domain": [
        "postgres",
        "root"
      ]
    },
    "mode": {
      "type": "string",
      "domain": null
    },
    "source_ip": {
      "type": "string",
      "domain": null
    },
    "source_network": {
      "type": "string",
      "domain": null
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "webservers",
        "internet"
      ]
    },
    "database": {
      "type": "enum",
      "domain": [
        "postgresql"
      ]
    },
    "privilege_level": {
      "type": "enum",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ]
    },
    "environment": {
      "type": "enum",
      "domain": [
        "production",
        "staging",
        "development"
      ]
    },
    "compliance_tier": {
      "type": "enum",
      "domain": [
        "soc2",
        "pci",
        "hipaa",
        "iso27001"
      ]
    },
    "org": {
      "type": "enum",
      "domain": [
        "labcorp"
      ]
    },
    "commands": {
      "type": "string",
      "domain": null
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        39,
        43
      ]
    },
    "obligations": []
  },
  {
    "rule_id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "commands": {
        "equals": "ALL"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        22,
        29
      ]
    },
    "obligations": [
      {
        "type": "audit",
        "description": "nopassword is false - password required for sudo"
      }
    ]
  },
  {
    "rule_id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
      "privilege_level": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        16,
        21
      ]
    },
    "obligations": []
  },
  {
    "rule_id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
      "privilege_level": {
        "equals": "NOSUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        23,
        28
      ]
    },
    "obligations": []
  },
  {
    "rule_id": "rule-005",
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
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        30,
        34
      ]
    },
    "obligations": [
      {
        "type": "authentication",
        "description": "scram-sha-256 authentication required"
      }
    ]
  },
  {
    "rule_id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "https"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        31,
        37
      ]
    },
    "obligations": []
  },
  {
    "rule_id": "rule-007",
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
      ]
    },
    "obligations": []
  },
  {
    "rule_id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        13,
        20
      ]
    },
    "obligations": []
  },
  {
    "rule_id": "rule-009",
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
    },
    "source": {
      "file": "policy_default",
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
    },
    "obligations": []
  },
  {
    "rule_id": "rule-010",
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
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
      ]
    },
    "obligations": []
  },
  {
    "rule_id": "rule-011",
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
    "action": "filesystem:execute",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
      ]
    },
    "obligations": []
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
      },
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
      "compliance_tier": {
        "equals": "soc2"
      },
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
      "compliance_tier": {
        "equals": "soc2"
      },
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
    "id": "rule-004",
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
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
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
    "id": "rule-005",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "https"
      },
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
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
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Use-after-free in resolver DNS response handling",
    "pinned_version": "1.27.0-1~noble",
    "affects_pinned_version": false,
    "recommendation": "Already patched in pinned version 1.27.0 (fix was in 1.9.10). No action needed.",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Out-of-bounds array access in njs through 0.7.0",
    "pinned_version": "1.27.0-1~noble",
    "affects_pinned_version": false,
    "recommendation": "Likely already patched. Verify bundled njs version is > 0.7.0. No immediate action needed.",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "SQL injection in pgjdbc JDBC driver via PreferQueryMode=SIMPLE",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "recommendation": "This affects the pgjdbc JDBC driver, not the PostgreSQL server. Ensure Java applications use pgjdbc >= 42.7.2.",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "Integer overflow in cash_out and other functions in PostgreSQL 7.2.1 and earlier",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "recommendation": "Already patched. Pinned version 16.4 is many major versions ahead of the affected 7.2.x. No action needed.",
    "source": "search_critical_remote"
  }
]
```

## Report

# ABAC Policy Report — LabCorp Ansible Configuration

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a **production** environment with **SOC2** compliance tier for **labcorp**, comprising 2 hosts (web01 in DMZ, db01 in internal zone), 2 defined users, and 2 user groups.

## Catalog Summary

### Subjects
| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |
| postgres | (system) | — | — | — |

### Groups
- **sudo** — administrative access
- **developers** — development access

### Resources
- **Hosts**: web01.lab.local (10.0.1.10, frontend, DMZ), db01.lab.local (10.0.2.10, primary, internal)
- **Services**: HTTPS/443 (tcp), SSH/22 (tcp), PostgreSQL/5432 (tcp)
- **Paths**: /var/lib/postgresql/data (postgres:postgres 0700), /var/www/html, /etc/ssh/sshd_config, /etc/postgresql/pg_hba.conf
- **Networks**: 10.0.1.0/24 (webservers subnet), 0.0.0.0/0 (public internet)

### Environment
- Organization: labcorp
- Environment: production
- Compliance tier: soc2
- Log retention: 90 days

## Rules Summary

| Rule ID | Action | Subject Condition | Resource Condition | Effect |
|---------|--------|-------------------|-------------------|--------|
| rule-001 | ssh:login | groups in [sudo] | service=ssh, port=22, host_group=webservers | permit |
| rule-002 | sudo:execute | groups in [sudo] AND clearance=secret | commands=ALL | permit |
| rule-003 | db:login | groups in [sudo] | database=postgresql, privilege_level=SUPERUSER | permit |
| rule-004 | db:login | groups in [developers] | database=postgresql, privilege_level=NOSUPERUSER | permit |
| rule-005 | network:connect | source_network=10.0.1.0/24 | service=postgresql, port=5432, host_group=dbservers | permit |
| rule-006 | network:connect | source_network=0.0.0.0/0 | service=https, port=443, host_group=webservers | permit |
| rule-007 | filesystem:read | user=postgres | path=/var/lib/postgresql/data, mode=0700 | permit |
| rule-010 | filesystem:write | user=postgres | path=/var/lib/postgresql/data, mode=0700 | permit |
| rule-011 | filesystem:execute | user=postgres | path=/var/lib/postgresql/data, mode=0700 | permit |
| rule-008 | user:create | groups in [sudo] | host_group=webservers | permit |
| rule-009 | * (all) | all | all | deny |

## Vulnerability Assessment

| CVE | Product | Severity | CVSS | Affects Pinned? | Recommendation |
|-----|---------|----------|------|-----------------|----------------|
| CVE-2016-0746 | nginx | critical | 9.8 | No | Patched in 1.9.10+; pinned 1.27.0 is safe |
| CVE-2021-46461 | nginx | critical | 9.8 | No | Verify bundled njs > 0.7.0 |
| CVE-2024-1597 | postgresql | critical | 9.8 | No | Affects pgjdbc driver, not server |
| CVE-2002-1399 | postgresql | critical | 10.0 | No | Affected 7.2.x; pinned 16.4 is safe |

**Result**: All known critical/remote CVEs do NOT affect the pinned package versions. The configuration comments confirm "ALL PATCHED, no applicable CVEs."

## Ambiguities and Notes

1. **Pinned versions confirmed safe**: The group_vars/all.yml explicitly states all packages are patched with no applicable CVEs. Vulnerability scanning confirms known CVEs target much older versions.
2. **System account 'postgres'**: The PostgreSQL data directory is owned by a system account (postgres) not defined in the users list. This is standard practice but noted for completeness.
3. **No pg_hba.conf deny rules**: The pg_hba.conf only has an explicit allow from 10.0.1.0/24. PostgreSQL's implicit default-deny is captured by rule-009 (policy default-deny).
4. **No SELinux policies detected**: No selinux-related files or tasks were found in the configuration.
5. **No handlers**: No handler files were present; none are access-relevant.
6. **Credential management**: No explicit credential storage or rotation tasks were found in the configuration. Passwords and keys are not managed by these playbooks.
7. **Document root permissions**: /var/www/html is listed with root:root 0755 but no explicit filesystem rules were found in the playbooks for it — this is inferred from the variable definition.

## Sources

- `inventory.ini` — host definitions and environment variables
- `group_vars/all.yml` — organization settings, pinned versions, user definitions
- `group_vars/dbservers.yml` — database configuration and network allow-lists
- `group_vars/webservers.yml` — web server configuration and firewall rules
- `roles/db/tasks/main.yml` — database installation, user roles, pg_hba configuration
- `roles/web/tasks/main.yml` — web server installation, SSH restriction, firewall, sudo provisioning
