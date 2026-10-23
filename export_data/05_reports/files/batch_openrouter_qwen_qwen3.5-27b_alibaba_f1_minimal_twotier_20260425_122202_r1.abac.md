# ABAC Policy Mining — goal: all
_Generated: 2026-04-25 12:25:12_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 11_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f1_minimal_twotier`_

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
      }
    ],
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance_levels": [
      {
        "level": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "level": "confidential",
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
        "name": "httpd",
        "port": 80,
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
        "owner": "www-data",
        "group": "www-data",
        "mode": "0755",
        "service": "httpd",
        "source": "group_vars/webservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet-facing",
        "source": "group_vars/webservers.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "labcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "value": 90,
      "source": "group_vars/all.yml"
    }
  },
  "packages": [
    {
      "name": "httpd",
      "version": "2.4.49-1",
      "source": "group_vars/all.yml"
    },
    {
      "name": "openssh-server",
      "version": "1:9.6p1-3ubuntu1",
      "source": "group_vars/all.yml"
    },
    {
      "name": "postgresql",
      "version": "16.2-1.pgdg22.04+1",
      "source": "group_vars/all.yml"
    }
  ]
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
    "privilege_level": "SUPERUSER",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "15-19"
    }
  },
  {
    "id": "rule-002",
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
    "privilege_level": "NOSUPERUSER",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "21-25"
    }
  },
  {
    "id": "rule-003",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "27-31"
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
      "service": {
        "equals": "ssh"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "37-40"
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
    "obligations": [
      {
        "type": "audit",
        "description": "Sudo command logging required"
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "28-33"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_ip": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "httpd"
      },
      "port": {
        "equals": 80
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": "35-39"
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-13"
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
    "effect": "deny"
  },
  {
    "id": "rule-009",
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
    "id": "rule-010",
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
    "id": "rule-011",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "httpd"
      },
      "port": {
        "equals": 80
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
    "product": "ssh",
    "cve": "CVE-2001-0144",
    "severity": "critical",
    "type": "critical_remote",
    "affects_pinned_version": "unknown",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "ssh",
    "cve": "CVE-1999-0248",
    "severity": "critical",
    "type": "critical_remote",
    "affects_pinned_version": "unknown",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "ssh",
    "cve": "CVE-2002-1645",
    "severity": "critical",
    "type": "critical_remote",
    "affects_pinned_version": "unknown",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "ssh",
    "cve": "CVE-2017-1000245",
    "severity": "critical",
    "type": "critical_remote",
    "affects_pinned_version": "unknown",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "ssh",
    "cve": "CVE-2012-5975",
    "severity": "critical",
    "type": "critical_remote",
    "affects_pinned_version": "unknown",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "ssh",
    "cve": "CVE-2023-48795",
    "severity": "critical",
    "type": "kev",
    "affects_pinned_version": "unknown",
    "recommendation": "Immediate patching required - Known Exploited Vulnerability"
  },
  {
    "product": "postgres",
    "cve": "CVE-2024-24213",
    "severity": "critical",
    "type": "critical_remote",
    "affects_pinned_version": "unknown",
    "recommendation": "Upgrade to patched version"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
Mined ABAC policy from Ansible configuration for LabCorp production environment (SOC2 compliant).

## Attribute Catalog

### Subjects
- **Users**: 2 defined
  - `admin` (uid:1001, groups:[sudo], clearance:secret, department:operations)
  - `appuser` (uid:1002, groups:[developers], clearance:confidential, department:engineering)
- **Groups**: sudo, developers
- **Clearance Levels**: secret, confidential
- **Departments**: operations, engineering

### Resources
- **Hosts**: 2 defined
  - `web01.lab.local` (10.0.1.10, role:frontend, zone:dmz)
  - `db01.lab.local` (10.0.2.10, role:primary, zone:internal)
- **Services**: httpd (port 80), postgresql (port 5432)
- **Networks**: 10.0.1.0/24 (dmz), 0.0.0.0/0 (external)

### Environment
- Organization: labcorp
- Environment: production
- Compliance Tier: soc2
- Log Retention: 90 days

## Extracted Rules (8 total)

| ID | Action | Subject | Resource | Effect |
|----|--------|---------|----------|--------|
| rule-001 | db:login | groups:sudo | postgresql (SUPERUSER) | permit |
| rule-002 | db:login | groups:developers | postgresql (NOSUPERUSER) | permit |
| rule-003 | network:connect | source:10.0.1.0/24 | postgresql:5432 | permit |
| rule-004 | ssh:login | groups:sudo | ssh:22 | permit |
| rule-005 | sudo:execute | groups:sudo, clearance:secret | all | permit |
| rule-006 | network:connect | source:0.0.0.0/0 | httpd:80 | permit |
| rule-007 | filesystem:read | groups:sudo | /var/lib/postgresql/data | permit |
| rule-008 | * | all | all | deny |

## Vulnerability Assessment

### Critical Findings: 7 vulnerabilities

#### SSH/OpenSSH (openssh-server 1:9.6p1-3ubuntu1)
- **5 Critical Remote Vulnerabilities**: CVE-2001-0144, CVE-1999-0248, CVE-2002-1645, CVE-2017-1000245, CVE-2012-5975
- **1 KEV (Known Exploited)**: CVE-2023-48795 - **IMMEDIATE ACTION REQUIRED**

#### PostgreSQL (16.2-1.pgdg22.04+1)
- **1 Critical Remote Vulnerability**: CVE-2024-24213

#### Apache HTTPD (2.4.49-1)
- No critical or KEV vulnerabilities found

## Ambiguities & Notes

1. **Package Version Matching**: Vulnerability affects_pinned_version marked as "unknown" - would require CPE mapping to confirm if specific CVEs affect the pinned versions.

2. **SSH Version Concern**: The CVEs found for SSH include very old vulnerabilities (1999-2017). These may not affect the current version (9.6p1), but the KEV entry (CVE-2023-48795) is recent and should be prioritized.

3. **Database Credentials**: User passwords are not defined in the Ansible configuration - flagged as potential security gap.

4. **Default Deny**: Rule-008 implements default-deny posture for all unspecified access.

## Compliance Notes (SOC2)
- Access controls are role-based (group membership)
- Clearance levels enforced for privileged operations
- Network segmentation between DMZ and internal zones
- Audit logging obligations attached to sudo operations
