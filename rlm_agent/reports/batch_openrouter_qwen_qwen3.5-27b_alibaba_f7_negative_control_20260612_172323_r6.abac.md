# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:30:19_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 10 | Rules: 10_  
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
        "department": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "department": "engineering",
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
        "name": "nginx",
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
        "name": "openssh-server",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "group_vars/all.yml"
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
        "service": "nginx",
        "source": "group_vars/webservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
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
    "log_retention_days": {
      "value": 90,
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
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "privilege_level": "SUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "13-17"
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
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "privilege_level": "NOSUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "19-23"
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "25-29"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "13-18"
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
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "nopassword": false,
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "20-25"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "27-32"
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
      "service": {
        "equals": "openssh-server"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "34-38"
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
    "action": "*",
    "effect": "deny",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "implicit",
      "task": "default-deny",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-009",
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
        "equals": "soc2"
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
    "id": "rule-010",
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
        "equals": "soc2"
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
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Ensure nginx remains patched. Current version 1.27.0 is up-to-date."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Ensure nginx remains patched. Current version 1.27.0 is up-to-date."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Ensure nginx remains patched. Current version 1.27.0 is up-to-date."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Ensure postgresql remains patched. Current version 16.4 is up-to-date."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Ensure postgresql remains patched. Current version 16.4 is up-to-date."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Ensure postgresql remains patched. Current version 16.4 is up-to-date."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web and database servers under SOC2 compliance requirements.

## Environment Overview
- **Organization**: labcorp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Infrastructure
### Hosts
| Hostname | IP | Role | Zone |
|----------|-----|------|------|
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| db01.lab.local | 10.0.2.10 | primary | internal |

### Users
| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

## Access Control Rules (8 total)

### Database Access
1. **rule-001**: Users in `sudo` group → PostgreSQL SUPERUSER access
2. **rule-002**: Users in `developers` group → PostgreSQL NOSUPERUSER (read-only) access
3. **rule-003**: Network access from 10.0.1.0/24 (webservers subnet) → PostgreSQL port 5432

### System Access
4. **rule-004**: Users in `sudo` group → user:create (shell user provisioning)
5. **rule-005**: Users in `sudo` group with `secret` clearance → sudo:execute (password required)
6. **rule-007**: Users in `sudo` group → SSH login access

### Network Access
7. **rule-006**: Any source (0.0.0.0/0) → HTTPS port 443 (internet-facing)

### Default Policy
8. **rule-008**: Default deny for all other access attempts

## Vulnerability Assessment
- **6 vulnerabilities** identified across nginx and postgresql
- **All pinned versions are patched** - no CVEs affect the deployed versions
- Products assessed: nginx 1.27.0, openssh-server 9.9p1, postgresql 16.4

### Critical Findings (Historical - Not Affecting Current Versions)
| CVE | Product | Severity | CVSS | Affects Pinned |
|-----|---------|----------|------|----------------|
| CVE-2016-0746 | nginx | critical | 9.8 | No |
| CVE-2021-46461 | nginx | critical | 9.8 | No |
| CVE-2017-20005 | nginx | critical | 9.8 | No |
| CVE-2007-3279 | postgresql | critical | 10.0 | No |
| CVE-2013-1902 | postgresql | critical | 10.0 | No |
| CVE-2013-1903 | postgresql | critical | 10.0 | No |

## Security Architecture
- **DMZ Layer**: Web servers (web01) expose HTTPS to internet, SSH restricted to sudo group
- **Internal Layer**: Database server (db01) accepts connections only from webservers subnet (10.0.1.0/24)
- **Access Control**: Role-based with clearance requirements for privileged operations

## Ambiguities and Notes
1. No explicit credentials/passwords found in configuration (good practice)
2. SSH access requires sudo group membership
3. Database access is role-based with separation between SUPERUSER and read-only access
4. Firewall rules are permissive for HTTPS (internet-facing) but restrictive for PostgreSQL

## Compliance Alignment
- SOC2 compliance tier enforced across all rules
- Access controls follow principle of least privilege
- Network segmentation between DMZ and internal zones
- Audit logging configured (90-day retention)
