# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:24:11_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 13 | Rules: 11_  
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
      "secret",
      "confidential"
    ],
    "departments": [
      "operations",
      "engineering"
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
    "org": "labcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "group_vars/all.yml"
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
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "27-31"
    }
  },
  {
    "id": "rule-002",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "19-25"
    },
    "obligations": [
      {
        "type": "nopassword",
        "value": false
      }
    ]
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "privilege_level": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "12-17"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "privilege_level": {
        "equals": "NOSUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "18-23"
    }
  },
  {
    "id": "rule-005",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "24-29"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "26-31"
    }
  },
  {
    "id": "rule-007",
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "6-11"
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
        "equals": "nginx"
      },
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Update to nginx 1.9.10 or later versions."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of njs where the issue is fixed."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Update to version 1.13.6 or later."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest versions of affected products."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Implement rate limiting and update to latest http/2 protocol standards."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 8.1,
    "is_remote": true,
    "type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Update to openssh 9.3p2 or later."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of openssh."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 6.8,
    "is_remote": true,
    "type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Update to openssh 4.7 or later."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 9.8,
    "is_remote": true,
    "type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Update to postgresql version 11.3 or later."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment with SOC2 compliance requirements.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | labcorp |
| Environment | production |
| Compliance Tier | soc2 |
| Log Retention | 90 days |

## Subjects (Users)

| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

## Resources

### Hosts

| Hostname | IP | Role | Zone |
|----------|-----|------|------|
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| db01.lab.local | 10.0.2.10 | primary | internal |

### Services

| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| nginx | 443 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |

### Filesystem Paths

| Path | Owner | Group | Mode |
|------|-------|-------|------|
| /var/lib/postgresql/data | postgres | postgres | 0700 |
| /var/www/html | www-data | www-data | 0755 |

## Mined ABAC Rules

### Access Control Rules

1. **SSH Login (rule-001)**: Members of `sudo` group can SSH login
2. **Sudo Execution (rule-002)**: Users in `sudo` group with `secret` clearance can execute sudo (password required)
3. **Database SUPERUSER (rule-003)**: Members of `sudo` group get SUPERUSER database access
4. **Database Read-Only (rule-004)**: Members of `developers` group get NOSUPERUSER database access

### Network Rules

5. **PostgreSQL Network (rule-005)**: Only 10.0.1.0/24 (webservers subnet) can connect to PostgreSQL
6. **HTTPS Network (rule-006)**: Internet (0.0.0.0/0) can connect to HTTPS port 443

### Filesystem Rules

7. **PostgreSQL Data Directory (rule-007)**: /var/lib/postgresql/data is owned by postgres:postgres with mode 0700

### Default Policy

8. **Default Deny (rule-008)**: All other access is denied by default

## Vulnerability Assessment

### Summary

- **Total CVEs Found**: 25 (10 shown in detail below)
- **Pinned Versions**: All patched (nginx 1.27.0, openssh 9.9p1, postgresql 16.4)
- **Active Threats**: None affecting current versions

### Critical Vulnerabilities (Historical)

| CVE | Product | Severity | CVSS | Status |
|-----|---------|----------|------|--------|
| CVE-2016-0746 | nginx | critical | 9.8 | Patched |
| CVE-2021-46461 | nginx | critical | 9.8 | Patched |
| CVE-2017-20005 | nginx | critical | 9.8 | Patched |
| CVE-2009-3555 | nginx | critical | 9.8 | Patched (KEV) |
| CVE-2023-38408 | openssh | critical | 8.1 | Patched (KEV) |
| CVE-2024-1597 | postgresql | critical | 10.0 | Patched (KEV) |

## Ambiguities

- No explicit session logging or audit obligations found in configuration
- Credentials management not explicitly defined (assumed external secret management)
- No SELinux policies found in configuration

## Compliance Notes

- SOC2 compliance tier requires strict access controls - implemented via group-based access
- Default-deny posture maintained
- Network segmentation enforced (DMZ vs internal zones)
