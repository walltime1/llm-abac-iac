# ABAC Policy Mining — goal: all
_Generated: 2026-04-25 12:33:41_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 13 | Rules: 10_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

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
        "hostname": "web-new01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_patched",
        "source": "inventory.ini"
      },
      {
        "hostname": "web-old01.lab.local",
        "ip": "10.0.1.20",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_legacy",
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
        "host_group": "webservers_patched",
        "source": "group_vars/webservers_patched.yml"
      },
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers_legacy",
        "source": "group_vars/webservers_legacy.yml"
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
        "host_group": "webservers_patched",
        "source": "roles/web_patched/tasks/main.yml"
      },
      {
        "name": "openssh-server",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers_legacy",
        "source": "roles/web_legacy/tasks/main.yml"
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
        "label": "web_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers_patched.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "patchcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
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
    "name": "SSH access for sudo group (legacy)",
    "description": "Allow SSH login to legacy web servers for users in sudo group",
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
      },
      "inventory_group": {
        "equals": "webservers_legacy"
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
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "17-21"
    }
  },
  {
    "id": "rule-002",
    "name": "SSH access for sudo group (patched)",
    "description": "Allow SSH login to patched web servers for users in sudo group",
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
      },
      "inventory_group": {
        "equals": "webservers_patched"
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "17-21"
    }
  },
  {
    "id": "rule-003",
    "name": "Firewall HTTPS access (legacy)",
    "description": "Allow HTTPS traffic from internet to legacy web servers",
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
      },
      "inventory_group": {
        "equals": "webservers_legacy"
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
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "13-17"
    }
  },
  {
    "id": "rule-004",
    "name": "Firewall HTTPS access (patched)",
    "description": "Allow HTTPS traffic from internet to patched web servers",
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
      },
      "inventory_group": {
        "equals": "webservers_patched"
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "13-17"
    }
  },
  {
    "id": "rule-005",
    "name": "PostgreSQL access from web subnet",
    "description": "Allow PostgreSQL connections from web server subnet",
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
      "inventory_group": {
        "equals": "dbservers"
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
      "task": "Allow postgres only from web subnet",
      "lines": "13-17"
    }
  },
  {
    "id": "rule-006",
    "name": "PostgreSQL data directory access",
    "description": "Restrict PostgreSQL data directory to postgres user/group",
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
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
    }
  },
  {
    "id": "rule-007",
    "name": "Default deny",
    "description": "Deny all access not explicitly permitted",
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
      "file": "generated",
      "task": "default_deny",
      "lines": "1"
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
    "id": "rule-009",
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
    "product": "openssh",
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update to OpenSSH version 3.7 or later."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2023-38408",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "source": "kev",
    "recommendation": "URGENT: openssh has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2024-6387",
    "severity": "high",
    "cvss_score": 8.1,
    "is_kev": true,
    "source": "kev",
    "recommendation": "URGENT: openssh has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2007-4752",
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "source": "kev",
    "recommendation": "URGENT: openssh has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2019-6109",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "source": "kev",
    "recommendation": "URGENT: openssh has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2019-6110",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "source": "kev",
    "recommendation": "URGENT: openssh has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2019-9193",
    "severity": "high",
    "cvss_score": 7.2,
    "is_kev": true,
    "source": "kev",
    "recommendation": "URGENT: postgresql has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2022-31197",
    "severity": "high",
    "cvss_score": 7.1,
    "is_kev": true,
    "source": "kev",
    "recommendation": "URGENT: postgresql has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update to nginx 1.9.10 or later versions."
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update to the latest version of njs where the issue is fixed."
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update to version 1.13.6 or later."
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update nginx to the latest version where this issue is fixed."
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2016-0742",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "affects_pinned_version": true,
    "source": "critical_remote",
    "recommendation": "Update nginx to version 1.8.1, 1.9.10 or later."
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2023-44487",
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "source": "kev",
    "recommendation": "URGENT: nginx has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2009-3555",
    "severity": "medium",
    "cvss_score": 5.8,
    "is_kev": true,
    "source": "kev",
    "recommendation": "URGENT: nginx has known exploited vulnerability - immediate patching required"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the Ansible configuration in `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web servers (patched and legacy variants) and database servers.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | patchcorp |
| Environment | production |
| Compliance Tier | SOC2 |
| Log Retention | 90 days |

## Subjects (2 users)

| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

### Groups
- `sudo` - Administrative access
- `developers` - Development access

### Clearance Levels
- `secret` - High clearance
- `confidential` - Medium clearance

## Resources

### Hosts (3)
| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services (5)
- nginx (port 443) on webservers_patched and webservers_legacy
- openssh-server (port 22) on webservers_patched and webservers_legacy
- postgresql (port 5432) on dbservers

### Filesystems (1)
- `/var/lib/postgresql/data` - owned by postgres:postgres, mode 0700

### Networks (2)
- `10.0.1.0/24` - DMZ web subnet
- `0.0.0.0/0` - Internet (external)

## Access Control Rules (7)

| ID | Name | Action | Effect |
|----|------|--------|--------|
| rule-001 | SSH access for sudo group (legacy) | ssh:login | permit |
| rule-002 | SSH access for sudo group (patched) | ssh:login | permit |
| rule-003 | Firewall HTTPS access (legacy) | network:connect | permit |
| rule-004 | Firewall HTTPS access (patched) | network:connect | permit |
| rule-005 | PostgreSQL access from web subnet | db:login | permit |
| rule-006 | PostgreSQL data directory access | filesystem:read | permit |
| rule-007 | Default deny | * | deny |

## Vulnerability Assessment (24 vulnerabilities)

### OpenSSH (9 vulnerabilities)
- **Critical**: CVE-2000-0999, CVE-2001-0144, CVE-2000-0525, CVE-2003-0693, CVE-2003-0786
- **KEV**: CVE-2023-38408 (critical), CVE-2024-6387 (high), CVE-2007-4752, CVE-2019-6109, CVE-2019-6110

### PostgreSQL (7 vulnerabilities)
- **Critical**: CVE-2007-3279, CVE-2002-1399, CVE-2024-1597, CVE-2013-1902, CVE-2013-1903
- **KEV**: CVE-2019-9193, CVE-2022-31197

### Nginx (8 vulnerabilities)
- **Critical**: CVE-2016-0746, CVE-2021-46461, CVE-2017-20005
- **High**: CVE-2021-23017, CVE-2016-0742
- **KEV**: CVE-2023-44487, CVE-2009-3555

## Security Observations

### Strengths
1. SSH access is properly restricted to the sudo group
2. Database access is limited to the web server subnet (10.0.1.0/24)
3. PostgreSQL data directory has restrictive permissions (0700)
4. Separate patched and legacy configurations allow for controlled upgrades

### Concerns
1. **Legacy nginx version (1.20.0)** on web-old01 is vulnerable to multiple CVEs
2. **Firewall allows 0.0.0.0/0** - all internet traffic can reach web servers
3. **KEV vulnerabilities** present in all three products (openssh, postgresql, nginx)
4. **CVE-2023-44487** (HTTP/2 Rapid Reset) affects nginx - actively exploited

### Recommendations
1. **URGENT**: Patch nginx on legacy servers to version 1.24.0+
2. **URGENT**: Address KEV vulnerabilities, especially CVE-2023-44487
3. Consider restricting firewall rules to specific source IPs rather than 0.0.0.0/0
4. Implement network segmentation between DMZ and internal zones
5. Upgrade legacy web server or decommission

## Ambiguities

1. **No sudo rules found**: The configuration restricts SSH to sudo group but does not define sudo privileges in the Ansible files
2. **No database user rules**: PostgreSQL pg_hba.conf allows connections but no specific database users are configured
3. **Credential management**: No password or key management policies found in the configuration
4. **Session logging**: No audit or logging obligations defined

## Files Analyzed

### Phase 1 (Catalog)
- inventory.ini
- group_vars/all.yml
- group_vars/dbservers.yml
- group_vars/webservers_legacy.yml
- group_vars/webservers_patched.yml

### Phase 2 (Rule Extraction)
- roles/db/tasks/main.yml
- roles/web_legacy/tasks/main.yml
- roles/web_patched/tasks/main.yml

---
*Report generated from ABAC policy mining*
