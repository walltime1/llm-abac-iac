# ABAC Policy Mining — goal: all
_Generated: 2026-04-25 12:30:33_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 8_  
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
        "value": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "value": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "value": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "value": "engineering",
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
        "version": "1.24.0-2ubuntu1",
        "source": "group_vars/webservers_patched.yml"
      },
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers_legacy",
        "version": "1.20.0-1~focal",
        "source": "group_vars/webservers_legacy.yml"
      },
      {
        "name": "openssh-server",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all",
        "version": "1:9.6p1-3ubuntu1",
        "source": "group_vars/all.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "version": "16.2-1.pgdg22.04+1",
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
        "source": "group_vars/webservers_legacy.yml"
      }
    ]
  },
  "environment": {
    "org": "patchcorp",
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
    "rule_id": "rule-001",
    "name": "SSH access for sudo group",
    "description": "Allow SSH login to sudo group members on web servers",
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
      "lines": "24-28"
    }
  },
  {
    "rule_id": "rule-002",
    "name": "HTTPS access from internet",
    "description": "Allow HTTPS connections from any source to web servers",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      },
      "role": {
        "equals": "frontend"
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
      "lines": "17-22"
    }
  },
  {
    "rule_id": "rule-003",
    "name": "PostgreSQL access from web subnet",
    "description": "Allow database connections from web server subnet to PostgreSQL",
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
      "role": {
        "equals": "primary"
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
      "task": "Allow postgres only from web subnet",
      "lines": "15-19"
    }
  },
  {
    "rule_id": "rule-004",
    "name": "PostgreSQL data directory access",
    "description": "Restrict access to PostgreSQL data directory (mode 0700)",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-13"
    }
  },
  {
    "rule_id": "rule-005",
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
      "file": "implicit",
      "task": "default-deny",
      "lines": "N/A"
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
    "id": "rule-003",
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
    "product": "openssh",
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply vendor patch: Update to version 42.7.2 or later.",
    "type": "critical_remote"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2016-0742",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Likely already patched in current version",
    "type": "critical_remote"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web servers (patched and legacy variants) and database servers.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | patchcorp |
| Environment | production |
| Compliance Tier | SOC2 |
| Log Retention | 90 days |

## Subjects

### Users

| Name | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |

### Groups

| Group Name | Purpose |
|------------|---------|
| sudo | Administrative access |
| developers | Application development |

## Resources

### Hosts

| Hostname | IP | Role | Zone | Inventory Group |
|----------|-----|------|------|-----------------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services

| Service | Port | Protocol | Host Group | Version |
|---------|------|----------|------------|---------|
| nginx | 443 | tcp | webservers_patched | 1.24.0-2ubuntu1 |
| nginx | 443 | tcp | webservers_legacy | 1.20.0-1~focal |
| openssh-server | 22 | tcp | all | 1:9.6p1-3ubuntu1 |
| postgresql | 5432 | tcp | dbservers | 16.2-1.pgdg22.04+1 |

### Filesystem Paths

| Path | Owner | Group | Mode | Service |
|------|-------|-------|------|---------|
| /var/lib/postgresql/data | postgres | postgres | 0700 | postgresql |

### Network Ranges

| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | web_subnet |
| 0.0.0.0/0 | external | internet |

## Access Rules

### Rule Summary

| Rule ID | Name | Action | Effect |
|---------|------|--------|--------|
| rule-001 | SSH access for sudo group | ssh:login | permit |
| rule-002 | HTTPS access from internet | network:connect | permit |
| rule-003 | PostgreSQL access from web subnet | network:connect | permit |
| rule-004 | PostgreSQL data directory access | filesystem:read | permit |
| rule-005 | Default deny | * | deny |

### Rule Details

#### rule-001: SSH access for sudo group
- **Subject Condition**: groups any_of [sudo]
- **Resource Condition**: service=openssh-server, port=22
- **Action**: ssh:login
- **Effect**: permit
- **Source**: roles/web_legacy/tasks/main.yml (lines 24-28)

#### rule-002: HTTPS access from internet
- **Subject Condition**: source_network=0.0.0.0/0
- **Resource Condition**: port=443, protocol=tcp, role=frontend
- **Action**: network:connect
- **Effect**: permit
- **Source**: roles/web_legacy/tasks/main.yml (lines 17-22)

#### rule-003: PostgreSQL access from web subnet
- **Subject Condition**: source_network=10.0.1.0/24
- **Resource Condition**: service=postgresql, port=5432, role=primary
- **Action**: network:connect
- **Effect**: permit
- **Source**: roles/db/tasks/main.yml (lines 15-19)

#### rule-004: PostgreSQL data directory access
- **Subject Condition**: user=postgres
- **Resource Condition**: path=/var/lib/postgresql/data, owner=postgres, group=postgres, mode=0700
- **Action**: filesystem:read
- **Effect**: permit
- **Source**: roles/db/tasks/main.yml (lines 8-13)

#### rule-005: Default deny
- **Subject Condition**: applies_to=all
- **Resource Condition**: applies_to=all
- **Action**: *
- **Effect**: deny
- **Source**: implicit (default-deny policy)

## Vulnerability Assessment

### Summary

| Product | Critical Remote CVEs | KEV CVEs | Affects Pinned Version |
|---------|---------------------|----------|----------------------|
| openssh | 5 | 0 | Mixed (age-based) |
| postgresql | 5 | 0 | Mixed (age-based) |
| nginx | 5 | 0 | Mixed (age-based) |

### Key Findings

1. **Legacy nginx (1.20.0-1~focal)**: Older version with potential exposure to historical CVEs
2. **Patched nginx (1.24.0-2ubuntu1)**: Current version, better security posture
3. **PostgreSQL 16.2**: Recent version, most CVEs are historical
4. **OpenSSH 9.6p1**: Recent version, most CVEs are historical

### Recommendations

1. **Upgrade legacy web servers**: Migrate web-old01 from nginx 1.20.0 to 1.24.0+
2. **Network segmentation**: Consider restricting 0.0.0.0/0 firewall rule to specific IPs
3. **Database access**: Current 10.0.1.0/24 restriction is appropriate
4. **SSH access**: Group-based restriction (sudo) is properly implemented

## Ambiguities

1. **User credentials**: No password policies or credential management found in configuration
2. **Audit logging**: Log retention (90 days) is defined but no audit rules extracted
3. **SELinux/AppArmor**: No mandatory access control policies found
4. **Session management**: No session timeout or concurrent session limits defined

## Compliance Notes

- **SOC2 Compliance**: Environment is marked as SOC2 tier
- **Default Deny**: Implicit default-deny policy in place
- **Least Privilege**: SSH access restricted to sudo group only
- **Network Segmentation**: Database access restricted to web subnet only
