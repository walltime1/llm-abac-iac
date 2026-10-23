# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:17:24_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 8 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

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
        "department": "operations",
        "clearance": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "department": "engineering",
        "clearance": "confidential",
        "source": "group_vars/all.yml"
      },
      {
        "name": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "department": "data",
        "clearance": "secret",
        "source": "group_vars/all.yml"
      }
    ],
    "groups": [
      "groups"
    ],
    "clearance_levels": [
      {
        "name": "clearance",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "name": "department",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      }
    ]
  },
  "resources": {
    "hosts": [
      {
        "hostname": "proxy01.lab.local",
        "ip": "10.0.1.10",
        "role": "reverse_proxy",
        "zone": "dmz",
        "inventory_group": "dmz",
        "source": "inventory.ini"
      },
      {
        "hostname": "app01.lab.local",
        "ip": "10.0.2.10",
        "role": "application",
        "zone": "app",
        "inventory_group": "appservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.3.10",
        "role": "primary",
        "zone": "data",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "https",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
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
        "host_group": "all",
        "source": "roles/app/tasks/main.yml"
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
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "sshd",
        "source": "roles/db/tasks/main.yml"
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
        "zone": "dmz",
        "label": "dmz_subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "public",
        "source": "group_vars/dmz.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "segcorp",
      "domain": [
        "segcorp"
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
      "value": "pci",
      "domain": [
        "pci",
        "hipaa",
        "sox",
        "gdpr"
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
    "description": "SSH login permitted for sudo and developers groups on app servers",
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
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "24-28"
    }
  },
  {
    "id": "rule-002",
    "description": "SSH login permitted for sudo and dba groups on db servers",
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
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "41-45"
    }
  },
  {
    "id": "rule-003",
    "description": "SSH login permitted for sudo group on DMZ servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "reverse_proxy"
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-004",
    "description": "Network connection from DMZ subnet to app server port 8080/tcp",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 8080
      },
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-22"
    }
  },
  {
    "id": "rule-005",
    "description": "Network connection from internet to DMZ HTTPS port 443/tcp",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "22-28"
    }
  },
  {
    "id": "rule-006",
    "description": "Network connection from app subnet to PostgreSQL port 5432",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "35-39"
    }
  },
  {
    "id": "rule-007",
    "description": "Database login with SUPERUSER privileges for dba group members",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
      },
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "21-26"
    },
    "obligations": [
      {
        "type": "audit",
        "description": "Session logging required for superuser access"
      }
    ]
  },
  {
    "id": "rule-008",
    "description": "Database login with NOSUPERUSER privileges for developers group",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
      },
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "28-33"
    }
  },
  {
    "id": "rule-009",
    "description": "Filesystem read/write/execute on PostgreSQL data directory (mode 0700, owner postgres)",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "13-19"
    }
  },
  {
    "id": "rule-010",
    "description": "User account creation for developers and sudo groups on app servers",
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
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:provision",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-14"
    }
  },
  {
    "id": "rule-011",
    "description": "User account creation for sudo group on DMZ servers",
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:provision",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "13-20"
    }
  },
  {
    "id": "rule-012",
    "description": "Default deny all access not explicitly permitted",
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
      "environment": {
        "equals": "production"
      },
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
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
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
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
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
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
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
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "description": "HTTP/2 Rapid Reset attack (CVE-2023-44487) - nginx 1.20.0 supports HTTP/2 and is vulnerable to rapid stream reset attacks causing DoS",
    "recommendation": "Upgrade nginx to >= 1.25.3 or apply vendor patches; configure rate limiting as mitigation"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "description": "Use-after-free in nginx (2016) - likely fixed in nginx 1.20.0 released 2021",
    "recommendation": "Verify patch status in Ubuntu focal nginx package; CVE status is 'rejected' by NVD"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL critical vulnerability (CVSS 10.0) - remotely exploitable, actively exploited in wild (KEV)",
    "recommendation": "Immediately upgrade PostgreSQL to latest patched version; this is a KEV entry with active exploitation"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "description": "PostgreSQL 8.1+ plpgsql PUBLIC privilege escalation (2007) - fixed in PostgreSQL 9+ by restricting PUBLIC grants",
    "recommendation": "Historical CVE; PostgreSQL 16.x has addressed this. Verify no custom PL/pgSQL functions grant excessive privileges"
  }
]
```

## Report

# ABAC Policy Mining Report — segcorp Production Infrastructure

## Executive Summary

Mined an Attribute-Based Access Control (ABAC) policy from the Ansible configuration at `RLM_ANSIBLE_DIR`. The infrastructure consists of 3 hosts across 3 zones (dmz, app, data) in a PCI-compliant production environment for organization **segcorp**.

## Infrastructure Overview

| Host | IP | Role | Zone | Inventory Group |
|------|-----|------|------|----------------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

**Environment:** production | **Compliance Tier:** PCI | **Org:** segcorp

## Users and Groups

| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

**Distinct Groups:** sudo, developers, dba
**Clearance Levels:** secret, confidential
**Departments:** operations, engineering, data

## Pinned Software Versions

| Package | Version | Source |
|---------|---------|--------|
| nginx | 1.20.0-1~focal | group_vars/all.yml |
| openssh-server | 1:9.1p1-1ubuntu1 | group_vars/all.yml |
| postgresql | 16.2-1.pgdg22.04+1 | group_vars/all.yml |

## Rules Summary (12 rules)

| ID | Action | Subject | Resource | Effect |
|----|--------|---------|----------|--------|
| rule-001 | ssh:login | groups in {sudo, developers} | zone=app | permit |
| rule-002 | ssh:login | groups in {sudo, dba} | zone=data | permit |
| rule-003 | ssh:login | groups in {sudo} | zone=dmz | permit |
| rule-004 | network:connect | source=10.0.1.0/24 | port=8080, zone=app | permit |
| rule-005 | network:connect | source=0.0.0.0/0 | port=443, zone=dmz | permit |
| rule-006 | network:connect | source=10.0.2.0/24 | port=5432, zone=data | permit |
| rule-007 | db:login (SUPERUSER) | groups in {dba} | zone=data | permit |
| rule-008 | db:login (NOSUPERUSER) | groups in {developers} | zone=data | permit |
| rule-009 | filesystem:read | groups in {dba} | path=/var/lib/postgresql/data | permit |
| rule-010 | user:provision | groups in {sudo, developers} | zone=app | permit |
| rule-011 | user:provision | groups in {sudo} | zone=dmz | permit |
| rule-012 | * | all | all | deny |

## Vulnerability Assessment

### Critical Findings

| CVE | Product | CVSS | Severity | KEV | Affects Pinned Version |
|-----|---------|------|----------|-----|----------------------|
| CVE-2024-1597 | postgresql | 10.0 | critical | Yes | **Yes** |
| CVE-2023-44487 | nginx | 7.5 | high | Yes | **Yes** |
| CVE-2016-0746 | nginx | 9.8 | critical | No | No (likely fixed) |
| CVE-2007-3279 | postgresql | 10.0 | critical | No | No (fixed in PG 9+) |

**⚠️ Immediate Action Required:**
- **CVE-2024-1597** (PostgreSQL, CVSS 10.0): Actively exploited in the wild (KEV). Upgrade PostgreSQL immediately.
- **CVE-2023-44487** (nginx, CVSS 7.5): HTTP/2 Rapid Reset attack, KEV-listed. Upgrade nginx to >= 1.25.3.

### Openssh-Server
No critical/remote or KEV vulnerabilities found for openssh-server 1:9.1p1-1ubuntu1.

## Ambiguities and Notes

1. **No sudoers rules found:** No explicit sudo configuration in the Ansible roles. SSH `AllowGroups` restricts login but sudo privileges are not explicitly defined in the configuration.
2. **No SELinux policies:** No SELinux configuration found in the Ansible files.
3. **Credentials in templates:** Firewall and database access rules reference variable interpolation (`{{ item }}`, `{{ db_allow_from }}`), which resolve at runtime. Actual values depend on group_vars.
4. **Filesystem rules limited:** Only one explicit filesystem permission rule found (PostgreSQL data directory). Other file permissions (e.g., sshd_config, pg_hba.conf) are implied but not explicitly enforced as ABAC rules.
5. **Session logging:** No explicit audit/session logging configuration found in the role tasks. An obligation was attached to the DBA superuser rule as a recommendation.
6. **Implicit deny:** No explicit default-deny in Ansible configuration; rule-012 is inferred as a best-practice default-deny for the ABAC policy.
7. **SSH on dbservers:** The db server SSH AllowGroups is hardcoded as `sudo dba` (not using the variable), while app and dmz servers use `{{ allowed_ssh_groups }}`.

## Data Retention

Default log retention: **365 days** (group_vars/all.yml)
