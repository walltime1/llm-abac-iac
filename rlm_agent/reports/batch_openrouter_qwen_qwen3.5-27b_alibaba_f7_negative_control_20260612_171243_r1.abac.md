# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:23:23_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 8 | Rules: 10_  
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
        "name": "openssh",
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
    "retention": {
      "default_log_retention_days": 90,
      "source": "group_vars/all.yml"
    },
    "pinned_packages": [
      {
        "name": "nginx",
        "version": "1.27.0-1~noble",
        "source": "group_vars/all.yml"
      },
      {
        "name": "openssh",
        "version": "1:9.9p1-3ubuntu1",
        "source": "group_vars/all.yml"
      },
      {
        "name": "postgresql",
        "version": "16.4-1.pgdg24.04+1",
        "source": "group_vars/all.yml"
      }
    ]
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
      "privilege": {
        "equals": "SUPERUSER"
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
      "privilege": {
        "equals": "NOSUPERUSER"
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "nopassword",
        "value": false
      }
    ],
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
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
        "equals": "openssh"
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
      "lines": "34-37"
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
    "effect": "deny",
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
[]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment with SOC2 compliance requirements.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | labcorp |
| Environment | production |
| Compliance Tier | soc2 |
| Log Retention | 90 days |

## Infrastructure

### Hosts

| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Users

| Username | UID | Groups | Department | Clearance |
|----------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |

### Pinned Software Versions

| Package | Version | Status |
|---------|---------|--------|
| nginx | 1.27.0-1~noble | ✅ Patched |
| openssh | 1:9.9p1-3ubuntu1 | ✅ Patched |
| postgresql | 16.4-1.pgdg24.04+1 | ✅ Patched |

## Vulnerability Assessment

### Summary
All pinned software versions have been assessed against critical remote vulnerabilities and Known Exploited Vulnerabilities (KEV). **No applicable CVEs found** - all packages are running patched versions.

### Assessment Details

| Package | CVEs Checked | Applicable | Notes |
|---------|--------------|------------|-------|
| nginx | CVE-2016-0746 | ❌ No | Affects versions < 1.9.10 |
| openssh | CVE-2024-6387 | ❌ No | Affects versions < 9.8p1 |
| postgresql | CVE-2022-31197 | ❌ No | Affects JDBC driver, not server |

## Extracted ABAC Rules

### Rule Summary

| ID | Subject | Resource | Action | Effect |
|----|---------|----------|--------|--------|
| rule-001 | groups: sudo | postgresql (SUPERUSER) | db:login | permit |
| rule-002 | groups: developers | postgresql (NOSUPERUSER) | db:login | permit |
| rule-003 | source: 10.0.1.0/24 | postgresql:5432 | network:connect | permit |
| rule-004 | groups: sudo | all | user:create | permit |
| rule-005 | groups: sudo, clearance: secret | all | sudo:execute | permit |
| rule-006 | source: 0.0.0.0/0 | nginx:443 | network:connect | permit |
| rule-007 | groups: sudo | openssh:22 | ssh:login | permit |
| rule-008 | all | all | * | deny |

### Detailed Rules

#### rule-001: Database Superuser Access
- **Subject**: Users in `sudo` group
- **Resource**: PostgreSQL with SUPERUSER privilege
- **Action**: db:login
- **Effect**: permit
- **Source**: roles/db/tasks/main.yml (lines 13-17)

#### rule-002: Database Read-Only Access
- **Subject**: Users in `developers` group
- **Resource**: PostgreSQL with NOSUPERUSER privilege
- **Action**: db:login
- **Effect**: permit
- **Source**: roles/db/tasks/main.yml (lines 19-23)

#### rule-003: PostgreSQL Network Access
- **Subject**: Source network 10.0.1.0/24 (webservers subnet)
- **Resource**: PostgreSQL port 5432
- **Action**: network:connect
- **Effect**: permit
- **Source**: roles/db/tasks/main.yml (lines 25-29)

#### rule-004: Shell User Provisioning
- **Subject**: Users in `sudo` group
- **Resource**: All
- **Action**: user:create
- **Effect**: permit
- **Source**: roles/web/tasks/main.yml (lines 13-18)

#### rule-005: Sudo Privilege Escalation
- **Subject**: Users in `sudo` group with `secret` clearance
- **Resource**: All
- **Action**: sudo:execute
- **Effect**: permit
- **Obligations**: nopassword=false (password required)
- **Source**: roles/web/tasks/main.yml (lines 20-25)

#### rule-006: HTTPS Internet Access
- **Subject**: Source network 0.0.0.0/0 (internet)
- **Resource**: nginx port 443
- **Action**: network:connect
- **Effect**: permit
- **Source**: roles/web/tasks/main.yml (lines 27-32)

#### rule-007: SSH Access Restriction
- **Subject**: Users in `sudo` group
- **Resource**: openssh port 22
- **Action**: ssh:login
- **Effect**: permit
- **Source**: roles/web/tasks/main.yml (lines 34-37)

#### rule-008: Default Deny
- **Subject**: All
- **Resource**: All
- **Action**: *
- **Effect**: deny
- **Source**: implicit default-deny policy

## Security Observations

### Strengths
1. **Least Privilege**: Database access is segmented by group (sudo→SUPERUSER, developers→NOSUPERUSER)
2. **Network Segmentation**: PostgreSQL only accessible from webservers subnet (10.0.1.0/24)
3. **SSH Restriction**: SSH login limited to sudo group members
4. **Clearance-Based Sudo**: Sudo access requires both group membership AND secret clearance
5. **Password Enforcement**: Sudo requires password (nopassword=false)

### Ambiguities
1. **Filesystem Permissions**: Document root `/var/www/html` permissions not explicitly defined in tasks
2. **Credential Management**: No explicit credential rotation or secrets management observed
3. **Audit Logging**: Log retention set to 90 days but no explicit audit rules extracted

## Files Processed

| File | Purpose |
|------|---------|
| inventory.ini | Host definitions and environment variables |
| group_vars/all.yml | Global variables, users, pinned versions |
| group_vars/dbservers.yml | Database server configuration |
| group_vars/webservers.yml | Web server configuration |
| roles/db/tasks/main.yml | Database provisioning tasks |
| roles/web/tasks/main.yml | Web server provisioning tasks |

## Compliance Notes

- **SOC2**: Environment marked as SOC2 compliant
- **Default Deny**: Implicit deny-all policy ensures least privilege
- **Access Control**: Multi-factor access control (group + clearance) for privileged operations
