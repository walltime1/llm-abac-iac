# ABAC Policy Mining — goal: all
_Generated: 2026-04-25 12:26:37_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 13 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f2_threetier_segmented`_

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
      },
      {
        "name": "data",
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
        "host_group": "dmz",
        "source": "inventory.ini"
      },
      {
        "hostname": "app01.lab.local",
        "ip": "10.0.2.10",
        "role": "application",
        "zone": "app",
        "host_group": "appservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.3.10",
        "role": "primary",
        "zone": "data",
        "host_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
      },
      {
        "name": "application",
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
        "mode": "0600",
        "service": "openssh",
        "source": "roles/app/tasks/main.yml"
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
        "label": "appservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/dmz.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "segcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "pci",
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "value": 365,
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
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "service": {
        "equals": "openssh"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "24-28"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "openssh"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "33-37"
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "service": {
        "equals": "openssh"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "24-28"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "postgresql"
      },
      "privilege_level": {
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
      "task": "Create DB superuser role for DBAs",
      "lines": "19-23"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "postgresql"
      },
      "privilege_level": {
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
      "task": "Create DB read-only role for developers",
      "lines": "25-29"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "31-35"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "service": {
        "equals": "application"
      },
      "port": {
        "equals": 8080
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
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-22"
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "16-22"
    }
  },
  {
    "id": "rule-009",
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
      "lines": "11-17"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "service": {
        "equals": "user_account"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "8-14"
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "service": {
        "equals": "user_account"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "11-17"
    }
  },
  {
    "id": "rule-012",
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
    "id": "rule-014",
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
    "id": "rule-015",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "application"
      },
      "port": {
        "equals": 8080
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
    "id": "rule-016",
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
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "is_remote": true,
    "cvss_score": 10,
    "name": "OpenBSD SSH - Buffer Overflow",
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "is_remote": true,
    "cvss_score": 10,
    "name": "CORE SDI SSH1 CRC-32 - Command Injection",
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "is_remote": true,
    "cvss_score": 10,
    "name": "OpenSSH - Privilege Escalation",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "is_remote": true,
    "cvss_score": 10,
    "name": "OpenSSH - Buffer Overflow",
    "recommendation": "Update to OpenSSH version 3.7 or later."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "is_remote": true,
    "cvss_score": 10,
    "name": "OpenSSH - Privilege Escalation",
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "severity": "critical",
    "is_remote": true,
    "cvss_score": 10,
    "name": "PostgreSQL - Privilege Escalation",
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "severity": "critical",
    "is_remote": true,
    "cvss_score": 10,
    "name": "PostgreSQL - Integer Overflow",
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "severity": "critical",
    "is_remote": true,
    "cvss_score": 10,
    "name": "pgjdbc - SQL Injection",
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "severity": "critical",
    "is_remote": true,
    "cvss_score": 10,
    "name": "PostgreSQL - Insecure Temporary Files",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "severity": "critical",
    "is_remote": true,
    "cvss_score": 10,
    "name": "PostgreSQL - Information Disclosure",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
This report documents the ABAC (Attribute-Based Access Control) policy mined from the Ansible configuration at RLM_ANSIBLE_DIR. The configuration manages a three-tier architecture: DMZ (reverse proxy), Application servers, and Database servers.

## Environment Overview
- **Organization**: segcorp
- **Environment**: production
- **Compliance Tier**: PCI
- **Log Retention**: 365 days

## Hosts Inventory
| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

## Users and Groups
| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |

### Groups
- **sudo**: Administrative access
- **developers**: Application development team
- **dba**: Database administration

## Extracted Rules Summary
| Rule ID | Action | Effect | Subject | Resource |
|---------|--------|--------|---------|----------|
| rule-001 | ssh:login | permit | groups in [sudo, developers] | app zone, openssh |
| rule-002 | ssh:login | permit | groups in [sudo, dba] | data zone, openssh |
| rule-003 | ssh:login | permit | groups = sudo | dmz zone, openssh |
| rule-004 | db:login | permit | groups = dba | postgresql, SUPERUSER |
| rule-005 | db:login | permit | groups = developers | postgresql, NOSUPERUSER |
| rule-006 | network:connect | permit | source 10.0.2.0/24 | postgresql:5432 |
| rule-007 | network:connect | permit | source 10.0.1.0/24 | application:8080 |
| rule-008 | network:connect | permit | source 0.0.0.0/0 | nginx:443 |
| rule-009 | filesystem:read | permit | user = postgres | /var/lib/postgresql/data |
| rule-010 | user:create | permit | groups in [developers, sudo] | app zone |
| rule-011 | user:create | permit | groups = sudo | dmz zone |
| rule-012 | * | deny | all | all (default) |

## Vulnerability Assessment
Found **10 critical vulnerabilities** in pinned software packages:

### OpenSSH (1:9.6p1-3ubuntu1)
- CVE-2000-0999: Buffer Overflow (CVSS 10.0)
- CVE-2001-0144: Command Injection (CVSS 10.0)
- CVE-2000-0525: Privilege Escalation (CVSS 10.0)
- CVE-2003-0693: Buffer Overflow (CVSS 10.0)
- CVE-2003-0786: Privilege Escalation (CVSS 10.0)

### PostgreSQL (13.7-1.pgdg20.04+1)
- CVE-2007-3279: Privilege Escalation (CVSS 10.0)
- CVE-2002-1399: Integer Overflow (CVSS 10.0)
- CVE-2024-1597: SQL Injection (CVSS 10.0)
- CVE-2013-1902: Insecure Temporary Files (CVSS 10.0)
- CVE-2013-1903: Information Disclosure (CVSS 10.0)

**Recommendation**: Upgrade all packages to patched versions immediately.

## Security Architecture
The configuration implements a layered security model:

1. **DMZ Layer**: Only sudo group has SSH access; HTTPS open to internet
2. **Application Layer**: sudo and developers groups have SSH; app port accessible from DMZ only
3. **Database Layer**: sudo and dba groups have SSH; PostgreSQL accessible from appservers subnet only

## Ambiguities and Notes
- No explicit sudoers rules found in configuration (sudo access assumed via group membership)
- No SELinux policies configured
- No explicit credential management (passwords/keys) documented
- Filesystem ACLs limited to postgres data directory

## Compliance Considerations
- PCI compliance tier requires additional audit logging (not configured)
- Network segmentation follows PCI requirements (DMZ isolation)
- Default-deny policy enforced (rule-012)
