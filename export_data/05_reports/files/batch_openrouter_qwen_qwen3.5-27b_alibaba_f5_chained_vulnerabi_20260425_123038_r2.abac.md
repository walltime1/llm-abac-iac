# ABAC Policy Mining — goal: all
_Generated: 2026-04-25 12:34:09_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 21_  
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
    "clearance_levels": {
      "domain": [
        "confidential",
        "secret",
        "top_secret"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "bastion01.lab.local",
        "ip": "10.0.0.5",
        "role": "bastion",
        "zone": "mgmt",
        "inventory_group": "bastion",
        "source": "inventory.ini"
      },
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers",
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
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all",
        "source": "group_vars/all.yml"
      },
      {
        "name": "http",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "group_vars/webservers.yml"
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
      }
    ],
    "paths": [
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql",
        "source": "group_vars/dbservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "bastion_subnet",
        "source": "inventory.ini"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web_subnet",
        "source": "inventory.ini"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet",
        "source": "inventory.ini"
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "db_subnet",
        "source": "inventory.ini"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "chaincorp",
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
        "soc2",
        "none"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "value": 365,
      "source": "group_vars/all.yml"
    }
  },
  "software": {
    "packages": [
      {
        "name": "openssh",
        "version": "1:9.9p1-3ubuntu1",
        "source": "group_vars/all.yml"
      },
      {
        "name": "openssh_bastion",
        "version": "1:9.1p1-1ubuntu1",
        "source": "group_vars/all.yml"
      },
      {
        "name": "httpd",
        "version": "2.4.49-1",
        "source": "group_vars/all.yml"
      },
      {
        "name": "log4j",
        "version": "2.14.1",
        "source": "group_vars/all.yml"
      },
      {
        "name": "postgresql",
        "version": "9.2.3-1.pgdg20.04+1",
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
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "mgmt"
      },
      "service": {
        "equals": "ssh"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "14-18"
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
      "zone": {
        "equals": "dmz"
      },
      "service": {
        "equals": "ssh"
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
      "lines": "23-27"
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
      "zone": {
        "equals": "app"
      },
      "service": {
        "equals": "ssh"
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
      "lines": "33-37"
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
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "ssh"
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
      "lines": "28-32"
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
      "zone": {
        "equals": "mgmt"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "19-25"
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
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "privilege": "SUPERUSER",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "16-20"
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
      "lines": "21-25"
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
        "equals": "mgmt"
      },
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": "10-14"
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
      "zone": {
        "equals": "dmz"
      },
      "service": {
        "equals": "http"
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
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "16-20"
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
      "zone": {
        "equals": "app"
      },
      "service": {
        "equals": "app"
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
      "task": "Firewall — allow app port from web subnet",
      "lines": "26-32"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "10-15"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "10-15"
    }
  },
  {
    "id": "rule-013",
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "10-15"
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
    "id": "rule-016",
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
    "id": "rule-017",
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
    "id": "rule-018",
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
    "id": "rule-019",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
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
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-020",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "http"
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
  },
  {
    "id": "rule-021",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "app"
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "product": "openssh",
    "cve_id": "CVE-2000-0999",
    "title": "OpenBSD SSH - Buffer Overflow",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "type": "critical_remote",
    "remediation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2001-0144",
    "title": "CORE SDI SSH1 CRC-32 - Command Injection",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "type": "critical_remote",
    "remediation": "Update to the latest version or apply security patches addressing the integer overflow issue."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2000-0525",
    "title": "OpenSSH - Privilege Escalation",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "type": "critical_remote",
    "remediation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option."
  },
  {
    "product": "log4j",
    "cve_id": "CVE-2021-44228",
    "title": "Apache Log4j2 - JNDI Injection",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "type": "critical_remote",
    "remediation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default."
  },
  {
    "product": "log4j",
    "cve_id": "CVE-2022-23305",
    "title": "Log4j - SQL Injection",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "type": "critical_remote",
    "remediation": "Upgrade to Log4j 2.0-beta8 or later, which supports parameterized queries and enhances security."
  },
  {
    "product": "log4j",
    "cve_id": "CVE-2020-9493",
    "title": "Apache Chainsaw - Insecure Deserialization",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "type": "critical_remote",
    "remediation": "Update to version 2.1.0 or later."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2007-3279",
    "title": "PostgreSQL - Privilege Escalation",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "type": "critical_remote",
    "remediation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2002-1399",
    "title": "PostgreSQL - Integer Overflow",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "type": "critical_remote",
    "remediation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2024-1597",
    "title": "pgjdbc - SQL Injection",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "type": "critical_remote",
    "remediation": "Update to version 42.7.2 or later."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC policy mined from the Ansible configuration for **ChainCorp**'s production environment (PCI compliance tier). The configuration covers 4 hosts across 4 zones with 3 user accounts and 14 access control rules.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | chaincorp |
| Environment | production |
| Compliance Tier | pci |
| Log Retention | 365 days |

## Hosts and Resources

### Hosts (4 total)

| Hostname | IP | Role | Zone |
|----------|-----|------|------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt |
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| app01.lab.local | 10.0.2.10 | application | app |
| db01.lab.local | 10.0.3.10 | primary | data |

### Services (4 total)

| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| ssh | 22 | tcp | all |
| http | 80 | tcp | webservers |
| app | 8080 | tcp | appservers |
| postgresql | 5432 | tcp | dbservers |

## Subjects

### Users (3 total)

| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |

### Groups

- `sudo` - Administrative access
- `developers` - Application development access
- `dba` - Database administration access

## Access Control Rules (14 total)

### SSH Access Rules

| Rule | Subject | Resource | Action |
|------|---------|----------|--------|
| rule-001 | groups: sudo, dba | zone: mgmt | ssh:login |
| rule-002 | groups: sudo | zone: dmz | ssh:login |
| rule-003 | groups: sudo, developers | zone: app | ssh:login |
| rule-004 | groups: sudo, dba | zone: data | ssh:login |

### Privilege Escalation Rules

| Rule | Subject | Resource | Action |
|------|---------|----------|--------|
| rule-005 | groups: sudo AND clearance: secret | zone: mgmt | sudo:execute |

### Database Access Rules

| Rule | Subject | Resource | Action |
|------|---------|----------|--------|
| rule-006 | groups: dba | zone: data, postgresql | db:login (SUPERUSER) |

### Network Policy Rules

| Rule | Source | Destination | Action |
|------|--------|-------------|--------|
| rule-007 | 10.0.2.0/24 (app) | zone: data, port: 5432 | network:connect |
| rule-008 | 0.0.0.0/0 (internet) | zone: mgmt, port: 22 | network:connect |
| rule-009 | 10.0.0.0/24 (mgmt) | zone: dmz, port: 80 | network:connect |
| rule-010 | 10.0.1.0/24 (dmz) | zone: app, port: 8080 | network:connect |

### Filesystem Rules

| Rule | Subject | Resource | Action |
|------|---------|----------|--------|
| rule-011 | user: postgres | /var/lib/postgresql/data | filesystem:read |
| rule-012 | user: postgres | /var/lib/postgresql/data | filesystem:write |
| rule-013 | user: postgres | /var/lib/postgresql/data | filesystem:execute |

### Default Deny

| Rule | Subject | Resource | Action |
|------|---------|----------|--------|
| rule-014 | all | all | * |

## Vulnerability Assessment

### Critical Remote Vulnerabilities Found (9 total)

#### OpenSSH (3 vulnerabilities)
| CVE | Title | CVSS |
|-----|-------|------|
| CVE-2000-0999 | OpenBSD SSH - Buffer Overflow | 10.0 |
| CVE-2001-0144 | CORE SDI SSH1 CRC-32 - Command Injection | 10.0 |
| CVE-2000-0525 | OpenSSH - Privilege Escalation | 10.0 |

#### Log4j (3 vulnerabilities)
| CVE | Title | CVSS |
|-----|-------|------|
| CVE-2021-44228 | Apache Log4j2 - JNDI Injection | 10.0 |
| CVE-2022-23305 | Log4j - SQL Injection | 9.8 |
| CVE-2020-9493 | Apache Chainsaw - Insecure Deserialization | 9.8 |

#### PostgreSQL (3 vulnerabilities)
| CVE | Title | CVSS |
|-----|-------|------|
| CVE-2007-3279 | PostgreSQL - Privilege Escalation | 10.0 |
| CVE-2002-1399 | PostgreSQL - Integer Overflow | 10.0 |
| CVE-2024-1597 | pgjdbc - SQL Injection | 10.0 |

### Pinned Software Versions (Known Vulnerable)

| Package | Version | Source |
|---------|---------|--------|
| openssh (bastion) | 1:9.1p1-1ubuntu1 | group_vars/all.yml |
| openssh (general) | 1:9.9p1-3ubuntu1 | group_vars/all.yml |
| httpd | 2.4.49-1 | group_vars/all.yml |
| log4j | 2.14.1 | group_vars/all.yml |
| postgresql | 9.2.3-1.pgdg20.04+1 | group_vars/all.yml |

## Security Observations

### Positive Findings
1. SSH access is properly restricted by group membership per zone
2. Bastion sudo access requires secret clearance level
3. Database access is limited to dba group with SUPERUSER privileges
4. Network segmentation follows tiered architecture (mgmt → dmz → app → data)
5. PostgreSQL data directory has restrictive permissions (0700)

### Areas of Concern
1. **Bastion SSH exposed to internet** (0.0.0.0/0) - high-risk attack surface
2. **Log4j version 2.14.1** is known vulnerable to Log4Shell (CVE-2021-44228)
3. **PostgreSQL 9.2.3** is an extremely old version with known vulnerabilities
4. **OpenSSH 9.1p1 on bastion** is deliberately vulnerable per config comments
5. **Apache httpd 2.4.49** may have unpatched vulnerabilities

### Ambiguities
1. No explicit session logging or audit obligations defined in tasks
2. Credentials management not visible in configuration (likely handled externally)
3. No SELinux policy rules found in configuration
4. No monitoring/monitoring access rules defined

## Recommendations

1. **Immediate**: Update Log4j to version 2.17.1 or later
2. **High**: Upgrade PostgreSQL to a supported version (14.x+)
3. **High**: Update OpenSSH on bastion to latest stable version
4. **Medium**: Restrict bastion SSH access to specific IP ranges instead of 0.0.0.0/0
5. **Low**: Add session logging obligations to access rules

---
*Report generated from ABAC policy mining of Ansible configuration*
