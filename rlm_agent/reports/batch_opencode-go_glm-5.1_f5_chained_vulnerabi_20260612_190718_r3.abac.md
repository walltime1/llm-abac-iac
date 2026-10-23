# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 19:56:07_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 17 | Rules: 19_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subject": {
    "user": {
      "type": "string",
      "description": "System username",
      "domain": [
        "admin",
        "developer",
        "dba",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "description": "User ID number",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "description": "User groups membership",
      "domain": [
        "sudo",
        "developers",
        "dba",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "string",
      "description": "User security clearance level",
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "string",
      "description": "User department",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "type": "string",
      "description": "Source network CIDR for firewall rules",
      "source": "group_vars/bastion.yml"
    },
    "source_zone": {
      "type": "string",
      "description": "Source network zone label",
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "applies_to": {
      "type": "string",
      "description": "Catch-all sentinel for default-deny rules",
      "domain": [
        "all"
      ],
      "source": "derived"
    }
  },
  "resource": {
    "hostname": {
      "type": "string",
      "description": "Target host FQDN",
      "domain": [
        "bastion01.lab.local",
        "web01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "description": "Target host IP address",
      "source": "inventory.ini"
    },
    "role": {
      "type": "string",
      "description": "Host role",
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "string",
      "description": "Network zone",
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "inventory_group": {
      "type": "string",
      "description": "Ansible inventory group",
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "string",
      "description": "Service or daemon name",
      "domain": [
        "ssh",
        "http",
        "app",
        "postgresql",
        "sudo"
      ],
      "source": "roles/*/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "description": "Network port number",
      "source": "group_vars/webservers.yml"
    },
    "path": {
      "type": "string",
      "description": "Filesystem path",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "string",
      "description": "Filesystem path owner user",
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "string",
      "description": "Filesystem path owner group",
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "description": "Filesystem path permission mode",
      "domain": [
        "0700",
        "0755",
        "0644",
        "0600"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "applies_to": {
      "type": "string",
      "description": "Catch-all sentinel for default-deny rules",
      "domain": [
        "all"
      ],
      "source": "derived"
    }
  },
  "environment": {
    "org": {
      "type": "string",
      "description": "Organization name",
      "domain": [
        "chaincorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "string",
      "description": "Deployment environment",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "string",
      "description": "Compliance classification",
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml"
    },
    "applies_to": {
      "type": "string",
      "description": "Catch-all sentinel for unscoped rules",
      "domain": [
        "all"
      ],
      "source": "derived"
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
          "dba"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "7-9"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
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
      "task": "Firewall - allow SSH from internet",
      "lines": "11-15"
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "17-21"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "18-21"
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
      "hostname": {
        "equals": "app01.lab.local"
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
      "task": "Firewall - allow app port from web subnet",
      "lines": "13-17"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "17-20"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "10-13"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
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
      "lines": "14-16"
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
      "hostname": {
        "equals": "db01.lab.local"
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
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "pg_hba implicit deny-default",
      "lines": "14-16"
    }
  },
  {
    "id": "rule-010",
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
      "lines": "6-11"
    }
  },
  {
    "id": "rule-011",
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "6-11"
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "11-14"
    }
  },
  {
    "id": "rule-013",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
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
      "task": "Firewall - allow HTTP from bastion subnet",
      "lines": "7-11"
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
    "id": "rule-018",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell). Affects Log4j versions 2.0-beta9 through 2.14.1",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to version 2.17.1 or later immediately. This is a critical RCE actively exploited in the wild."
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Apache Log4j socket server deserialization RCE. Affects versions before 2.8.2",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Already fixed in pinned version 2.14.1. No action needed for this CVE."
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Apache Log4j SMTP appender deserialization RCE. Affects 2.0.0 to 2.14.1",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to version 2.15.0 or later to fix deserialization vulnerability in SMTP appender."
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Log4j JDBCAppender SQL injection. Affects versions before 2.17.1",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to version 2.17.1 or later. SQL injection in JDBCAppender allows code execution."
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Log4j SocketServer deserialization RCE in 1.2 and 2.x before 2.8.2",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Already fixed in pinned version 2.14.1. No action needed for this CVE."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "PostgreSQL 8.1+ grants plpgsql privileges to PUBLIC, allowing privilege escalation",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Revoke default PUBLIC privileges on plpgsql language. Apply manual REVOKE or upgrade."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "PostgreSQL 9.2.x before 9.2.4 random number generator issue",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to 9.2.4 or later. Pinned version 9.2.3 is directly affected."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "PostgreSQL before 9.2.4 insecure temporary file handling",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to 9.2.4 or later. Insecure temp file handling in pinned version."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "PostgreSQL 7.2.1 and earlier unknown vulnerability",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Does not affect pinned version 9.2.3 (only 7.2.1 and earlier). No action needed."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "pgjdbc SQL injection via line comment generation. Affects JDBC driver, not server",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Affects the PostgreSQL JDBC driver (pgjdbc), not the server. Upgrade pgjdbc to 42.7.2+ if used."
  }
]
```

## Report

# ABAC Policy Mining Report - Ansible Infrastructure

## Overview

This report presents an Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration for organization **chaincorp**. The infrastructure consists of 4 hosts in a PCI-compliant production environment.

## Infrastructure Summary

| Host | IP | Role | Zone | Inventory Group |
|------|-----|------|------|----------------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt | bastion |
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

## Users

| Name | UID | Groups | Department | Clearance |
|------|-----|--------|------------|----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

## Policy Summary

- **Total Rules**: 14 (13 access rules + 1 default-deny)
- **Permit Rules**: 13
- **Deny Rules**: 1 (default-deny catch-all)

### Access Rules by Category

| Category | Count | Rules |
|----------|-------|-------|
| SSH Login | 4 | rule-001, rule-004, rule-006, rule-012 |
| Network/Firewall | 5 | rule-002, rule-005, rule-008, rule-009, rule-013 |
| Sudo | 1 | rule-003 |
| Database | 1 | rule-007 |
| Filesystem | 2 | rule-010, rule-011 |
| Default-Deny | 1 | rule-014 |

## Key Access Control Findings

### SSH Access (AllowGroups)

- **Bastion** (bastion01.lab.local): Groups `sudo` and `dba` may SSH in
- **App** (app01.lab.local): Groups `sudo` and `developers` may SSH in
- **DB** (db01.lab.local): Groups `sudo` and `dba` may SSH in
- **Web** (web01.lab.local): Only group `sudo` may SSH in

### Sudo Access

- **Bastion only**: Users in group `sudo` with `clearance=secret` may execute sudo (password required)
- Other hosts do not configure sudoers explicitly

### Database Access

- **PostgreSQL SUPERUSER**: Users in group `dba` are granted LOGIN+SUPERUSER roles
- **Network access**: PostgreSQL port 5432 only accepts connections from 10.0.2.0/24 (app subnet)
- **Implicit deny**: All other network sources are denied PostgreSQL connectivity

### Firewall Rules

| Source | Destination | Port | Service |
|--------|-------------|------|---------|
| 0.0.0.0/0 | bastion01 | 22/tcp | SSH |
| 10.0.0.0/24 | web01 | 80/tcp | HTTP |
| 10.0.1.0/24 | app01 | 8080/tcp | App |
| 10.0.2.0/24 | db01 | 5432/tcp | PostgreSQL |

### Filesystem Permissions

- `/var/lib/postgresql/data`: owner=postgres, group=postgres, mode=0700 (read+write for postgres group only)

## Vulnerability Assessment

### Critical Vulnerabilities Affecting Pinned Versions

| CVE | Product | Pinned Version | CVSS | Affects Pinned? |
|-----|---------|----------------|------|-----------------|
| CVE-2021-44228 | log4j | 2.14.1 | 10.0 | **YES** |
| CVE-2020-9493 | log4j | 2.14.1 | 9.8 | **YES** |
| CVE-2022-23305 | log4j | 2.14.1 | 9.8 | **YES** |
| CVE-2007-3279 | postgresql | 9.2.3 | 10.0 | **YES** |
| CVE-2013-1903 | postgresql | 9.2.3 | 10.0 | **YES** |
| CVE-2013-1902 | postgresql | 9.2.3 | 10.0 | **YES** |

### Not Affecting Pinned Version

| CVE | Product | Reason |
|-----|---------|--------|
| CVE-2017-5645 | log4j | Fixed before 2.14.1 |
| CVE-2019-17571 | log4j | Fixed before 2.14.1 |
| CVE-2002-1399 | postgresql | Only affects 7.2.1 and earlier |
| CVE-2024-1597 | postgresql | Affects JDBC driver, not server |

### Critical Recommendations

1. **Log4j 2.14.1 (App Server)**: Upgrade to 2.17.1+ immediately. CVE-2021-44228 (Log4Shell) is a CVSS 10.0 RCE actively exploited in the wild.
2. **PostgreSQL 9.2.3 (DB Server)**: Upgrade to at least 9.2.4. Three critical CVEs directly affect this version.
3. **Apache httpd 2.4.49 (Web Server)**: Version 2.4.49 is known to be vulnerable to path traversal (CVE-2021-41773). Upgrade recommended.
4. **OpenSSH 9.1p1 (Bastion)**: Monitor for advisories; the configuration pins a specific version that may have vulnerabilities.

## Ambiguities

1. **Credentials**: The Ansible configuration does not explicitly manage credentials/secrets. Database user passwords, SSH keys, and API tokens are not defined.
2. **Apache httpd CVEs**: The vulnerability search tools did not return CVEs for httpd 2.4.49, but this version is widely known to be vulnerable (CVE-2021-41773, CVE-2021-42013). Manual verification recommended.
3. **Sudo on non-bastion hosts**: Only the bastion role explicitly configures sudoers. Other hosts may inherit default sudo behavior.
4. **PostgreSQL 'postgres' group**: The filesystem rule references group 'postgres' which is not in the users list but is a system account.
5. **Firewall default policy**: Only 'enabled' rules are defined. Default firewalld policy (deny-all) is assumed but not explicitly configured.
6. **Session logging / audit**: No explicit session logging or audit configuration was found in the Ansible roles.

## Compliance Notes (PCI)

- The environment is classified as `compliance_tier=pci`
- Default log retention is 365 days
- SSH access is restricted via AllowGroups on all hosts
- The bastion exposes SSH to the entire internet (0.0.0.0/0), which is a significant PCI concern
