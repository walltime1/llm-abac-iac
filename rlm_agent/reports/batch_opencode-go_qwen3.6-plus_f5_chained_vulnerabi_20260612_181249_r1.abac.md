# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:19:13_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 10 | Rules: 19_  
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
    "groups": {
      "values": [
        "sudo",
        "developers",
        "dba"
      ],
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "values": [
        "secret",
        "confidential"
      ],
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "values": [
        "operations",
        "engineering",
        "data"
      ],
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
        "source": "roles/bastion/tasks/main.yml"
      },
      {
        "name": "http",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "roles/app/tasks/main.yml"
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
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "group_vars/bastion.yml"
      },
      {
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "bastion-subnet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web-subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app-subnet",
        "source": "group_vars/dbservers.yml"
      }
    ]
  },
  "environment": {
    "org": "chaincorp",
    "environment": "production",
    "compliance_tier": "pci",
    "log_retention_days": 365,
    "source": "group_vars/all.yml"
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "SSH login to bastion restricted to sudo and dba groups",
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
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        7,
        11
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Network access to bastion SSH from any source",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "bastion"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        13,
        19
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Sudo execution on bastion for secret-clearance users in sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "bastion"
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
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "nopassword": false,
        "commands": "ALL"
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        21,
        28
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "SSH login to webservers restricted to sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        16,
        20
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Network access to webserver HTTP from bastion subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        10,
        15
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "SSH login to appservers restricted to sudo and developers groups",
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
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "lines": [
        22,
        26
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Network access to appserver port 8080 from web subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "application"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
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
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        17,
        21
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "PostgreSQL superuser login for dba group members",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "database": {
        "equals": "all"
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
    "obligations": [
      {
        "privilege_level": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        12,
        17
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Network access to PostgreSQL from appservers subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": [
        19,
        22
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "SSH login to dbservers restricted to sudo and dba groups",
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
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        24,
        28
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "Filesystem access to PostgreSQL data directory restricted to owner",
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
      "lines": [
        7,
        11
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "description": "Filesystem write to PostgreSQL data directory restricted to owner",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        7,
        11
      ]
    }
  },
  {
    "rule_id": "rule-013",
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
      "file": "policy",
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
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
    "id": "rule-002",
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
    "id": "rule-003",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
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
    "id": "rule-004",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
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
    "id": "rule-005",
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
    "id": "rule-006",
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
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "title": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP/JNDI endpoints (Log4Shell)",
    "recommendation": "Upgrade log4j to 2.17.0 or later. Immediately apply mitigations if upgrade not possible."
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 8.8,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "title": "Apache Log4j JDBC Appender deserialization of untrusted data",
    "recommendation": "Upgrade log4j to 2.17.1 or later to address JDBC appender deserialization vulnerability."
  },
  {
    "cve_id": "CVE-2022-23307",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "title": "Apache Log4j ScheduledThreadPoolExecutor deserialization vulnerability (CVE-2022-23307)",
    "recommendation": "Upgrade log4j to 2.17.1 or later. Remove JMSTask, Chainsaw, and SMTPAppender if not needed."
  },
  {
    "cve_id": "CVE-2021-41773",
    "product": "apache",
    "pinned_version": "2.4.49",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "title": "Apache HTTP Server 2.4.49 path traversal and file disclosure vulnerability",
    "recommendation": "Upgrade Apache httpd to 2.4.51 or later. This version is specifically vulnerable to path traversal."
  },
  {
    "cve_id": "CVE-2021-42013",
    "product": "apache",
    "pinned_version": "2.4.49",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "title": "Apache HTTP Server 2.4.49-2.4.51 path traversal and remote code execution",
    "recommendation": "Upgrade Apache httpd to 2.4.52 or later. CVE-2021-42013 is a more severe variant of CVE-2021-41773 with RCE."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "cvss_score": 6.5,
    "severity": "medium",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "title": "PostgreSQL 9.2.x denial of service via crafted SQL",
    "recommendation": "Upgrade PostgreSQL to latest supported version. PostgreSQL 9.2 is EOL since 2017."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "cvss_score": 6.5,
    "severity": "medium",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "title": "PostgreSQL 9.2.x privilege escalation via crafted SQL",
    "recommendation": "Upgrade PostgreSQL to latest supported version. PostgreSQL 9.2 is EOL since 2017."
  },
  {
    "cve_id": "CVE-2018-1058",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "cvss_score": 8.8,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "title": "PostgreSQL pg_catalog namespace manipulation allows user-controlled query execution",
    "recommendation": "Upgrade PostgreSQL. Restrict CREATE privilege in pg_catalog schema. PostgreSQL 9.2 is EOL."
  }
]
```

## Report

# ABAC Policy Report — Chaincorp Production Infrastructure

## Overview

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration manages a PCI-compliant production environment (`chaincorp`) across four host tiers: bastion, webservers, appservers, and dbservers.

**Policy Goal:** `all` (full coverage — SSH, sudo, DB access, firewall, filesystem)

## Attribute Catalog Summary

### Subjects
| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |

- **Groups:** sudo, developers, dba
- **Clearance Levels:** secret, confidential
- **Departments:** operations, engineering, data

### Resources
- **Hosts:** bastion01 (10.0.0.5, mgmt), web01 (10.0.1.10, dmz), app01 (10.0.2.10, app), db01 (10.0.3.10, data)
- **Services:** SSH (22/tcp), HTTP (80/tcp), App (8080/tcp), PostgreSQL (5432/tcp)
- **Paths:** /var/lib/postgresql/data (postgres:postgres, 0700)
- **Networks:** 0.0.0.0/0 (internet), 10.0.0.0/24 (mgmt), 10.0.1.0/24 (dmz), 10.0.2.0/24 (app)

### Environment
- **Org:** chaincorp
- **Environment:** production
- **Compliance Tier:** PCI
- **Log Retention:** 365 days

## Rules Summary

| ID | Action | Subject | Resource | Effect |
|----|--------|---------|----------|--------|
| rule-001 | ssh:login | groups in {sudo, dba} | role=bastion, port=22 | permit |
| rule-002 | network:connect | source_network=0.0.0.0/0 | role=bastion, port=22 | permit |
| rule-003 | sudo:execute | groups in {sudo} AND clearance=secret | role=bastion | permit |
| rule-004 | ssh:login | groups in {sudo} | role=frontend, port=22 | permit |
| rule-005 | network:connect | source_network=10.0.0.0/24 | role=frontend, port=80 | permit |
| rule-006 | ssh:login | groups in {sudo, developers} | role=application, port=22 | permit |
| rule-007 | network:connect | source_network=10.0.1.0/24 | role=application, port=8080 | permit |
| rule-008 | db:login | groups in {dba} | role=primary, port=5432, SUPERUSER | permit |
| rule-009 | network:connect | source_network=10.0.2.0/24 | role=primary, port=5432 | permit |
| rule-010 | ssh:login | groups in {sudo, dba} | role=primary, port=22 | permit |
| rule-011 | filesystem:read | user=postgres | path=/var/lib/postgresql/data, mode=0700 | permit |
| rule-012 | filesystem:write | user=postgres | path=/var/lib/postgresql/data, mode=0700 | permit |
| rule-013 | * | all | all | deny |

**Total:** 13 rules (12 permit, 1 default-deny)

## Vulnerability Findings

| CVE | Product | Pinned Version | CVSS | Severity | Affects | KEV |
|-----|---------|----------------|------|----------|---------|-----|
| CVE-2021-44228 | log4j | 2.14.1 | 10.0 | critical | YES | YES |
| CVE-2022-23305 | log4j | 2.14.1 | 8.8 | high | YES | NO |
| CVE-2022-23307 | log4j | 2.14.1 | 7.5 | high | YES | NO |
| CVE-2021-42013 | apache | 2.4.49 | 9.8 | critical | YES | NO |
| CVE-2021-41773 | apache | 2.4.49 | 7.5 | high | YES | NO |
| CVE-2018-1058 | postgresql | 9.2.3 | 8.8 | high | YES | NO |
| CVE-2013-1902 | postgresql | 9.2.3 | 6.5 | medium | YES | NO |
| CVE-2013-1903 | postgresql | 9.2.3 | 6.5 | medium | YES | NO |

### Critical Remediation Priority
1. **CVE-2021-44228 (Log4Shell, CVSS 10.0)** — Actively exploited (KEV). Upgrade log4j to >=2.17.0 immediately.
2. **CVE-2021-42013 (Apache RCE, CVSS 9.8)** — Path traversal to RCE on httpd 2.4.49. Upgrade to >=2.4.52.
3. **CVE-2018-1058 (PostgreSQL, CVSS 8.8)** — pg_catalog namespace manipulation. PostgreSQL 9.2 is EOL since 2017.

## Ambiguities and Notes

1. **System user "postgres" not in user catalog:** The filesystem rules (rule-011, rule-012) reference `user=postgres`, which is a PostgreSQL service account not listed in the `users` variable in `group_vars/all.yml`. This is common for daemon accounts but means the subject catalog is incomplete for system users.

2. **Bastion SSH open to internet (0.0.0.0/0):** Rule-002 permits SSH from any source to the bastion. While the bastion role is expected to be internet-facing, this is an unusually permissive rule for a PCI environment. Access relies on SSH key authentication and `AllowGroups` restriction (rule-001).

3. **No explicit DENY rules for pg_hba:** The pg_hba.conf entries only permit connections from 10.0.2.0/24. PostgreSQL's default behavior for unmatched entries is to deny, which is captured by the default-deny rule (rule-013).

4. **Vulnerable packages deliberately pinned:** The Ansible configuration explicitly pins vulnerable package versions with comments noting they are "vulnerable." This appears intentional (possibly for testing/CTF purposes).

5. **No credentials management rules found:** No Ansible tasks manage API keys, passwords, or certificates in this configuration. Credentials may be managed externally (e.g., Vault).

6. **No SELinux rules:** No SELinux boolean or policy tasks were found in the role configurations.