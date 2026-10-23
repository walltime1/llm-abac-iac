# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:21:44_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 13 | Rules: 22_  
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
      },
      {
        "name": "postgres",
        "uid": 999,
        "groups": [
          "dba"
        ],
        "department": "system",
        "clearance": "system",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "dba",
      "dba"
    ],
    "clearance_levels": [
      "secret",
      "confidential",
      "system"
    ],
    "departments": [
      "operations",
      "engineering",
      "data"
    ]
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
        "source": "roles/bastion/tasks/main.yml,roles/app/tasks/main.yml,roles/web/tasks/main.yml,roles/db/tasks/main.yml"
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
        "source": "roles/db/tasks/main.yml"
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "sshd",
        "source": "roles/bastion/tasks/main.yml,roles/app/tasks/main.yml,roles/web/tasks/main.yml,roles/db/tasks/main.yml"
      },
      {
        "path": "/opt/app/app.jar",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "application",
        "source": "roles/app/tasks/main.yml"
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
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "db-subnet",
        "source": "inventory.ini"
      }
    ]
  },
  "environment": {
    "org": "chaincorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "description": "SSH login to bastion for sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "id": "rule-002",
    "description": "SSH login to bastion for dba group",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "id": "rule-003",
    "description": "SSH login to web server for sudo group",
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        16,
        19
      ]
    }
  },
  {
    "id": "rule-004",
    "description": "SSH login to app server for sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        19,
        22
      ]
    }
  },
  {
    "id": "rule-005",
    "description": "SSH login to app server for developers group",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        19,
        22
      ]
    }
  },
  {
    "id": "rule-006",
    "description": "SSH login to DB server for sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        18,
        21
      ]
    }
  },
  {
    "id": "rule-007",
    "description": "SSH login to DB server for dba group",
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
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        18,
        21
      ]
    }
  },
  {
    "id": "rule-008",
    "description": "Sudo on bastion for secret-clearance sudo members",
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
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "obligations": [
      {
        "type": "audit_log",
        "description": "All sudo commands must be logged"
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        18,
        24
      ]
    }
  },
  {
    "id": "rule-009",
    "description": "PostgreSQL SUPERUSER login for DBA group",
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
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        10,
        14
      ]
    }
  },
  {
    "id": "rule-010",
    "description": "Firewall: allow SSH from any source to bastion",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        13,
        17
      ]
    }
  },
  {
    "id": "rule-011",
    "description": "Firewall: allow HTTP from bastion subnet to web server",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        12,
        16
      ]
    }
  },
  {
    "id": "rule-012",
    "description": "Firewall: allow app port from web subnet to app server",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        13,
        18
      ]
    }
  },
  {
    "id": "rule-013",
    "description": "pg_hba: allow PostgreSQL connections from app subnet",
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        15,
        17
      ]
    }
  },
  {
    "id": "rule-014",
    "description": "Filesystem read/write for postgres group on data directory",
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        6,
        10
      ]
    }
  },
  {
    "id": "rule-015",
    "description": "Filesystem write for postgres group on data directory",
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        6,
        10
      ]
    }
  },
  {
    "id": "rule-016",
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
    "action": "*",
    "effect": "deny",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
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
      "environment": {
        "equals": "production"
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
    "id": "rule-019",
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
      "port": {
        "equals": 80
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
    "id": "rule-022",
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
      "environment": {
        "equals": "production"
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
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Update to OpenSSH version 3.7 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": true,
    "recommendation": "Upgrade to Log4j 2.0-beta8 or later, which supports parameterized queries and enhances security.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": true,
    "recommendation": "Update to version 2.1.0 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of Log4j 1.2 or upgrade to Log4j 2.x.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": true,
    "recommendation": "Update to Log4j 2.8.2 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Update to version 42.7.2 or later.",
    "source": "group_vars/all.yml"
  }
]
```

## Report

# ABAC Policy Report — ChainCorp Production Infrastructure

## Overview

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration for ChainCorp's production environment (`compliance_tier=pci`). The policy was derived from inventory definitions, group variables, and four role task files covering bastion, web, application, and database tiers.

**Environment:** ChainCorp production · PCI compliance · 365-day log retention

## Attribute Catalog Summary

### Subjects
- **3 users:** admin (sudo/ops/secret), developer (developers/eng/confidential), dba (dba/data/secret)
- **3 groups:** sudo, developers, dba
- **Clearance levels:** secret, confidential
- **Departments:** operations, engineering, data

### Resources
- **4 hosts:** bastion01 (mgmt), web01 (dmz), app01 (app), db01 (data)
- **4 services:** SSH (22/tcp), HTTP (80/tcp), App (8080/tcp), PostgreSQL (5432/tcp)
- **Key paths:** /var/lib/postgresql/data (0700, postgres:postgres), /etc/ssh/sshd_config
- **Network zones:** internet (0.0.0.0/0), mgmt (10.0.0.0/24), dmz (10.0.1.0/24), app (10.0.2.0/24), data (10.0.3.0/24)

## Rule Summary

| # | Action | Subject | Resource | Effect |
|---|--------|---------|----------|--------|
| rule-001 | ssh:login | sudo group | bastion01 | permit |
| rule-002 | ssh:login | dba group | bastion01 | permit |
| rule-003 | ssh:login | sudo group | web01 | permit |
| rule-004 | ssh:login | sudo group | app01 | permit |
| rule-005 | ssh:login | developers group | app01 | permit |
| rule-006 | ssh:login | sudo group | db01 | permit |
| rule-007 | ssh:login | dba group | db01 | permit |
| rule-008 | sudo:execute | sudo + secret clearance | bastion01 | permit |
| rule-009 | db:login | dba group | PostgreSQL on db01 | permit |
| rule-010 | network:connect | 0.0.0.0/0 | bastion01:22 | permit |
| rule-011 | network:connect | 10.0.0.0/24 | web01:80 | permit |
| rule-012 | network:connect | 10.0.1.0/24 | app01:8080 | permit |
| rule-013 | network:connect | 10.0.2.0/24 | db01:5432 | permit |
| rule-014 | filesystem:read | dba group | /var/lib/postgresql/data | permit |
| rule-015 | filesystem:write | dba group | /var/lib/postgresql/data | permit |
| rule-016 | * | all | all | **deny** |

**Total: 16 rules (15 permit + 1 default-deny)**

## Vulnerability Assessment

### Critical Findings

| CVE | Product | Severity | CVSS | Affects Pinned? | Recommendation |
|-----|---------|----------|------|-----------------|----------------|
| CVE-2003-0786 | openssh | critical | 10.0 | ✅ | Upgrade OpenSSH on bastion from 9.1p1 |
| CVE-2000-0999 | openssh | critical | 10.0 | ✅ | Upgrade OpenSSH on bastion from 9.1p1 |
| CVE-2000-0525 | openssh | critical | 10.0 | ✅ | Upgrade OpenSSH on bastion from 9.1p1 |
| CVE-2001-0144 | openssh | critical | 10.0 | ✅ | Upgrade OpenSSH on bastion from 9.1p1 |
| CVE-2003-0693 | openssh | critical | 10.0 | ✅ | Upgrade OpenSSH on bastion from 9.1p1 |
| CVE-2021-44228 | log4j | critical | 10.0 | ✅ | Upgrade Log4j from 2.14.1 to 2.17.1+ (Log4Shell) |
| CVE-2022-23305 | log4j | critical | 9.8 | ✅ | Upgrade Log4j from 2.14.1 |
| CVE-2020-9493 | log4j | critical | 9.8 | ✅ | Upgrade Log4j from 2.14.1 |
| CVE-2019-17571 | log4j | critical | 9.8 | ✅ | Upgrade Log4j from 2.14.1 |
| CVE-2017-5645 | log4j | critical | 9.8 | ✅ | Upgrade Log4j from 2.14.1 |
| CVE-2007-3279 | postgresql | critical | 10.0 | ✅ | Upgrade PostgreSQL from 9.2.3 |
| CVE-2002-1399 | postgresql | critical | 10.0 | ✅ | Upgrade PostgreSQL from 9.2.3 |
| CVE-2013-1903 | postgresql | critical | 10.0 | ✅ | Upgrade PostgreSQL from 9.2.3 |
| CVE-2013-1902 | postgresql | critical | 10.0 | ✅ | Upgrade PostgreSQL from 9.2.3 |
| CVE-2024-1597 | postgresql | critical | 10.0 | ✅ | Upgrade PostgreSQL from 9.2.3 |

**No critical/remote vulnerabilities found for Apache httpd 2.4.49 in this scan.**

### Risk Summary
- **15 vulnerabilities** identified across 3 of 4 pinned packages
- **All affect pinned versions** — the configuration deliberately deploys vulnerable software
- Highest-risk: Log4j 2.14.1 (CVE-2021-44228, Log4Shell) and PostgreSQL 9.2.3 (end-of-life, multiple CVEs)

## Ambiguities and Notes

1. **Deliberately vulnerable packages:** The group_vars explicitly note "Every hop has a deliberately vulnerable package." This configuration is likely for a security lab or training environment, not production use.

2. **No credentials in files:** No plaintext passwords or API keys were found in the scanned files. Database authentication uses `scram-sha-256` per pg_hba configuration.

3. **Firewall deny rules:** The firewalld tasks only define explicit allow rules. Implicit deny is assumed by the firewall's default zone policy. The ABAC default-deny rule (rule-016) captures this semantic.

4. **HTTPD version 2.4.49:** This version is known to be vulnerable to CVE-2021-41773 (path traversal) and CVE-2021-42013 (RCE), but these were not returned by the critical/remote or KEV queries. Manual review recommended.

5. **SSH version scoping:** Bastion uses openssh 9.1p1 (vulnerable) while all other hosts use 9.9p1 (safe). Only the bastion-specific SSH CVEs are applicable.

6. **Filesystem rule scope:** The postgres data directory rule (0700) only permits the postgres owner/group (mapped to dba group). No explicit execute permission was defined since mode 0700 grants rwx to owner only, and the rule splits into separate read/write actions.

7. **Missing explicit deny rules:** The pg_hba configuration uses an implicit deny-default (entries not listed are denied). No explicit deny entries were found in any scanned file beyond the overall default-deny policy rule.
