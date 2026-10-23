# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 14:14:39_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 13 | Rules: 19_  
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
      }
    ],
    "user": {
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "type": "enum",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba",
        "postgres"
      ],
      "type": "set",
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "domain": [
        "confidential",
        "secret"
      ],
      "type": "enum",
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "type": "enum",
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "domain": [
        "0.0.0.0/0",
        "10.0.0.0/24",
        "10.0.1.0/24",
        "10.0.2.0/24"
      ],
      "type": "cidr",
      "source": "group_vars/bastion.yml, group_vars/webservers.yml, group_vars/appservers.yml, group_vars/dbservers.yml"
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
    "hostname": {
      "domain": [
        "bastion01.lab.local",
        "web01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "type": "enum",
      "source": "inventory.ini"
    },
    "role": {
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "type": "enum",
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "type": "enum",
      "source": "inventory.ini"
    },
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
    "service": {
      "domain": [
        "ssh",
        "http",
        "app",
        "postgresql"
      ],
      "type": "enum",
      "source": "group_vars/webservers.yml, group_vars/appservers.yml, group_vars/dbservers.yml, roles/bastion/tasks/main.yml"
    },
    "port": {
      "domain": [
        22,
        80,
        8080,
        5432
      ],
      "type": "integer",
      "source": "group_vars/webservers.yml, group_vars/appservers.yml, group_vars/dbservers.yml"
    },
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
    "path": {
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "type": "enum",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "domain": [
        "postgres"
      ],
      "type": "enum",
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "domain": [
        "postgres"
      ],
      "type": "enum",
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "domain": [
        "0700"
      ],
      "type": "enum",
      "source": "roles/db/tasks/main.yml"
    },
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet",
        "source": "group_vars/bastion.yml"
      },
      {
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "mgmt_subnet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web_subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet",
        "source": "group_vars/dbservers.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "name": "org",
      "domain": [
        "chaincorp"
      ],
      "type": "enum",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "name": "environment",
      "domain": [
        "production"
      ],
      "type": "enum",
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "name": "compliance_tier",
      "domain": [
        "pci"
      ],
      "type": "enum",
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "name": "default_log_retention_days",
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
    "description": "Allow SSH login on bastion host for sudo and dba groups",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "10-13"
    }
  },
  {
    "id": "rule-002",
    "description": "Allow SSH login on web hosts for sudo group",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "16-19"
    }
  },
  {
    "id": "rule-003",
    "description": "Allow SSH login on app hosts for sudo and developers groups",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "23-26"
    }
  },
  {
    "id": "rule-004",
    "description": "Allow SSH login on db hosts for sudo and dba groups",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "24-27"
    }
  },
  {
    "id": "rule-005",
    "description": "Allow sudo on bastion only for users with sudo group AND secret clearance (password required)",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "authentication",
        "description": "Password required (nopassword: false)"
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "19-25"
    }
  },
  {
    "id": "rule-006",
    "description": "Allow SSH network connections to bastion from internet (0.0.0.0/0)",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall - allow SSH from internet",
      "lines": "15-19"
    }
  },
  {
    "id": "rule-007",
    "description": "Allow HTTP network connections to web hosts from mgmt subnet (10.0.0.0/24)",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall - allow HTTP from bastion subnet",
      "lines": "11-16"
    }
  },
  {
    "id": "rule-008",
    "description": "Allow app port network connections to app hosts from web subnet (10.0.1.0/24)",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall - allow app port from web subnet",
      "lines": "17-22"
    }
  },
  {
    "id": "rule-009",
    "description": "Allow DBA group members superuser database login on db hosts",
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
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "14-17"
    }
  },
  {
    "id": "rule-010",
    "description": "Allow PostgreSQL network connections from app subnet (10.0.2.0/24)",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "19-21"
    }
  },
  {
    "id": "rule-011",
    "description": "Deny PostgreSQL network connections from outside app subnet (pg_hba deny-default)",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet (implicit deny)",
      "lines": "19-21"
    }
  },
  {
    "id": "rule-012",
    "description": "Allow filesystem read access to postgres data directory for postgres group",
    "subject_condition": {
      "groups": {
        "equals": "postgres"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "9-14"
    }
  },
  {
    "id": "rule-013",
    "description": "Allow filesystem write access to postgres data directory for postgres group",
    "subject_condition": {
      "groups": {
        "equals": "postgres"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "9-14"
    }
  },
  {
    "id": "rule-014",
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
    "id": "rule-015",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
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
    "id": "rule-016",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
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
    "id": "rule-018",
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
    "id": "rule-019",
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
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": true,
    "description": "Apache Log4j2 <=2.14.1 JNDI remote code execution (Log4Shell)",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to Log4j 2.17.1 or later immediately. This is a critical RCE actively exploited in the wild.",
    "source": "group_vars/all.yml (log4j_version: 2.14.1), roles/app/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 9.2.x before 9.2.4 generates insecure random numbers for session keys",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to version 15.x or later. Version 9.2.3 is end-of-life and has multiple critical vulnerabilities.",
    "source": "group_vars/all.yml (postgres_version: 9.2.3-1.pgdg20.04+1), roles/db/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2021-41773",
    "product": "apache-httpd",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "description": "Apache HTTP Server 2.4.49 path traversal leading to remote code execution",
    "affects_pinned_version": true,
    "recommendation": "Upgrade Apache httpd to version 2.4.51 or later. Version 2.4.49 has a critical path traversal vulnerability.",
    "source": "group_vars/all.yml (httpd_version: 2.4.49-1), roles/web/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH ssh-agent PKCS#11 agent forwarding allows remote code execution via library loading",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH on bastion to version 9.9p1 or later (matching the version used on other hosts).",
    "source": "group_vars/all.yml (ssh_version_bastion: 1:9.1p1-1ubuntu1), roles/bastion/tasks/main.yml"
  }
]
```

## Report

# ABAC Policy Mining Report — ChainCorp Ansible Infrastructure

## 1. Executive Summary

An Attribute-Based Access Control (ABAC) policy was mined from the Ansible configuration for the ChainCorp production environment. The policy covers 4 hosts, 3 users, and 4 services across 4 network zones. **Four critical vulnerabilities** were identified in pinned software versions, including the infamous Log4Shell (CVE-2021-44228).

## 2. Attribute Catalog

### Subjects
- **Users**: admin (sudo/operations/secret), developer (developers/engineering/confidential), dba (dba/data/secret)
- **Groups**: sudo, developers, dba, postgres
- **Clearance Levels**: confidential, secret
- **Departments**: operations, engineering, data
- **Source Networks**: 0.0.0.0/0 (internet), 10.0.0.0/24 (mgmt), 10.0.1.0/24 (dmz/web), 10.0.2.0/24 (app)

### Resources
- **Hosts**: bastion01 (mgmt/bastion), web01 (dmz/frontend), app01 (app/application), db01 (data/primary)
- **Services**: ssh (22/tcp), http (80/tcp), app (8080/tcp), postgresql (5432/tcp)
- **Paths**: /var/lib/postgresql/data (owner=postgres, group=postgres, mode=0700)

### Environment
- **Org**: chaincorp
- **Environment**: production
- **Compliance Tier**: pci
- **Log Retention**: 365 days

## 3. Policy Rules (14 rules)

### SSH Access Control (rules 001–004)
| Rule | Host | Allowed Groups | Source |
|------|------|----------------|--------|
| 001 | bastion01 | sudo, dba | bastion/tasks/main.yml |
| 002 | web01 | sudo | web/tasks/main.yml |
| 003 | app01 | sudo, developers | app/tasks/main.yml |
| 004 | db01 | sudo, dba | db/tasks/main.yml |

### Sudo Access (rule 005)
| Rule | Host | Condition | Note |
|------|------|-----------|------|
| 005 | bastion01 | groups=sudo AND clearance=secret | Password required (nopassword: false) |

### Network Firewall (rules 006–010)
| Rule | Source Network | Destination | Port | Effect |
|------|---------------|-------------|------|--------|
| 006 | 0.0.0.0/0 | bastion01 | 22/tcp (SSH) | permit |
| 007 | 10.0.0.0/24 | web01 | 80/tcp (HTTP) | permit |
| 008 | 10.0.1.0/24 | app01 | 8080/tcp (app) | permit |
| 010 | 10.0.2.0/24 | db01 | 5432/tcp (PostgreSQL) | permit |

### Database Access (rule 009)
| Rule | Subject | Host | Privilege | Effect |
|------|---------|------|-----------|--------|
| 009 | dba group | db01 | SUPERUSER LOGIN | permit |

### Implicit Deny (rules 011, 014)
- Rule 011: Deny PostgreSQL network connections from outside app subnet (pg_hba deny-default)
- Rule 014: Global default-deny

### Filesystem Access (rules 012–013)
| Rule | Path | Subject | Action |
|------|------|---------|--------|
| 012 | /var/lib/postgresql/data | postgres group | filesystem:read |
| 013 | /var/lib/postgresql/data | postgres group | filesystem:write |

## 4. Vulnerability Assessment

### Critical Vulnerabilities in Pinned Packages

| CVE | Product | Pinned Version | Severity | CVSS | KEV | Affects Pinned? |
|-----|---------|---------------|----------|------|-----|-----------------|
| CVE-2021-44228 | Log4j | 2.14.1 | Critical | 10.0 | Yes | Yes |
| CVE-2021-41773 | Apache httpd | 2.4.49-1 | Critical | 9.8 | Yes | Yes |
| CVE-2013-1903 | PostgreSQL | 9.2.3-1 | Critical | 9.8 | No | Yes |
| CVE-2023-38408 | OpenSSH (bastion) | 9.1p1 | High | 8.1 | No | Yes |

### Recommendations
1. **Log4j (CVE-2021-44228)**: Upgrade to Log4j 2.17.1+ immediately. Log4Shell is actively exploited in the wild with known ransomware use.
2. **Apache httpd (CVE-2021-41773)**: Upgrade to 2.4.51+. Path traversal in 2.4.49 allows RCE.
3. **PostgreSQL (CVE-2013-1903)**: Upgrade to PostgreSQL 15.x+. Version 9.2.3 is end-of-life with multiple critical flaws.
4. **OpenSSH (CVE-2023-38408)**: Upgrade bastion OpenSSH from 9.1p1 to 9.9p1+ to match other hosts.

## 5. Ambiguities and Observations

1. **Bastion SSH open to internet**: The bastion allows SSH from 0.0.0.0/0, which is a significant attack surface. Consider restricting to known management subnets.
2. **Sudo restriction is bastion-only**: The sudoers configuration with clearance checks only applies to the bastion host. No sudo restrictions are defined for other hosts, meaning any sudo group member has unrestricted sudo elsewhere.
3. **`postgres` group not in user list**: The filesystem rule for /var/lib/postgresql/data references the `postgres` group, which is a system account not listed in the users list from group_vars/all.yml. This is an OS-level user, not a human subject.
4. **No credentials management**: The Ansible config does not appear to manage SSH keys, passwords, or secrets directly — these may be managed externally.
5. **HTTP access limited to mgmt subnet**: Web hosts only accept HTTP from 10.0.0.0/24 (bastion/mgmt subnet), not from the internet. This suggests the bastion may serve as a reverse proxy or the web hosts are not publicly accessible.
6. **PCI compliance**: The environment is flagged as PCI compliance tier, which has specific requirements for access control logging and data protection that should be verified against the policy.
7. **No session logging/audit obligations observed**: The Ansible config does not include explicit session logging or audit configuration tasks.
