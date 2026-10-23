# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 23:34:34_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 16 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "type": "scalar",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "scalar",
      "domain": [
        1001,
        1002,
        1003
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "scalar",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "scalar",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "type": "scalar",
      "domain": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/appservers.yml, group_vars/dbservers.yml, group_vars/dmz.yml"
    },
    "source_zone": {
      "type": "scalar",
      "domain": [
        "dmz",
        "app",
        "data",
        "internet"
      ],
      "source": "inventory.ini"
    }
  },
  "resources": {
    "hostname": {
      "type": "scalar",
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "scalar",
      "domain": [
        "10.0.1.10",
        "10.0.2.10",
        "10.0.3.10"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "type": "scalar",
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "scalar",
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "scalar",
      "domain": [
        "dmz",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "scalar",
      "domain": [
        "openssh-server",
        "postgresql",
        "nginx"
      ],
      "source": "roles/app/tasks/main.yml, roles/db/tasks/main.yml, roles/dmz/tasks/main.yml"
    },
    "port": {
      "type": "scalar",
      "domain": [
        443,
        5432,
        8080
      ],
      "source": "group_vars/dmz.yml, group_vars/dbservers.yml, group_vars/appservers.yml"
    },
    "protocol": {
      "type": "scalar",
      "domain": [
        "tcp"
      ],
      "source": "roles/app/tasks/main.yml, roles/db/tasks/main.yml, roles/dmz/tasks/main.yml"
    },
    "path": {
      "type": "scalar",
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "owner": {
      "type": "scalar",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "scalar",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "scalar",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "role_attr": {
      "type": "scalar",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "scalar",
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "scalar",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "scalar",
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "scalar",
      "domain": [
        365
      ],
      "source": "group_vars/all.yml"
    }
  },
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
    "sudo",
    "developers",
    "dba"
  ],
  "clearance_levels": [
    "secret",
    "confidential"
  ],
  "departments": [
    "operations",
    "engineering",
    "data"
  ],
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
      "name": "nginx",
      "port": 443,
      "protocol": "tcp",
      "host_group": "dmz",
      "source": "group_vars/dmz.yml"
    },
    {
      "name": "openssh-server",
      "port": 22,
      "protocol": "tcp",
      "host_group": "all",
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
      "cidr": "10.0.1.0/24",
      "zone": "dmz",
      "label": "DMZ subnet",
      "source": "group_vars/appservers.yml"
    },
    {
      "cidr": "10.0.2.0/24",
      "zone": "app",
      "label": "appservers subnet",
      "source": "group_vars/dbservers.yml"
    },
    {
      "cidr": "0.0.0.0/0",
      "zone": "internet",
      "label": "internet-facing",
      "source": "group_vars/dmz.yml"
    }
  ]
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "description": "Allow SSH login on appservers for sudo and developers groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "openssh-server"
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
      "lines": "17-20"
    }
  },
  {
    "id": "rule-002",
    "description": "Allow SSH login on dbservers for sudo and dba groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "openssh-server"
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
      "task": "Restrict SSH to sudo group",
      "lines": "29-32"
    }
  },
  {
    "id": "rule-003",
    "description": "Allow SSH login on DMZ hosts for sudo group only",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "service": {
        "equals": "openssh-server"
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
      "lines": "17-20"
    }
  },
  {
    "id": "rule-004",
    "description": "DBA group members get SUPERUSER database login on dbservers",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "role_attr": {
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
      "lines": "16-19"
    }
  },
  {
    "id": "rule-005",
    "description": "Developers group members get NOSUPERUSER database login on dbservers",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "role_attr": {
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
      "lines": "21-24"
    }
  },
  {
    "id": "rule-006",
    "description": "Allow network connections from DMZ subnet to appservers on port 8080/tcp",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      },
      "source_zone": {
        "equals": "dmz"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": "13-16"
    }
  },
  {
    "id": "rule-007",
    "description": "Allow network connections from internet to DMZ on port 443/tcp",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      },
      "source_zone": {
        "equals": "internet"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": "13-16"
    }
  },
  {
    "id": "rule-008",
    "description": "Allow PostgreSQL connections from appservers subnet to dbservers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      },
      "source_zone": {
        "equals": "app"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": "26-28"
    }
  },
  {
    "id": "rule-009",
    "description": "Deny PostgreSQL connections from networks other than appservers subnet",
    "subject_condition": {
      "source_zone": {
        "in": [
          "dmz",
          "data",
          "internet"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
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
      "task": "Allow postgres only from appservers subnet",
      "lines": "26-28"
    }
  },
  {
    "id": "rule-010",
    "description": "Postgres user can read/write/execute the data directory",
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
      "lines": "12-17"
    }
  },
  {
    "id": "rule-011",
    "description": "Non-postgres users denied access to data directory (mode 0700)",
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
    "action": "filesystem:write",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "12-17"
    }
  },
  {
    "id": "rule-012",
    "description": "Users with sudo or developers groups can be created on appservers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
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
      "lines": "7-11"
    }
  },
  {
    "id": "rule-013",
    "description": "Users with sudo group can be created on DMZ hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
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
      "lines": "10-14"
    }
  },
  {
    "id": "rule-999",
    "description": "Default deny - all access not explicitly permitted is denied",
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
      "file": "implicit",
      "task": "default-deny",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-1000",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
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
    "id": "rule-1001",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
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
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "description": "nginx resolver 1-byte memory overwrite via forged DNS UDP packets, causing worker process crash or potential code execution",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to 1.21.0 or later; apply vendor patch for CVE-2021-23017",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "description": "HTTP/2 rapid reset attack causing denial of service via stream cancellation",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to 1.25.3+ or apply HTTP/2 rapid reset mitigation patches",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.1p1-1ubuntu1",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "description": "OpenSSH regreSSHion - signal handler race condition leading to remote code execution as root",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to 9.8p1 or later; set LoginGraceTime=0 as temporary mitigation",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.1p1-1ubuntu1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "OpenSSH ssh-agent PKCS#11 feature allows remote code execution via library loading from forwarded agent",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to 9.3p2 or later; disable agent forwarding where not required",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "high",
    "cvss_score": 7.2,
    "is_remote": true,
    "description": "PostgreSQL COPY TO/FROM PROGRAM allows superusers to execute arbitrary OS commands",
    "affects_pinned_version": false,
    "recommendation": "Not affected - PostgreSQL 16.2 is outside the affected range (9.3-11.2); ensure superuser access is restricted per policy",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "description": "pgjdbc SQL injection via improper placeholder handling in PreferQueryMode=SIMPLE",
    "affects_pinned_version": false,
    "recommendation": "Not affected - CVE targets pgjdbc (JDBC driver), not PostgreSQL server; review JDBC driver versions if used",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "description": "pgjdbc SQL injection via unescaped column names in refreshRow() method",
    "affects_pinned_version": false,
    "recommendation": "Not affected - CVE targets pgjdbc (JDBC driver), not PostgreSQL server; review JDBC driver versions if used",
    "source": "kev"
  }
]
```

## Report

# ABAC Policy Mining Report — Ansible Configuration

## Executive Summary

This report presents an Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The policy covers SSH access, database authentication, network firewall rules, filesystem permissions, and user provisioning across three host groups: DMZ (reverse proxy), appservers (application tier), and dbservers (data tier).

## Environment Overview

- **Organization**: segcorp
- **Environment**: production
- **Compliance Tier**: PCI
- **Log Retention**: 365 days

## Host Inventory

| Hostname | IP | Role | Zone | Inventory Group |
|----------|-----|------|------|----------------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

## Users

| Name | UID | Groups | Department | Clearance |
|------|-----|--------|------------|----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

## Policy Rules Summary

### SSH Access (ssh:login)

| Rule | Host Group | Allowed Groups | Source |
|------|-----------|---------------|--------|
| rule-001 | appservers | sudo, developers | roles/app/tasks/main.yml |
| rule-002 | dbservers | sudo, dba | roles/db/tasks/main.yml |
| rule-003 | dmz | sudo | roles/dmz/tasks/main.yml |

### Database Access (db:login)

| Rule | Host Group | Subject Group | Privilege Level | Source |
|------|-----------|--------------|----------------|--------|
| rule-004 | dbservers | dba | SUPERUSER | roles/db/tasks/main.yml |
| rule-005 | dbservers | developers | NOSUPERUSER | roles/db/tasks/main.yml |

### Network Access (network:connect)

| Rule | Source Network | Source Zone | Destination | Port | Effect | Source |
|------|---------------|-------------|-------------|------|--------|--------|
| rule-006 | 10.0.1.0/24 | dmz | appservers | 8080/tcp | permit | roles/app/tasks/main.yml |
| rule-007 | 0.0.0.0/0 | internet | dmz | 443/tcp | permit | roles/dmz/tasks/main.yml |
| rule-008 | 10.0.2.0/24 | app | dbservers | 5432/tcp | permit | roles/db/tasks/main.yml |
| rule-009 | dmz/data/internet | - | dbservers | 5432/tcp | deny | roles/db/tasks/main.yml |

### Filesystem Access

| Rule | Path | Owner | Mode | Action | Effect | Source |
|------|------|-------|------|--------|--------|--------|
| rule-010 | /var/lib/postgresql/data | postgres | 0700 | filesystem:read | permit | roles/db/tasks/main.yml |
| rule-011 | /var/lib/postgresql/data | postgres | 0700 | filesystem:write | deny | roles/db/tasks/main.yml |

### User Provisioning

| Rule | Host Group | Subject Groups | Action | Source |
|------|-----------|---------------|--------|--------|
| rule-012 | appservers | sudo, developers | user:create | roles/app/tasks/main.yml |
| rule-013 | dmz | sudo | user:create | roles/dmz/tasks/main.yml |

### Default Deny

| Rule | Action | Effect |
|------|--------|--------|
| rule-999 | * | deny |

## Vulnerability Assessment

### Pinned Software Versions

| Package | Pinned Version | Source |
|---------|---------------|--------|
| nginx | 1.20.0-1~focal | group_vars/all.yml |
| openssh-server | 9.1p1-1ubuntu1 | group_vars/all.yml |
| postgresql-16 | 16.2-1.pgdg22.04+1 | group_vars/all.yml |

### Critical/High Vulnerabilities Affecting Pinned Versions

| CVE | Product | Severity | CVSS | Affects Pinned | Recommendation |
|-----|---------|----------|------|---------------|----------------|
| CVE-2021-23017 | nginx | high | 7.7 | **Yes** | Upgrade nginx to 1.21.0+ or apply vendor patch |
| CVE-2023-44487 | nginx | high | 7.5 | **Yes** | Upgrade nginx to 1.25.3+ or apply HTTP/2 rapid reset mitigation |
| CVE-2024-6387 | openssh | high | 8.1 | **Yes** | Upgrade OpenSSH to 9.8p1+; set LoginGraceTime=0 as interim mitigation |
| CVE-2023-38408 | openssh | critical | 9.8 | **Yes** | Upgrade OpenSSH to 9.3p2+; disable agent forwarding where not required |

### Vulnerabilities NOT Affecting Pinned Versions

| CVE | Product | Severity | Reason |
|-----|---------|----------|--------|
| CVE-2019-9193 | postgresql | high | Affects PostgreSQL 9.3-11.2 only; 16.2 is outside range |
| CVE-2024-1597 | postgresql | critical | Targets pgjdbc (JDBC driver), not PostgreSQL server |
| CVE-2022-31197 | postgresql | high | Targets pgjdbc (JDBC driver), not PostgreSQL server |

## Ambiguities and Observations

1. **No sudoers configuration found**: The Ansible config defines `sudo` group membership but does not deploy a sudoers file. The actual sudo privileges (e.g., NOPASSWD) are undefined in the configuration.

2. **No SELinux/AppArmor policies**: No SELinux booleans or AppArmor profiles are configured in the Ansible roles.

3. **No session logging/audit obligations**: No audit scripts, profile.d logging, or session recording configurations were found in the Ansible configuration.

4. **No credentials management**: No vault-encrypted credentials or secret management integration was detected. Database user creation uses plain names without password specifications.

5. **pg_hba implicit deny**: The pg_hba.conf configuration only allows connections from the appservers subnet (10.0.2.0/24). All other sources are implicitly denied by PostgreSQL's default behavior, which is captured in rule-009.

6. **DMZ firewall allows all internet traffic**: The DMZ firewall rule allows 0.0.0.0/0 on port 443, which is expected for an internet-facing reverse proxy but should be monitored.

7. **No monitoring access rules**: No Nagios, Prometheus, or other monitoring service configurations were found.

8. **No load balancer backend definitions**: No HAProxy or similar load balancer configurations were found.

## Attribute Catalog

The complete attribute catalog includes:
- **Subject attributes**: user, uid, groups, clearance, department, source_network, source_zone
- **Resource attributes**: hostname, ip, role, zone, host_group, service, port, protocol, path, owner, group, mode, role_attr
- **Environment attributes**: org, environment, compliance_tier, default_log_retention_days
