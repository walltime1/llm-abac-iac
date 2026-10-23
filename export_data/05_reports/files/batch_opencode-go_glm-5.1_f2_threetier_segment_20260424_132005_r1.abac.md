# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 13:47:02_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 21 | Rules: 20_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f2_threetier_segmented`_

## Attributes

```json
{
  "subject": {
    "user": {
      "type": "string",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
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
    "department": {
      "type": "string",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "string",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "type": "cidr",
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml"
    },
    "source_zone": {
      "type": "string",
      "domain": [
        "dmz",
        "app",
        "data",
        "internet"
      ],
      "source": "derived from inventory.ini zone assignments and firewall_allow_from"
    }
  },
  "resource": {
    "hostname": {
      "type": "string",
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "ip",
      "domain": [
        "10.0.1.10",
        "10.0.2.10",
        "10.0.3.10"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "type": "string",
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "string",
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "string",
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "string",
      "domain": [
        "nginx",
        "openssh-server",
        "postgresql"
      ],
      "source": "group_vars/all.yml,roles/app/tasks/main.yml,roles/db/tasks/main.yml,roles/dmz/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "domain": [
        443,
        22,
        5432,
        8080
      ],
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml"
    },
    "protocol": {
      "type": "string",
      "domain": [
        "tcp"
      ],
      "source": "roles/app/tasks/main.yml,roles/db/tasks/main.yml,roles/dmz/tasks/main.yml"
    },
    "path": {
      "type": "string",
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "string",
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "string",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "string",
      "domain": [
        "pci"
      ],
      "source": "inventory.ini,group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "integer",
      "domain": [
        365
      ],
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
    "description": "SSH login allowed for sudo and developers groups on appservers",
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
      "lines": "21-23"
    }
  },
  {
    "id": "rule-002",
    "description": "SSH login allowed for sudo and dba groups on dbservers",
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
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "31-33"
    }
  },
  {
    "id": "rule-003",
    "description": "SSH login allowed only for sudo group on dmz hosts",
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
      "lines": "23-25"
    }
  },
  {
    "id": "rule-004",
    "description": "Allow network connections to app port 8080/tcp from DMZ subnet on appservers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
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
      "task": "Firewall - allow app port from DMZ only",
      "lines": "15-20"
    }
  },
  {
    "id": "rule-005",
    "description": "Allow HTTPS connections from internet to DMZ hosts",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
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
      "task": "Firewall - allow HTTPS from internet",
      "lines": "16-20"
    }
  },
  {
    "id": "rule-006",
    "description": "Allow PostgreSQL connections from appservers subnet on dbservers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "27-29"
    }
  },
  {
    "id": "rule-007",
    "description": "Implicit deny for PostgreSQL connections from non-appserver subnets (pg_hba default-deny)",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
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
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet (implicit deny-default)",
      "lines": "27-29"
    }
  },
  {
    "id": "rule-008",
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
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login:superuser",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "18-21"
    }
  },
  {
    "id": "rule-009",
    "description": "Developers group members get NOSUPERUSER (read-only) database login on dbservers",
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
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login:readonly",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "23-26"
    }
  },
  {
    "id": "rule-010",
    "description": "Postgres data directory read access for DBA group (owner:postgres, mode:0700)",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "14-18"
    }
  },
  {
    "id": "rule-011",
    "description": "Postgres data directory write access for DBA group (owner:postgres, mode:0700)",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "14-18"
    }
  },
  {
    "id": "rule-012",
    "description": "Postgres data directory execute access for DBA group (owner:postgres, mode:0700)",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "14-18"
    }
  },
  {
    "id": "rule-013",
    "description": "Users with sudo or developers groups are provisioned on appservers",
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
      "lines": "7-12"
    }
  },
  {
    "id": "rule-014",
    "description": "Users with sudo group are provisioned on dmz hosts",
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
    "id": "rule-015",
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
      "host_group": {
        "equals": "dbservers"
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
      "host_group": {
        "equals": "dbservers"
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
      "host_group": {
        "equals": "dbservers"
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
    "id": "rule-019",
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
    "id": "rule-020",
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
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "is_remote": true,
    "kev": true,
    "affects_pinned_version": true,
    "description": "HTTP/2 Rapid Reset Attack - allows remote attackers to trigger denial of service via rapid creation and cancellation of HTTP/2 streams",
    "recommendation": "Upgrade nginx to latest stable version with HTTP/2 Rapid Reset mitigation"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "high",
    "is_remote": true,
    "kev": true,
    "affects_pinned_version": true,
    "description": "regreSSHion - signal handler race condition in OpenSSH server (sshd) allows remote code execution as root",
    "recommendation": "Upgrade openssh-server to 9.8p1 or later immediately - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "13.7",
    "severity": "critical",
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "description": "Buffer overflow in PostgreSQL encoding conversion allowing potential code execution",
    "recommendation": "Upgrade postgresql-13 to latest patched 13.x version"
  }
]
```

## Report

# ABAC Policy Mining Report — Ansible Configuration

## 1. Overview

This report presents an Attribute-Based Access Control (ABAC) policy mined from an Ansible configuration managing a three-zone production environment (DMZ, App, Data) for organization **segcorp** under **PCI compliance**.

- **Source files analyzed:** 9 (inventory, 4 group_vars, 3 role task files, 1 README)
- **Policy rules extracted:** 15 (14 explicit + 1 default-deny)
- **Vulnerabilities affecting pinned versions:** 3

## 2. Attribute Catalog

### 2.1 Subject Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| user | string | admin, developer, dba | group_vars/all.yml |
| uid | integer | 1001, 1002, 1003 | group_vars/all.yml |
| groups | set | sudo, developers, dba | group_vars/all.yml |
| department | string | operations, engineering, data | group_vars/all.yml |
| clearance | string | secret, confidential | group_vars/all.yml |
| source_network | cidr | — | group_vars appservers/dbservers/dmz |
| source_zone | string | dmz, app, data, internet | derived from inventory.ini |

### 2.2 Resource Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| hostname | string | proxy01, app01, db01 | inventory.ini |
| ip | ip | 10.0.1.10, 10.0.2.10, 10.0.3.10 | inventory.ini |
| role | string | reverse_proxy, application, primary | inventory.ini |
| zone | string | dmz, app, data | inventory.ini |
| host_group | string | dmz, appservers, dbservers, prod | inventory.ini |
| service | string | nginx, openssh-server, postgresql | group_vars + roles |
| port | integer | 443, 22, 5432, 8080 | group_vars |
| protocol | string | tcp | roles |
| path | string | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| owner | string | postgres | roles/db/tasks/main.yml |
| group | string | postgres | roles/db/tasks/main.yml |
| mode | string | 0700 | roles/db/tasks/main.yml |
| database | string | all | roles/db/tasks/main.yml |

### 2.3 Environment Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| org | string | segcorp | group_vars/all.yml |
| environment | string | production | inventory.ini |
| compliance_tier | string | pci | inventory.ini, group_vars/all.yml |
| default_log_retention_days | integer | 365 | group_vars/all.yml |

## 3. Extracted Policy Rules

### 3.1 SSH Access Control (AllowGroups)

| Rule ID | Subject Condition | Resource | Action | Effect |
|---------|------------------|----------|--------|--------|
| rule-001 | groups any_of [sudo, developers] | appservers / openssh-server | ssh:login | permit |
| rule-002 | groups any_of [sudo, dba] | dbservers / openssh-server | ssh:login | permit |
| rule-003 | groups any_of [sudo] | dmz / openssh-server | ssh:login | permit |

**Observation:** DMZ hosts are the most restrictive (admin-only SSH). Application servers allow developers. Database servers allow DBAs but NOT developers directly.

### 3.2 Network Firewall Rules (firewalld)

| Rule ID | Source Network | Destination | Port | Action | Effect |
|---------|--------------|-------------|------|--------|--------|
| rule-004 | 10.0.1.0/24 (DMZ subnet) | appservers | 8080/tcp | network:connect | permit |
| rule-005 | 0.0.0.0/0 (internet) | dmz | 443/tcp | network:connect | permit |
| rule-006 | 10.0.2.0/24 (app subnet) | dbservers | 5432/postgresql | network:connect | permit |
| rule-007 | applies_to=all | dbservers / postgresql | network:connect | deny |

**Observation:** Three-tier network segmentation: Internet -> DMZ (HTTPS only) -> App (from DMZ only) -> Data (from App only). Rule-007 is the pg_hba implicit deny.

### 3.3 Database Access

| Rule ID | Subject Condition | Resource | Action | Effect |
|---------|------------------|----------|--------|--------|
| rule-008 | groups any_of [dba] | dbservers / postgresql | db:login:superuser | permit |
| rule-009 | groups any_of [developers] | dbservers / postgresql | db:login:readonly | permit |

**Observation:** DBAs get SUPERUSER privileges; developers get NOSUPERUSER (read-only) access. This implements least-privilege separation.

### 3.4 Filesystem Access

| Rule ID | Subject Condition | Resource | Action | Effect |
|---------|------------------|----------|--------|--------|
| rule-010 | groups any_of [dba] | dbservers, path=/var/lib/postgresql/data, mode=0700 | filesystem:read | permit |
| rule-011 | groups any_of [dba] | dbservers, path=/var/lib/postgresql/data, mode=0700 | filesystem:write | permit |
| rule-012 | groups any_of [dba] | dbservers, path=/var/lib/postgresql/data, mode=0700 | filesystem:execute | permit |

**Observation:** Postgres data directory has restrictive 0700 mode (owner-only). Only DBA group members (who operate as postgres user) can access.

### 3.5 User Provisioning

| Rule ID | Subject Condition | Resource | Action | Effect |
|---------|------------------|----------|--------|--------|
| rule-013 | groups any_of [sudo, developers] | appservers | user:create | permit |
| rule-014 | groups any_of [sudo] | dmz | user:create | permit |

### 3.6 Default Deny

| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-015 | applies_to=all | applies_to=all | * | deny |

## 4. Vulnerability Assessment

Three vulnerabilities were identified that affect the pinned software versions:

| CVE | Product | Pinned Version | Severity | KEV | Impact |
|-----|---------|---------------|----------|-----|--------|
| CVE-2023-44487 | nginx | 1.20.0 | high | Yes | HTTP/2 Rapid Reset DoS |
| CVE-2024-6387 | openssh | 9.6p1 | high | Yes | regreSSHion RCE (root) |
| CVE-2024-1597 | postgresql | 13.7 | critical | No | Encoding conversion buffer overflow |

**Critical Finding:** CVE-2024-6387 (regreSSHion) is actively exploited in the wild and allows unauthenticated remote code execution as root on OpenSSH servers. The pinned version 9.6p1 falls within the affected range (8.5p1-9.7p1). **Immediate remediation is required.**

## 5. Ambiguities and Gaps

1. **Sudo privileges:** The `admin` user is in the `sudo` group, but no sudoers file was found in the Ansible configuration. It is unclear whether password-less sudo is configured (NOPASSWD flag). This should be audited.

2. **Developer DB access path:** Developers have NOSUPERUSER database login (rule-009) but do NOT have SSH access to dbservers (rule-002 only allows sudo+dba). The access path is unclear - developers may connect via application layer only.

3. **SSH port:** No explicit SSH port configuration was found; assumed default (22/tcp) but not confirmed in firewall rules.

4. **DBA user on dbservers:** The DBA user (uid=1003) has no explicit `user:create` task for dbservers. The `roles/db/tasks/main.yml` creates PostgreSQL roles but not OS-level user accounts. DBA SSH access assumes OS account exists.

5. **Credentials:** No explicit credential management (passwords, keys) was found in the Ansible configuration. SSH keys and database passwords are not managed here.

6. **PostgreSQL schema/database:** pg_hba grants access to `all` databases. No per-database or per-schema restrictions were found.

7. **Nginx configuration:** No nginx access control rules (location blocks, auth) were found beyond the firewall rules.

8. **Logging/audit:** The `default_log_retention_days: 365` setting exists but no specific audit/logging tasks were found in the role definitions.
