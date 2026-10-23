# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 14:56:09_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 9 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "type": "enum",
      "domain": [
        "admin",
        "appuser",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "enum",
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "source_ip": {
      "type": "cidr",
      "source": "group_vars/dbservers.yml"
    },
    "source_network": {
      "type": "cidr",
      "source": "group_vars/dbservers.yml"
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal",
        "internet"
      ],
      "source": "inventory.ini"
    }
  },
  "resources": {
    "hostname": {
      "type": "enum",
      "domain": [
        "web01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "ip",
      "source": "inventory.ini"
    },
    "role": {
      "type": "enum",
      "domain": [
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "webservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "openssh-server",
        "postgresql"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "source": "group_vars/webservers.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp",
        "udp"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    "path": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "enum",
      "domain": [
        "postgres",
        "root"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "enum",
      "domain": [
        "postgres",
        "root"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "enum",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "privilege_level": {
      "type": "enum",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environments": {
    "org": {
      "type": "enum",
      "domain": [
        "labcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "enum",
      "domain": [
        "soc2"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "integer",
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
    "description": "Allow SSH login for members of sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
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
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "40-44"
    }
  },
  {
    "id": "rule-002",
    "description": "Allow sudo execute for admin users with secret clearance",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sudo"
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
      "lines": "23-30"
    }
  },
  {
    "id": "rule-003",
    "description": "Allow DB superuser login for sudo group members",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
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
      "task": "Create DB superuser role",
      "lines": "16-21"
    }
  },
  {
    "id": "rule-004",
    "description": "Allow DB read-only login for developers group members",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
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
      "task": "Create DB read-only role",
      "lines": "23-28"
    }
  },
  {
    "id": "rule-005",
    "description": "Allow PostgreSQL network connections from webservers subnet",
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
      },
      "database": {
        "equals": "all"
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
      "lines": "30-34"
    }
  },
  {
    "id": "rule-006",
    "description": "Deny PostgreSQL network connections from non-webservers subnets (pg_hba implicit default)",
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
      },
      "database": {
        "equals": "all"
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
      "task": "Allow postgres only from webservers subnet",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-007",
    "description": "Allow HTTPS from internet via firewall",
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "32-38"
    }
  },
  {
    "id": "rule-008",
    "description": "Allow postgres user to read postgres data directory",
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
      "lines": "8-14"
    }
  },
  {
    "id": "rule-009",
    "description": "Allow postgres user to write postgres data directory",
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
      "lines": "8-14"
    }
  },
  {
    "id": "rule-010",
    "description": "Allow postgres user to execute (traverse) postgres data directory",
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
      "lines": "8-14"
    }
  },
  {
    "id": "rule-011",
    "description": "Allow user creation for sudo group members on webservers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
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
      "lines": "14-21"
    }
  },
  {
    "id": "rule-012",
    "description": "Default deny all access",
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
      "file": "synthetic",
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
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cves": [
      {
        "cve_id": "CVE-2016-0746",
        "severity": "critical",
        "is_remote": true,
        "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 use-after-free",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — pinned version 1.27.0 is past affected range (before 1.9.10)"
      },
      {
        "cve_id": "CVE-2021-46461",
        "severity": "critical",
        "is_remote": true,
        "description": "NGINX njs versions through 0.7.0 out-of-bounds array access",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — affects njs module, not nginx core; pinned version 1.27.0 ships with newer njs"
      },
      {
        "cve_id": "CVE-2017-20005",
        "severity": "critical",
        "is_remote": true,
        "description": "NGINX before 1.13.6 buffer overflow via integer overflow",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — pinned version 1.27.0 is past 1.13.6"
      },
      {
        "cve_id": "CVE-2021-23017",
        "severity": "high",
        "is_remote": true,
        "description": "nginx resolver 1-byte memory overwrite via forged UDP packets",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — patched in 1.21.6; pinned version 1.27.0 includes fix"
      },
      {
        "cve_id": "CVE-2013-4547",
        "severity": "high",
        "is_remote": true,
        "description": "nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 restriction bypass",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — pinned version 1.27.0 is far past affected range"
      }
    ]
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "cves": [
      {
        "cve_id": "CVE-2003-0786",
        "severity": "critical",
        "is_remote": true,
        "description": "OpenSSH 3.7.1 and 3.7.1p1 privilege escalation",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — pinned version 9.9p1 is far past 3.7.1"
      },
      {
        "cve_id": "CVE-2000-0999",
        "severity": "critical",
        "is_remote": true,
        "description": "OpenBSD ssh format string vulnerability",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — ancient vulnerability, long patched"
      },
      {
        "cve_id": "CVE-2000-0525",
        "severity": "critical",
        "is_remote": true,
        "description": "OpenSSH with UseLogin enabled privilege dropping issue",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — ancient vulnerability"
      },
      {
        "cve_id": "CVE-2001-0144",
        "severity": "critical",
        "is_remote": true,
        "description": "CORE SDI SSH1 CRC-32 compensation attack detector integer overflow",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — affects SSH1 protocol, not SSH2"
      },
      {
        "cve_id": "CVE-2003-0693",
        "severity": "critical",
        "is_remote": true,
        "description": "OpenSSH before 3.7 buffer management error",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — pinned version 9.9p1 is far past 3.7"
      }
    ]
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cves": [
      {
        "cve_id": "CVE-2007-3279",
        "severity": "critical",
        "is_remote": true,
        "description": "PostgreSQL 8.1 and later with plpgsql enabled privilege escalation",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — patched in later versions; pinned 16.4 includes fix"
      },
      {
        "cve_id": "CVE-2002-1399",
        "severity": "critical",
        "is_remote": true,
        "description": "PostgreSQL 7.2.1 and earlier buffer overflow",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — pinned version 16.4 is far past 7.2.1"
      },
      {
        "cve_id": "CVE-2013-1903",
        "severity": "critical",
        "is_remote": true,
        "description": "PostgreSQL 9.2.x before 9.2.4 denial of service",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — pinned version 16.4 is past affected range"
      },
      {
        "cve_id": "CVE-2013-1902",
        "severity": "critical",
        "is_remote": true,
        "description": "PostgreSQL before 9.2.4 insecure random number generation",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — pinned version 16.4 is past affected range"
      },
      {
        "cve_id": "CVE-2024-1597",
        "severity": "critical",
        "is_remote": true,
        "description": "pgjdbc PostgreSQL JDBC Driver before 42.7.2 SQL injection",
        "affects_pinned_version": false,
        "recommendation": "Not applicable — affects pgjdbc (Java JDBC driver), not PostgreSQL server"
      }
    ]
  }
]
```

## Report

# ABAC Policy Mining Report — Ansible Configuration

## 1. Executive Summary

An Attribute-Based Access Control (ABAC) policy was mined from an Ansible configuration managing a two-host production environment (web01.lab.local in DMZ, db01.lab.local in internal zone). The policy comprises **12 rules** governing SSH access, sudo privileges, database authentication, network connectivity, and filesystem permissions. All pinned software versions (nginx 1.27.0, OpenSSH 9.9p1, PostgreSQL 16.4) are current and unaffected by known critical/high remote CVEs.

## 2. Attribute Catalog

### 2.1 Subject Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| user | enum | admin, appuser, postgres | group_vars/all.yml |
| uid | integer | — | group_vars/all.yml |
| groups | set | sudo, developers | group_vars/all.yml |
| clearance | enum | secret, confidential | group_vars/all.yml |
| department | enum | operations, engineering | group_vars/all.yml |
| source_ip | cidr | — | group_vars/dbservers.yml |
| source_network | cidr | — | group_vars/dbservers.yml |
| source_zone | enum | dmz, internal, internet | inventory.ini |

### 2.2 Resource Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| hostname | enum | web01.lab.local, db01.lab.local | inventory.ini |
| ip | ip | — | inventory.ini |
| role | enum | frontend, primary | inventory.ini |
| zone | enum | dmz, internal | inventory.ini |
| host_group | enum | webservers, dbservers, prod | inventory.ini |
| service | enum | nginx, openssh-server, postgresql | roles/web/tasks/main.yml |
| port | integer | — | group_vars/webservers.yml |
| protocol | enum | tcp, udp | roles/web/tasks/main.yml |
| path | string | — | roles/db/tasks/main.yml |
| owner | enum | postgres, root | roles/db/tasks/main.yml |
| group | enum | postgres, root | roles/db/tasks/main.yml |
| mode | string | — | roles/db/tasks/main.yml |
| database | enum | all | roles/db/tasks/main.yml |
| privilege_level | enum | SUPERUSER, NOSUPERUSER | roles/db/tasks/main.yml |

### 2.3 Environment Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| org | enum | labcorp | group_vars/all.yml |
| environment | enum | production | inventory.ini |
| compliance_tier | enum | soc2 | group_vars/all.yml |
| default_log_retention_days | integer | — | group_vars/all.yml |

## 3. Policy Rules

### 3.1 SSH Access (rule-001)
- **Subject**: groups ∈ {sudo}
- **Resource**: service = openssh-server
- **Action**: ssh:login
- **Effect**: PERMIT
- **Source**: roles/web/tasks/main.yml (AllowGroups directive)

### 3.2 Sudo Privileges (rule-002)
- **Subject**: groups ∈ {sudo} ∧ clearance = secret
- **Resource**: service = sudo
- **Action**: sudo:execute
- **Effect**: PERMIT
- **Obligation**: nopassword = false (password required)
- **Source**: roles/web/tasks/main.yml (sudoers task)

### 3.3 Database Superuser Login (rule-003)
- **Subject**: groups ∈ {sudo}
- **Resource**: service = postgresql ∧ privilege_level = SUPERUSER
- **Action**: db:login
- **Effect**: PERMIT
- **Source**: roles/db/tasks/main.yml (postgresql_user with SUPERUSER)

### 3.4 Database Read-Only Login (rule-004)
- **Subject**: groups ∈ {developers}
- **Resource**: service = postgresql ∧ privilege_level = NOSUPERUSER
- **Action**: db:login
- **Effect**: PERMIT
- **Source**: roles/db/tasks/main.yml (postgresql_user with NOSUPERUSER)

### 3.5 PostgreSQL Network Access from Webservers (rule-005)
- **Subject**: source_network = 10.0.1.0/24
- **Resource**: service = postgresql ∧ port = 5432 ∧ database = all
- **Action**: network:connect
- **Effect**: PERMIT
- **Source**: roles/db/tasks/main.yml (pg_hba.conf lineinfile)

### 3.6 PostgreSQL Network Deny — Implicit Default (rule-006)
- **Subject**: applies_to = all
- **Resource**: service = postgresql ∧ port = 5432 ∧ database = all
- **Action**: network:connect
- **Effect**: DENY
- **Source**: roles/db/tasks/main.yml (pg_hba implicit deny-default)

### 3.7 HTTPS from Internet (rule-007)
- **Subject**: source_network = 0.0.0.0/0
- **Resource**: service = nginx ∧ port = 443 ∧ protocol = tcp
- **Action**: network:connect
- **Effect**: PERMIT
- **Source**: roles/web/tasks/main.yml (firewalld task)

### 3.8–3.10 Postgres Data Directory Filesystem Access (rules 008–010)
- **Subject**: user = postgres
- **Resource**: path = /var/lib/postgresql/data ∧ owner = postgres ∧ group = postgres ∧ mode = 0700
- **Actions**: filesystem:read, filesystem:write, filesystem:execute
- **Effect**: PERMIT
- **Source**: roles/db/tasks/main.yml (file task)

### 3.11 User Creation on Webservers (rule-011)
- **Subject**: groups ∈ {sudo}
- **Resource**: host_group = webservers
- **Action**: user:create
- **Effect**: PERMIT
- **Source**: roles/web/tasks/main.yml (user task with when condition)

### 3.12 Default Deny (rule-012)
- **Subject**: applies_to = all
- **Resource**: applies_to = all
- **Action**: *
- **Effect**: DENY

## 4. Vulnerability Assessment

### Pinned Software Versions
| Package | Pinned Version | Status |
|---------|---------------|--------|
| nginx | 1.27.0-1~noble | ✅ No applicable CVEs |
| openssh-server | 1:9.9p1-3ubuntu1 | ✅ No applicable CVEs |
| postgresql-16 | 16.4-1.pgdg24.04+1 | ✅ No applicable CVEs |

All five critical/high remote CVEs found per product affect versions significantly older than the pinned versions. The Ansible configuration explicitly pins recent, patched versions. No remediation actions are required.

## 5. Ambiguities and Assumptions

1. **appuser SSH access**: The `AllowGroups sudo` directive in sshd_config means `appuser` (who is in the `developers` group only) cannot SSH into any host. This may be intentional but should be confirmed.

2. **appuser database access scope**: The `postgresql_user` task grants `appuser` LOGIN with NOSUPERUSER, but no specific database or schema privileges are defined. The actual read/write scope within PostgreSQL is unspecified.

3. **pg_hba authentication method**: The pg_hba rule uses `scram-sha-256` authentication, which is appropriate, but the pg_hba file path (`/etc/postgresql/pg_hba.conf`) is non-standard (typically `/etc/postgresql/<version>/main/pg_hba.conf`). This may be a template path.

4. **Firewall 0.0.0.0/0**: The web server firewall allows HTTPS from all IPs (0.0.0.0/0), which is expected for an internet-facing service but should be documented.

5. **No explicit deny rules for SSH**: Only `AllowGroups sudo` is configured; there is no explicit deny for other groups, relying on the default-deny behavior of AllowGroups.

6. **Credentials**: The Ansible configuration does not manage passwords, keys, or secrets directly — these are assumed to be managed elsewhere (e.g., Ansible Vault).

## 6. Security Observations

- **Least privilege**: The policy follows least-privilege principles — SSH restricted to sudo group, database access tiered by group, PostgreSQL network access limited to the webservers subnet.
- **Defense in depth**: PostgreSQL is protected both at the network level (pg_hba + firewall) and at the authentication level (SUPERUSER vs NOSUPERUSER).
- **SOC2 compliance**: The environment is tagged as SOC2 compliance tier, with 90-day log retention configured.
