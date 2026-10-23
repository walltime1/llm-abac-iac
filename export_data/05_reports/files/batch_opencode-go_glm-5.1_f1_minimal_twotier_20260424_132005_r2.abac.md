# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 13:32:04_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 13 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f1_minimal_twotier`_

## Attributes

```json
{
  "subjects": [
    {
      "name": "user",
      "type": "enum",
      "domain": [
        "admin",
        "appuser",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "uid",
      "type": "integer",
      "source": "group_vars/all.yml"
    },
    {
      "name": "groups",
      "type": "set",
      "domain": [
        "sudo",
        "developers"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "clearance",
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "department",
      "type": "enum",
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "source_network",
      "type": "cidr",
      "source": "group_vars/webservers.yml"
    },
    {
      "name": "source_zone",
      "type": "enum",
      "domain": [
        "internet",
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    }
  ],
  "resources": [
    {
      "name": "hostname",
      "type": "enum",
      "domain": [
        "web01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "ip",
      "type": "ip",
      "source": "inventory.ini"
    },
    {
      "name": "role",
      "type": "enum",
      "domain": [
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "zone",
      "type": "enum",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "host_group",
      "type": "enum",
      "domain": [
        "webservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "service",
      "type": "enum",
      "domain": [
        "httpd",
        "sshd",
        "postgresql"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    {
      "name": "port",
      "type": "integer",
      "source": "group_vars/webservers.yml"
    },
    {
      "name": "protocol",
      "type": "enum",
      "domain": [
        "tcp"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    {
      "name": "path",
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    {
      "name": "owner",
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    {
      "name": "group",
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    {
      "name": "mode",
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    {
      "name": "database",
      "type": "enum",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  ],
  "environment": [
    {
      "name": "org",
      "type": "enum",
      "domain": [
        "labcorp"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "environment",
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "compliance_tier",
      "type": "enum",
      "domain": [
        "soc2"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "default_log_retention_days",
      "type": "integer",
      "source": "group_vars/all.yml"
    }
  ]
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
      "lines": "12-18"
    }
  },
  {
    "id": "rule-002",
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
      "lines": "20-26"
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
      "service": {
        "equals": "sshd"
      },
      "host_group": {
        "equals": "webservers"
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
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      },
      "source_zone": {
        "equals": "internet"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "webservers"
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
      "task": "Firewall - allow HTTP from internet",
      "lines": "28-33"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "role_attr_flags",
        "value": "LOGIN,SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "13-17"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "role_attr_flags",
        "value": "LOGIN,NOSUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "19-23"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      },
      "source_zone": {
        "equals": "dmz"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "host_group": {
        "equals": "dbservers"
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
      "lines": "25-28"
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
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
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
      "task": "Allow postgres only from webservers subnet (implicit deny-default)",
      "lines": "25-28"
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
      "lines": "7-12"
    }
  },
  {
    "id": "rule-010",
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
      "lines": "7-12"
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
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
      "port": {
        "equals": 80
      },
      "host_group": {
        "equals": "webservers"
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
    "cve_id": "CVE-2021-41773",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "high",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev_status": false,
    "affects_pinned_version": true,
    "description": "Apache HTTP Server 2.4.49 contains a path traversal caused by flawed path normalization, letting attackers map URLs outside the document root and potentially read arbitrary files.",
    "recommendation": "Upgrade httpd to at least 2.4.51. The pinned version 2.4.49 is directly vulnerable. Combined with internet-facing HTTP (0.0.0.0/0), this is a critical remediation priority."
  },
  {
    "cve_id": "CVE-2021-42013",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "high",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev_status": false,
    "affects_pinned_version": true,
    "description": "Apache HTTP Server 2.4.49 and 2.4.50 suffer from path traversal and file disclosure. The fix for CVE-2021-41773 was incomplete, allowing double-URL encoding bypass.",
    "recommendation": "Upgrade httpd to at least 2.4.51. The pinned version 2.4.49 is vulnerable to both CVE-2021-41773 and this bypass. Critical priority given internet-facing exposure."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "kev_status": false,
    "affects_pinned_version": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation vulnerability.",
    "recommendation": "Not applicable - affects OpenSSH 3.7.x only. Pinned version 9.6p1 is not affected."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "pgjdbc",
    "pinned_version": "postgresql-16.2-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev_status": false,
    "affects_pinned_version": false,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2 contain a SQL injection vulnerability via protocol level. Affects the JDBC driver, not the PostgreSQL server.",
    "recommendation": "Not applicable - this affects pgjdbc (Java JDBC driver), not the PostgreSQL server binary. Pinned postgresql 16.2 is not affected."
  }
]
```

## Report

# ABAC Policy Mining Report — Labcorp Ansible Configuration

## Executive Summary

An Attribute-Based Access Control (ABAC) policy was mined from the Ansible configuration. The configuration defines two host groups (**webservers** and **dbservers**) in a **production** environment under **SOC2** compliance. Two named users (**admin** and **appuser**) are provisioned, and access controls cover SSH, sudo, HTTP (firewall), PostgreSQL (database login + network restrictions), and filesystem permissions.

The policy comprises **12 rules** (10 permit, 1 explicit deny, 1 default-deny) and **24 attribute definitions** across subject, resource, and environment dimensions.

---

## Attribute Catalog

### Subject Attributes
| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| user | enum | admin, appuser, postgres | group_vars/all.yml |
| uid | integer | — | group_vars/all.yml |
| groups | set | sudo, developers | group_vars/all.yml |
| clearance | enum | secret, confidential | group_vars/all.yml |
| department | enum | operations, engineering | group_vars/all.yml |
| source_network | cidr | — | group_vars/webservers.yml |
| source_zone | enum | internet, dmz, internal | inventory.ini |

### Resource Attributes
| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| hostname | enum | web01.lab.local, db01.lab.local | inventory.ini |
| ip | ip | — | inventory.ini |
| role | enum | frontend, primary | inventory.ini |
| zone | enum | dmz, internal | inventory.ini |
| host_group | enum | webservers, dbservers, prod | inventory.ini |
| service | enum | httpd, sshd, postgresql | roles/web+db/tasks/main.yml |
| port | integer | — | group_vars/webservers.yml |
| protocol | enum | tcp | roles/web/tasks/main.yml |
| path | string | — | roles/db/tasks/main.yml |
| owner | enum | postgres | roles/db/tasks/main.yml |
| group | enum | postgres | roles/db/tasks/main.yml |
| mode | string | — | roles/db/tasks/main.yml |
| database | enum | all | roles/db/tasks/main.yml |

### Environment Attributes
| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| org | enum | labcorp | group_vars/all.yml |
| environment | enum | production | inventory.ini |
| compliance_tier | enum | soc2 | group_vars/all.yml |
| default_log_retention_days | integer | — | group_vars/all.yml |

---

## Extracted Rules

| ID | Subject | Action | Effect | Key Conditions |
|----|---------|--------|--------|----------------|
| rule-001 | members of sudo group | user:create | permit | — |
| rule-002 | sudo + secret clearance | sudo:execute | permit | nopassword=false |
| rule-003 | members of sudo group | ssh:login | permit | sshd on webservers |
| rule-004 | internet (0.0.0.0/0) | network:connect | permit | TCP/80 on webservers |
| rule-005 | members of sudo group | db:login | permit | SUPERUSER on dbservers |
| rule-006 | members of developers | db:login | permit | NOSUPERUSER on dbservers |
| rule-007 | DMZ (10.0.1.0/24) | network:connect | permit | PostgreSQL 5432 on dbservers |
| rule-008 | all | network:connect | deny | PostgreSQL on dbservers (implicit deny-default) |
| rule-009 | postgres user | filesystem:read | permit | /var/lib/postgresql/data 0700 |
| rule-010 | postgres user | filesystem:write | permit | /var/lib/postgresql/data 0700 |
| rule-011 | postgres user | filesystem:execute | permit | /var/lib/postgresql/data 0700 |
| rule-012 | all | * | deny | default-deny |

---

## Vulnerability Assessment

### Critical Findings

| CVE | Product | Pinned Version | Severity | CVSS | Affects Pinned? | Action |
|-----|---------|---------------|----------|------|------------------|--------|
| CVE-2021-41773 | httpd | 2.4.49-1 | High | 9.8 | YES | **Upgrade immediately** |
| CVE-2021-42013 | httpd | 2.4.49-1 | High | 9.8 | YES | **Upgrade immediately** |

### Non-Applicable Findings

| CVE | Product | Why Not Applicable |
|-----|---------|-------------------|
| CVE-2003-0786 | openssh | Affects 3.7.x only; pinned 9.6p1 unaffected |
| CVE-2024-1597 | pgjdbc | Affects JDBC driver, not PostgreSQL server |

**httpd 2.4.49** is critically vulnerable to the well-known path traversal attacks (CVE-2021-41773 and CVE-2021-42013). Combined with the firewall rule allowing HTTP from 0.0.0.0/0 (the entire internet), this represents a **critical risk** requiring immediate remediation.

---

## Ambiguities and Design Observations

1. **Internet-facing HTTP (0.0.0.0/0):** The firewall allows HTTP from any source to webservers, which combined with the vulnerable httpd version creates a critical attack surface.

2. **SSH restricted to sudo group only:** The `AllowGroups sudo` directive means the `appuser` (in developers group only) cannot SSH into webservers. This is intentional access control but may conflict with development workflows.

3. **Postgres system user vs. defined users:** The `/var/lib/postgresql/data` directory is owned by the `postgres` OS system user (mode 0700), but `postgres` is not listed in the Ansible `users` variable. The filesystem rules reference this system user which is implicitly created by the PostgreSQL package.

4. **No explicit deny rule for SSH:** The `AllowGroups sudo` directive in sshd_config implicitly denies SSH for non-sudo users, but there is no explicit ABAC deny rule for this. A future iteration could add an explicit deny rule for completeness.

5. **Credentials:** The Ansible configuration does not contain any hardcoded passwords or API keys in the files examined.

6. **Appuser cannot SSH to webservers:** The `appuser` (in developers group) gets NOSUPERUSER database access but cannot SSH to webservers per the AllowGroups restriction. This is a potential operational issue worth clarifying with the site administrators.
