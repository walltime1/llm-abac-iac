# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 14:33:52_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 14 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": [
    {
      "name": "user",
      "type": "enum",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "uid",
      "type": "enum",
      "domain": [
        1001,
        1002,
        1003
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "groups",
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "department",
      "type": "enum",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "clearance",
      "type": "enum",
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "source_network",
      "type": "string",
      "source": "group_vars/appservers.yml,group_vars/dmz.yml,group_vars/dbservers.yml"
    },
    {
      "name": "source_zone",
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data",
        "internet"
      ],
      "source": "inventory.ini,group_vars/dmz.yml"
    }
  ],
  "resources": [
    {
      "name": "hostname",
      "type": "enum",
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "role",
      "type": "enum",
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "zone",
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "host_group",
      "type": "enum",
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "service",
      "type": "enum",
      "domain": [
        "ssh",
        "app",
        "https",
        "postgresql"
      ],
      "source": "roles/app/tasks/main.yml,roles/db/tasks/main.yml,roles/dmz/tasks/main.yml"
    },
    {
      "name": "port",
      "type": "enum",
      "domain": [
        22,
        443,
        8080,
        5432
      ],
      "source": "group_vars/appservers.yml,group_vars/dmz.yml,group_vars/dbservers.yml"
    },
    {
      "name": "protocol",
      "type": "enum",
      "domain": [
        "tcp"
      ],
      "source": "roles/app/tasks/main.yml,roles/db/tasks/main.yml,roles/dmz/tasks/main.yml"
    },
    {
      "name": "path",
      "type": "enum",
      "domain": [
        "/var/lib/postgresql/data"
      ],
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
      "type": "enum",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    {
      "name": "database",
      "type": "enum",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    {
      "name": "privilege",
      "type": "enum",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  ],
  "environment": [
    {
      "name": "org",
      "type": "enum",
      "domain": [
        "segcorp"
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
        "pci"
      ],
      "source": "group_vars/all.yml,inventory.ini"
    },
    {
      "name": "default_log_retention_days",
      "type": "enum",
      "domain": [
        365
      ],
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
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "appservers"
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
      "lines": "29-32"
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
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "dbservers"
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
      "task": "Restrict SSH to sudo group",
      "lines": "33-36"
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
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "27-30"
    }
  },
  {
    "id": "rule-004",
    "description": "Allow network connections to app port 8080/tcp from DMZ subnet only",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      },
      "source_zone": {
        "equals": "dmz"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "appservers"
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
      "task": "Firewall - allow app port from DMZ only",
      "lines": "21-27"
    }
  },
  {
    "id": "rule-005",
    "description": "Allow HTTPS connections from internet to DMZ proxy",
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
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall - allow HTTPS from internet",
      "lines": "21-27"
    }
  },
  {
    "id": "rule-006",
    "description": "Allow PostgreSQL connections from appservers subnet only",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      },
      "source_zone": {
        "equals": "app"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
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
      "lines": "27-30"
    }
  },
  {
    "id": "rule-007",
    "description": "Deny PostgreSQL connections from non-appservers subnets (pg_hba implicit deny)",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
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
      "task": "Allow postgres only from appservers subnet",
      "lines": "27-30"
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
      },
      "database": {
        "equals": "all"
      },
      "privilege": {
        "equals": "SUPERUSER"
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "19-22"
    }
  },
  {
    "id": "rule-009",
    "description": "Developers group members get read-only (NOSUPERUSER) database login on dbservers",
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
      "database": {
        "equals": "all"
      },
      "privilege": {
        "equals": "NOSUPERUSER"
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "24-27"
    }
  },
  {
    "id": "rule-010",
    "description": "Postgres data directory read access for dba group via service account",
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
      "lines": "14-19"
    }
  },
  {
    "id": "rule-011",
    "description": "Postgres data directory write access for dba group via service account",
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
      "lines": "14-19"
    }
  },
  {
    "id": "rule-012",
    "description": "Provision user accounts on appservers for sudo and developers groups",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "11-17"
    }
  },
  {
    "id": "rule-013",
    "description": "Provision admin user accounts on DMZ hosts for sudo group only",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "14-20"
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
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 8080
      },
      "host_group": {
        "equals": "appservers"
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
    "id": "rule-018",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "dmz"
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
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "description": "nginx resolver 1-byte memory overwrite via forged UDP packets from DNS server, causing worker process crash or other impacts.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to 1.21.0+ or apply patch from F5 advisory K12331123. nginx 1.20.0 is explicitly in the affected range.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "nginx 0.6.18 through 1.8.0 use-after-free in DNS response handling.",
    "affects_pinned_version": false,
    "recommendation": "Not applicable - pinned version 1.20.0 is above affected range (0.6.18-1.8.0).",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "nginx before 1.13.6 buffer overflow via integer overflow in modification date processing.",
    "affects_pinned_version": false,
    "recommendation": "Not applicable - pinned version 1.20.0 is above affected range (before 1.13.6).",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 8.1+ with plpgsql grants privileges to PUBLIC, allowing remote attackers to execute arbitrary code.",
    "affects_pinned_version": false,
    "recommendation": "Not applicable - pinned version 16.2 is far above affected range (8.1 era).",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 9.2.x before 9.2.4, 9.1.x before 9.1.9 allows unprivileged users to interfere with in-place updates.",
    "affects_pinned_version": false,
    "recommendation": "Not applicable - pinned version 16.2 is far above affected range.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql_jdbc_driver",
    "pinned_version": "N/A (not pinned)",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": true,
    "description": "pgjdbc PostgreSQL JDBC Driver SQL injection via improper handling of placeholders in PreferQueryMode=SIMPLE.",
    "affects_pinned_version": false,
    "recommendation": "Not applicable - this affects the JDBC driver, not the PostgreSQL server. If JDBC is used, upgrade driver to 42.7.2+.",
    "source": "group_vars/all.yml"
  }
]
```

## Report

# ABAC Policy Mining Report - segcorp Ansible Infrastructure

## 1. Summary

Mined an Attribute-Based Access Control (ABAC) policy from the Ansible configuration at `RLM_ANSIBLE_DIR`. The infrastructure comprises three host groups (DMZ, appservers, dbservers) in a PCI-compliant production environment with segmented network zones.

- **14 rules** extracted (including default-deny)
- **7 subject attributes**, **13 resource attributes**, **4 environment attributes** catalogued
- **1 active vulnerability** affecting pinned software (CVE-2021-23017 for nginx 1.20.0)

## 2. Infrastructure Overview

| Zone | Host | Role | IP |
|------|------|------|-----|
| DMZ | proxy01.lab.local | reverse_proxy | 10.0.1.10 |
| App | app01.lab.local | application | 10.0.2.10 |
| Data | db01.lab.local | primary | 10.0.3.10 |

**Users:** admin (sudo, operations, secret), developer (developers, engineering, confidential), dba (dba, data, secret)

## 3. Access Control Summary

### 3.1 SSH Access (AllowGroups)
- **Appservers:** sudo + developers groups
- **DB servers:** sudo + dba groups
- **DMZ:** sudo group only (most restrictive - internet-facing hosts)

### 3.2 Network Firewall Rules
- **App port 8080/tcp:** Only from DMZ subnet (10.0.1.0/24) - no direct internet access to app tier
- **HTTPS port 443/tcp:** From internet (0.0.0.0/0) to DMZ proxy - internet traffic terminates at reverse proxy
- **PostgreSQL port 5432/tcp:** Only from appservers subnet (10.0.2.0/24) - no DMZ or internet access to data tier
- **Implicit deny:** PostgreSQL denies all connections not from 10.0.2.0/24 (pg_hba default-deny)

### 3.3 Database Access
- **DBA group:** SUPERUSER + LOGIN privileges on all databases
- **Developers group:** NOSUPERUSER + LOGIN privileges (read-only equivalent)
- **Admin (sudo):** No direct database login provisioned

### 3.4 Filesystem ACLs
- `/var/lib/postgresql/data`: owner=postgres, group=postgres, mode=0700 - only postgres OS user can access

### 3.5 User Provisioning
- Appservers: admin + developer accounts created
- DMZ: admin account only (most restrictive for internet-facing hosts)
- DB servers: no shell user provisioning tasks (only DB roles)

## 4. Vulnerability Assessment

### 4.1 Pinned Software Versions
| Package | Pinned Version |
|---------|---------------|
| nginx | 1.20.0-1~focal |
| openssh-server | 1:9.1p1-1ubuntu1 |
| postgresql-16 | 16.2-1.pgdg22.04+1 |

### 4.2 Active Vulnerabilities

| CVE | Product | Severity | CVSS | Affects Pinned | Status |
|-----|---------|----------|------|----------------|--------|
| CVE-2021-23017 | nginx | High | 7.7 | **YES** | **Action required** |

**CVE-2021-23017 (nginx DNS resolver):** A 1-byte memory overwrite vulnerability in nginx's DNS resolver allows attackers who can forge UDP packets from a DNS server to cause worker process crashes or other impacts. nginx 1.20.0 is within the affected range. **Recommendation: Upgrade to nginx 1.21.0+ or apply the patch from F5 advisory K12331123.**

### 4.3 Non-Applicable CVEs
The following CVEs were found in searches but do NOT affect the pinned versions:
- CVE-2016-0746 (nginx < 1.8.0) - version too old
- CVE-2017-20005 (nginx < 1.13.6) - version too old
- CVE-2007-3279, CVE-2013-1903, CVE-2002-1399, CVE-2013-1902 (PostgreSQL < 9.x) - version too old
- CVE-2024-1597 (pgjdbc JDBC driver) - different product, not the PostgreSQL server

## 5. Ambiguities and Open Questions

1. **Database privileges granularity:** The `postgresql_user` module with `NOSUPERUSER` + `LOGIN` is used for developers, but specific table/schema-level grants are not defined. The exact read-only scope (SELECT-only vs broader) is ambiguous - `NOSUPERUSER` does not inherently mean read-only.

2. **pg_hba implicit deny:** The pg_hba configuration uses `scram-sha-256` for the explicitly allowed subnet, but the default behavior for unspecified sources is implicit deny. This is captured as rule-007 but should be verified on actual deployment.

3. **No sudoers configuration found:** The `sudo` group is referenced in SSH AllowGroups but no `sudoers` file or `visudo` task was found. The NOPASSWD status of sudo access is unspecified.

4. **Credentials handling:** No vault-encrypted credentials or password management tasks were found in the Ansible configuration. Authentication mechanisms (password vs key-based) for SSH and PostgreSQL are not explicitly managed.

5. **DMZ firewall - internet-wide exposure:** The DMZ firewall allows 0.0.0.0/0 on port 443/tcp. While this is expected for a reverse proxy, the absence of rate-limiting or WAF configuration is a gap worth noting for PCI compliance.

6. **No monitoring/NIDS configuration:** No Nagios, SELinux, or intrusion detection configurations were found in the Ansible roles.

## 6. Security Observations

- **Defense-in-depth architecture:** Three-tier network segmentation (DMZ -> App -> Data) with progressively restrictive firewall rules.
- **Least-privilege SSH:** DMZ hosts only allow sudo group SSH access, limiting attack surface on internet-facing hosts.
- **PostgreSQL network isolation:** Only the appservers subnet can reach the database, preventing direct DMZ or internet access.
- **Missing hardening:** No fail2ban, no AppArmor/SELinux, no SSH key-only enforcement visible in the configuration.
