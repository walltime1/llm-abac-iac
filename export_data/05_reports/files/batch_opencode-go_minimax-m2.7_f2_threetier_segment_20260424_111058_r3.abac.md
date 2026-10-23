# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 11:15:49_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 8 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f2_threetier_segmented`_

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
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "domain": [
        "secret",
        "confidential"
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
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all",
        "source": "inventory.ini"
      },
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "roles/dmz/tasks/main.yml"
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
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "dmz_subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "group_vars/dmz.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml"
    },
    "retention_days": {
      "default": 365,
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
    "description": "SSH login allowed for sudo group on all production hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "in": [
          "dmz",
          "app",
          "data"
        ]
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
      "lines": "22-25"
    }
  },
  {
    "id": "rule-002",
    "description": "SSH login allowed for dba group on database servers",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
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
      "lines": "32-35"
    }
  },
  {
    "id": "rule-003",
    "description": "SSH login allowed for developers group on application servers only",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
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
      "file": "group_vars/appservers.yml",
      "task": "allowed_ssh_groups definition",
      "lines": "3"
    }
  },
  {
    "id": "rule-004",
    "description": "DMZ subnet allowed to connect to app service port 8080 on appservers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      },
      "port": {
        "equals": 8080
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "17-21"
    }
  },
  {
    "id": "rule-005",
    "description": "Internet access allowed to HTTPS port on DMZ servers",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dmz"
      },
      "port": {
        "equals": 443
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "18-23"
    }
  },
  {
    "id": "rule-006",
    "description": "App servers subnet allowed to connect to PostgreSQL database on port 5432",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "27-31"
    }
  },
  {
    "id": "rule-007",
    "description": "DBA group members granted SUPERUSER privileges on PostgreSQL",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
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
      "lines": "13-17"
    }
  },
  {
    "id": "rule-008",
    "description": "Developer group members granted NOSUPERUSER login on PostgreSQL",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
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
      "task": "Create DB read-only role for developers",
      "lines": "19-23"
    }
  },
  {
    "id": "rule-009",
    "description": "Admin users with sudo group membership can be provisioned on app servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "8-13"
    }
  },
  {
    "id": "rule-010",
    "description": "Postgres user has full access to database data directory",
    "subject_condition": {
      "user": {
        "equals": "postgres"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/lib/postgresql/data"
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
    "id": "rule-011",
    "description": "DBA users can be provisioned on database servers",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-012",
    "description": "Default deny all unspecified access",
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
    "id": "rule-013",
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
    "environment_condition": {},
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
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
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {},
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
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
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {},
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "nginx heap buffer overflow",
    "is_remote": true,
    "recommendation": "Update nginx to latest patch version"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "nginx alias traversal",
    "is_remote": true,
    "recommendation": "Update nginx to latest patch version"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "nginx HTTP/2 vulnerability",
    "is_remote": true,
    "recommendation": "Update nginx to latest patch version"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "13.7",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "PostgreSQL privilege escalation",
    "is_remote": true,
    "recommendation": "Update PostgreSQL to latest patch version"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "13.7",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "PostgreSQL format string bug",
    "is_remote": true,
    "recommendation": "Update PostgreSQL to latest patch version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "13.7",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "PostgreSQL SQL injection",
    "is_remote": true,
    "recommendation": "Update PostgreSQL to latest patch version"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "OpenSSH remote code execution",
    "is_remote": true,
    "recommendation": "Update OpenSSH to latest patch version"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "OpenSSH buffer overflow",
    "is_remote": true,
    "recommendation": "Update OpenSSH to latest patch version"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "OpenSSH authentication bypass",
    "is_remote": true,
    "recommendation": "Update OpenSSH to latest patch version"
  }
]
```

## Report

# ABAC Policy Mining Report — Three-Tier Segmented Architecture

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy extracted from the Ansible configuration for the three-tier segmented environment at **segcorp**. The infrastructure implements a PCI-compliant three-tier architecture with DMZ (proxy), application, and database tiers.

- **Organization:** segcorp
- **Environment:** production
- **Compliance Tier:** PCI
- **Hosts:** 3 (proxy01, app01, db01)
- **Users:** 3 (admin, developer, dba)
- **Rules Extracted:** 12 (11 permit, 1 deny)
- **Critical Vulnerabilities:** 9

---

## Phase 1: Attribute Catalog

### Subjects

| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |

**Groups:** sudo, developers, dba  
**Clearance Levels:** secret, confidential  
**Departments:** operations, engineering, data

### Resources

#### Hosts

| Hostname | IP | Role | Zone | Inventory Group |
|----------|-----|------|------|-----------------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

#### Services

| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| ssh | 22 | tcp | all |
| nginx | 443 | tcp | dmz |
| app | 8080 | tcp | appservers |
| postgresql | 5432 | tcp | dbservers |

#### Networks

| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | dmz_subnet |
| 10.0.2.0/24 | app | app_subnet |
| 0.0.0.0/0 | internet | any |

### Environment

- **Organization:** segcorp
- **Environment:** production
- **Compliance Tier:** PCI
- **Log Retention:** 365 days

---

## Phase 1.5: Vulnerability Assessment

### Pinned Software Versions

| Product | Version |
|---------|---------|
| nginx | 1.20.0-1~focal |
| openssh-server | 1:9.6p1-3ubuntu1 |
| postgresql-13 | 13.7-1.pgdg20.04+1 |

### Critical Vulnerabilities Found

| CVE ID | Product | CVSS | Description |
|--------|---------|------|-------------|
| CVE-2016-0746 | nginx | 9.8 | Heap buffer overflow |
| CVE-2021-46461 | nginx | 9.8 | Alias traversal |
| CVE-2017-20005 | nginx | 9.8 | HTTP/2 vulnerability |
| CVE-2007-3279 | postgresql | 10.0 | Privilege escalation |
| CVE-2002-1399 | postgresql | 10.0 | Format string bug |
| CVE-2013-1903 | postgresql | 10.0 | SQL injection |
| CVE-2003-0786 | openssh | 10.0 | Remote code execution |
| CVE-2000-0999 | openssh | 10.0 | Buffer overflow |
| CVE-2000-0525 | openssh | 10.0 | Authentication bypass |

**Recommendation:** All three products have critical CVEs. Priority patching recommended for OpenSSH (10.0 CVSS) and PostgreSQL (10.0 CVSS).

---

## Phase 2: ABAC Rules

| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-001 | sudo | all zones | ssh:login | permit |
| rule-002 | dba | dbservers | ssh:login | permit |
| rule-003 | developers | appservers | ssh:login | permit |
| rule-004 | DMZ subnet (10.0.1.0/24) | appservers:8080 | network:connect | permit |
| rule-005 | internet (0.0.0.0/0) | dmz:443 | network:connect | permit |
| rule-006 | app subnet (10.0.2.0/24) | dbservers:5432 | network:connect | permit |
| rule-007 | dba | postgresql | db:login (SUPERUSER) | permit |
| rule-008 | developers | postgresql | db:login (NOSUPERUSER) | permit |
| rule-009 | sudo | appservers | user:create | permit |
| rule-010 | postgres | /var/lib/postgresql/data | filesystem:write | permit |
| rule-011 | dba | dbservers | user:create | permit |
| rule-012 | all | all | * | deny |

---

## Phase 1.6: Security-Relevant Files

The following files were identified as security-relevant:

- `roles/app/tasks/main.yml` — SSH restrictions, firewall, user provisioning
- `roles/db/tasks/main.yml` — PostgreSQL config, pg_hba.conf, SSH restrictions
- `roles/dmz/tasks/main.yml` — nginx, firewall, SSH restrictions

---

## Ambiguities & Notes

1. **Credentials:** No plaintext credentials found in Ansible config. Authentication is managed via SSH key-based auth and group membership.
2. **Session Logging:** No explicit audit/logging configuration found. Consider adding obligations for session logging on SSH access.
3. **Implicit Deny:** PostgreSQL `pg_hba.conf` uses explicit `host all all <subnet> scram-sha-256` entries; default deny is implicit via PostgreSQL's default behavior.
4. **Sudo Password:** No `nopassword` flag found in user provisioning; sudo requires password (secure default).

---

## Conclusion

The ABAC policy correctly reflects the three-tier segmented architecture:
- **DMZ:** Public HTTPS access, SSH restricted to sudo group only
- **App Tier:** DMZ-to-app firewall rule, developers allowed SSH, app port exposed
- **Data Tier:** App-to-DB firewall rule, DBA gets SUPERUSER, developers get read-only

All rules include provenance and the default-deny rule ensures no unspecified access is permitted.
