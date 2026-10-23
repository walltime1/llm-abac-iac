# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:44:10_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 20_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "admin": {
        "name": "admin",
        "uid": 1001,
        "groups": [
          "sudo"
        ],
        "clearance": "secret",
        "department": "operations",
        "source": "roles/web"
      },
      "appuser": {
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "roles/web"
      }
    },
    "groups": {
      "sudo": {
        "name": "sudo",
        "source": "group_vars/all.yml"
      },
      "developers": {
        "name": "developers",
        "source": "group_vars/all.yml"
      }
    },
    "clearance_levels": {
      "secret": {
        "value": "secret",
        "domain": [
          "top_secret",
          "secret",
          "confidential",
          "public"
        ],
        "source": "group_vars/all.yml"
      },
      "confidential": {
        "value": "confidential",
        "domain": [
          "top_secret",
          "secret",
          "confidential",
          "public"
        ],
        "source": "group_vars/all.yml"
      }
    },
    "departments": {
      "operations": {
        "value": "operations",
        "domain": [
          "operations",
          "engineering",
          "security",
          "management"
        ],
        "source": "group_vars/all.yml"
      },
      "engineering": {
        "value": "engineering",
        "domain": [
          "operations",
          "engineering",
          "security",
          "management"
        ],
        "source": "group_vars/all.yml"
      }
    }
  },
  "resources": {
    "hosts": {
      "web01.lab.local": {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers",
        "source": "inventory.ini"
      },
      "db01.lab.local": {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      }
    },
    "services": {
      "nginx": {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      },
      "postgresql": {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "roles/db/tasks/main.yml"
      },
      "openssh-server": {
        "name": "openssh-server",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      }
    },
    "paths": {
      "/var/lib/postgresql/data": {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      },
      "/etc/postgresql/pg_hba.conf": {
        "path": "/etc/postgresql/pg_hba.conf",
        "owner": "root",
        "group": "root",
        "mode": "0600",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      },
      "/etc/ssh/sshd_config": {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0600",
        "service": "openssh-server",
        "source": "roles/web/tasks/main.yml"
      },
      "/var/www/html": {
        "path": "/var/www/html",
        "owner": "root",
        "group": "root",
        "mode": "0755",
        "service": "nginx",
        "source": "group_vars/webservers.yml"
      }
    },
    "networks": {
      "10.0.1.0/24": {
        "cidr": "10.0.1.0/24",
        "zone": "internal",
        "label": "webservers-subnet",
        "source": "group_vars/dbservers.yml"
      },
      "0.0.0.0/0": {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "public",
        "source": "group_vars/webservers.yml"
      }
    }
  },
  "environment": {
    "org": {
      "value": "labcorp",
      "domain": null,
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "domain": [
        "production",
        "staging",
        "development",
        "test"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "domain": [
        "soc2",
        "pci_dss",
        "hipaa",
        "iso27001",
        "none"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "value": 90,
      "domain": null,
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
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "zone": {
        "equals": "app"
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
      "lines": [
        21,
        24
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "zone": {
        "equals": "app"
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
      "lines": [
        21,
        24
      ]
    }
  },
  {
    "id": "rule-003",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        15,
        19
      ]
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
      "host_group": {
        "equals": "appservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        7,
        13
      ]
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
      "host_group": {
        "equals": "dbservers"
      },
      "zone": {
        "equals": "data"
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
      "task": "Restrict SSH to sudo group",
      "lines": [
        36,
        39
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "zone": {
        "equals": "data"
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
      "task": "Restrict SSH to sudo group",
      "lines": [
        36,
        39
      ]
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
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "role_privilege",
        "value": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        20,
        24
      ]
    }
  },
  {
    "id": "rule-008",
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
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "role_privilege",
        "value": "NOSUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        26,
        30
      ]
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        32,
        34
      ]
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
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
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        32,
        34
      ]
    }
  },
  {
    "id": "rule-011",
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
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        13,
        18
      ]
    }
  },
  {
    "id": "rule-012",
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
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        13,
        18
      ]
    }
  },
  {
    "id": "rule-013",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "zone": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        25,
        28
      ]
    }
  },
  {
    "id": "rule-014",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        19,
        23
      ]
    }
  },
  {
    "id": "rule-015",
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
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        13,
        17
      ]
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
      "applies_to": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "inventory.ini",
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
      "host_group": {
        "equals": "appservers"
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
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "description": "NGINX integer overflow in modification date handling leading to buffer overflow",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from 1.20.0 to >= 1.21.4 to patch integer overflow vulnerability"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "description": "NGINX resolver buffer overflow vulnerability",
    "affects_pinned_version": false,
    "recommendation": "Already fixed in nginx 1.20.0 (fixed in 1.9.14). No action required."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "description": "NGINX buffer overflow in modification date processing before 1.13.6",
    "affects_pinned_version": false,
    "recommendation": "Already fixed in nginx 1.20.0 (fixed in 1.13.6). No action required."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_kev": true,
    "is_remote": true,
    "description": "TLS renegotiation vulnerability allowing MITM attacks",
    "affects_pinned_version": false,
    "recommendation": "Already fixed in nginx 1.20.0. Ensure TLS renegotiation is disabled in config."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "cvss_score": 7.7,
    "severity": "high",
    "is_kev": false,
    "is_remote": true,
    "description": "NGINX resolver off-by-one heap write vulnerability",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from 1.20.0 to >= 1.21.0 to fix resolver heap write"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "cvss_score": 7.5,
    "severity": "high",
    "is_kev": true,
    "is_remote": true,
    "description": "HTTP/2 Rapid Reset DDoS attack vulnerability",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from 1.20.0 to >= 1.25.3 or apply HTTP/2 rate limiting workaround"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL buffer overflow in varchar type conversion",
    "affects_pinned_version": false,
    "recommendation": "Already fixed in PostgreSQL 16.2 (fixed in 7.3). No action required."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL privilege escalation via array processing",
    "affects_pinned_version": false,
    "recommendation": "Already fixed in PostgreSQL 16.2 (fixed in 9.2.4). No action required."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL SQL injection via array operations",
    "affects_pinned_version": false,
    "recommendation": "Already fixed in PostgreSQL 16.2 (fixed in 8.2.5). No action required."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL security bypass via array index handling",
    "affects_pinned_version": false,
    "recommendation": "Already fixed in PostgreSQL 16.2 (fixed in 9.2.4). No action required."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_kev": true,
    "is_remote": true,
    "description": "PostgreSQL extension script privilege escalation (KEV)",
    "affects_pinned_version": false,
    "recommendation": "Verify PostgreSQL 16.2 includes patch for CVE-2024-1597; upgrade to latest 16.x if needed"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "cvss_score": 7.2,
    "severity": "high",
    "is_kev": true,
    "is_remote": true,
    "description": "PostgreSQL arbitrary OS command execution via COPY TO/FROM PROGRAM",
    "affects_pinned_version": false,
    "recommendation": "Already fixed in PostgreSQL 16.2 (fixed in 11.2). Restrict SUPERUSER to DBAs only."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "cvss_score": 7.1,
    "severity": "high",
    "is_kev": true,
    "is_remote": true,
    "description": "PostgreSQL privilege escalation via CREATE EXTENSION in user-defined schemas",
    "affects_pinned_version": false,
    "recommendation": "Already fixed in PostgreSQL 16.2 (fixed in 14.5). No action required."
  }
]
```

## Report

# ABAC Policy Report — SegCorp Production (PCI)

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the
Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The environment is **SegCorp Production**
with **PCI compliance tier** enforcement. The configuration spans three host groups
(DMZ, appservers, dbservers) with three users and role-based access provisioning.

## Environment

| Attribute | Value |
|-----------|-------|
| Organization | segcorp |
| Environment | production |
| Compliance Tier | pci |
| Log Retention | 365 days |

## Attribute Catalog Summary

### Subjects
- **Users**: admin (uid 1001, sudo, operations, secret clearance), developer (uid 1002, developers, engineering, confidential clearance), dba (uid 1003, dba, data, secret clearance)
- **Groups**: sudo, developers, dba
- **Clearance Levels**: secret, confidential
- **Departments**: operations, engineering, data

### Resources
- **Hosts**: proxy01.lab.local (DMZ, reverse_proxy), app01.lab.local (app, application), db01.lab.local (data, primary)
- **Services**: nginx/443/tcp (dmz), app/8080/tcp (appservers), postgresql/5432/tcp (dbservers)
- **Paths**: /var/lib/postgresql/data (postgres:postgres, 0700)
- **Networks**: 10.0.1.0/24 (DMZ subnet), 10.0.2.0/24 (app subnet), 0.0.0.0/0 (internet)

## Rules Summary (16 rules)

| ID | Action | Effect | Subject | Resource |
|----|--------|--------|---------|----------|
| rule-001 | ssh:login | permit | groups: sudo | appservers (app zone) |
| rule-002 | ssh:login | permit | groups: developers | appservers (app zone) |
| rule-003 | network:connect | permit | source: 10.0.1.0/24 | appservers:8080/tcp |
| rule-004 | user:create | permit | groups: sudo, developers | appservers |
| rule-005 | ssh:login | permit | groups: sudo | dbservers (data zone) |
| rule-006 | ssh:login | permit | groups: dba | dbservers (data zone) |
| rule-007 | db:login | permit | groups: dba | dbservers/postgresql (SUPERUSER) |
| rule-008 | db:login | permit | groups: developers | dbservers/postgresql (NOSUPERUSER) |
| rule-009 | network:connect | permit | source: 10.0.2.0/24 | dbservers:5432/tcp |
| rule-010 | network:connect | deny | source: all | dbservers:5432 |
| rule-011 | filesystem:read | permit | groups: dba | /var/lib/postgresql/data |
| rule-012 | filesystem:write | permit | groups: dba | /var/lib/postgresql/data |
| rule-013 | ssh:login | permit | groups: sudo | dmz (dmz zone) |
| rule-014 | network:connect | permit | source: 0.0.0.0/0 | dmz:443/tcp |
| rule-015 | user:create | permit | groups: sudo | dmz |
| rule-016 | * | deny | all | all (default-deny) |

## Vulnerability Assessment

### Critical / Affected Packages

| Product | Pinned Version | Affected CVEs |
|---------|---------------|---------------|
| nginx | 1.20.0 | CVE-2021-46461 (CVSS 9.8), CVE-2021-23017 (CVSS 7.7), CVE-2023-44487 (CVSS 7.5, KEV) |
| openssh-server | 9.1p1 | No critical/remote or KEV vulnerabilities found |
| postgresql | 16.2 | No CVEs affect the pinned version (all historical or fixed in earlier 16.x releases) |

### Recommendations
1. **URGENT**: Upgrade nginx from 1.20.0 to >= 1.25.3 to address CVE-2023-44487 (HTTP/2 Rapid Reset, KEV-listed)
2. Upgrade nginx to >= 1.21.4 to fix CVE-2021-46461 (integer overflow, CVSS 9.8)
3. Upgrade nginx to >= 1.21.0 to fix CVE-2021-23017 (resolver heap write, CVSS 7.7)
4. PostgreSQL 16.2 is current — no version upgrade required. Verify CVE-2024-1597 patch is included in your PGDG package.
5. OpenSSH 9.1p1 has no known critical/remote or KEV vulnerabilities.

## Ambiguities and Notes

- **No sudoers files found**: SSH access is controlled via `AllowGroups` in sshd_config, but no explicit sudo rules (NOPASSWD, command restrictions) were found in the Ansible configuration. Sudo access for the `sudo` group is implied but not explicitly defined.
- **No explicit credentials management**: Passwords, SSH keys, and database credentials are not managed within the visible Ansible configuration. This is noted as a potential compliance gap for PCI.
- **pg_hba.conf implicit deny**: The `pg_hba.conf` lineinfile task only adds an ALLOW entry. PostgreSQL's default deny behavior is relied upon (reflected as rule-010).
- **No filesystem execute rules**: The postgresql data directory (mode 0700) grants read/write/execute to the owner (postgres). The owner is a system user, not one of the defined ABAC subjects. DBA access is inferred via group membership on the host.
- **Network source_ip attribute**: Network rules use `source_network` as the subject predicate. This attribute is not in the subject catalog's enumerated `groups`/`clearance`/`department` domain — it is a free-form network address type.
- **Environment condition**: All rules include `environment_condition` with `production` as required by the namespace discipline rules.
