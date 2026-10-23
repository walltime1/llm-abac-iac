# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 22:05:49_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 15 | Rules: 14_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

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
    "groups": [
      "sudo",
      "developers",
      "dba"
    ],
    "clearance_levels": [
      {
        "value": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "value": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "value": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "value": "engineering",
        "source": "group_vars/all.yml"
      },
      {
        "value": "data",
        "source": "group_vars/all.yml"
      }
    ],
    "source_network": {
      "type": "subject",
      "description": "Source CIDR for network-layer rules",
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml",
      "domain": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ]
    },
    "source_zone": {
      "type": "subject",
      "domain": [
        "dmz",
        "app",
        "data",
        "internet"
      ],
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml"
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
      },
      {
        "name": "https",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
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
        "label": "DMZ subnet only",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "appservers subnet only",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet-facing",
        "source": "group_vars/dmz.yml"
      }
    ],
    "host_group": {
      "type": "resource",
      "domain": [
        "dmz",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "type": "resource",
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "resource",
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "resource",
      "domain": [
        "app",
        "postgresql",
        "https",
        "ssh"
      ],
      "source": "group_vars/*,roles/*/tasks/main.yml"
    },
    "port": {
      "type": "resource",
      "domain": [
        8080,
        5432,
        443
      ],
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml"
    },
    "protocol": {
      "type": "resource",
      "domain": [
        "tcp"
      ],
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml"
    },
    "database_privilege": {
      "type": "resource",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "path": {
      "type": "resource",
      "description": "Filesystem path",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "resource",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "resource",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "resource",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "value": "segcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "pci",
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
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
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "24-28"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
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
      },
      "service": {
        "equals": "app"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-23"
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-15"
    }
  },
  {
    "id": "rule-004",
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
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
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
      },
      "service": {
        "equals": "https"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "22-29"
    }
  },
  {
    "id": "rule-006",
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
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "13-21"
    }
  },
  {
    "id": "rule-007",
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
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "41-45"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "database_privilege": {
        "equals": "SUPERUSER"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "21-27"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "database_privilege": {
        "equals": "NOSUPERUSER"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "28-34"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "35-40"
    }
  },
  {
    "id": "rule-011",
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
      "file": "policy",
      "task": "default-deny",
      "lines": "0-0"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
      "port": {
        "equals": 8080
      },
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "app"
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
    "id": "rule-013",
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
      },
      "service": {
        "equals": "https"
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
    "id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
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
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "search_source": "critical_remote",
    "recommendation": "Update to nginx 1.9.10 or later versions."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "search_source": "critical_remote",
    "recommendation": "Update to the latest version of njs where the issue is fixed."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "search_source": "critical_remote",
    "recommendation": "Update to version 1.13.6 or later."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.7,
    "search_source": "critical_remote",
    "recommendation": "Update nginx to the latest version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2016-0742",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.5,
    "search_source": "critical_remote",
    "recommendation": "Update nginx to version 1.8.1, 1.9.10 or later."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "search_source": "critical_remote",
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "search_source": "critical_remote",
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "search_source": "critical_remote",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "search_source": "critical_remote",
    "recommendation": "Update to OpenSSH version 3.7 or later."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "search_source": "critical_remote",
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "search_source": "critical_remote",
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "search_source": "critical_remote",
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "search_source": "critical_remote",
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "search_source": "critical_remote",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "search_source": "critical_remote",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  }
]
```

## Report

# ABAC Policy Mining Report — SegCorp Production Ansible

## 1. Scope
- **Policy goal:** `all`
- **Sources:** `inventory.ini`, `group_vars/*.yml`, `roles/app/tasks/main.yml`, `roles/db/tasks/main.yml`, `roles/dmz/tasks/main.yml`

## 2. Attribute Catalog Summary

### Subjects
- **Users (3):** admin (uid 1001, sudo, operations, secret), developer (uid 1002, developers, engineering, confidential), dba (uid 1003, dba, data, secret)
- **Groups (3):** sudo, developers, dba
- **Clearance levels:** secret, confidential
- **Departments:** operations, engineering, data
- **Network-layer subject attributes:** `source_network` (CIDR), `source_zone` (dmz, app, data, internet)

### Resources
- **Hosts (3):** proxy01.lab.local (dmz/reverse_proxy), app01.lab.local (app/application), db01.lab.local (data/primary)
- **Services (3):** app:8080/tcp, postgresql:5432/tcp, https:443/tcp
- **Paths (1):** `/var/lib/postgresql/data` (owner postgres, group postgres, mode 0700)
- **Networks (3):** 10.0.1.0/24 (dmz), 10.0.2.0/24 (app), 0.0.0.0/0 (internet)
- **Enumerated domains:** host_group {dmz, appservers, dbservers}, role {reverse_proxy, application, primary}, zone {dmz, app, data}, database_privilege {SUPERUSER, NOSUPERUSER}

### Environment
- **org:** segcorp
- **environment:** production
- **compliance_tier:** pci
- **default_log_retention_days:** 365

## 3. Extracted Rules Summary
11 rules extracted (10 permit, 1 default-deny).

| ID | Action | Effect | Subject Condition | Resource Condition | Source |
|---|---|---|---|---|---|
| rule-001 | ssh:login | permit | groups any_of [sudo, developers] | host_group=appservers, service=ssh | roles/app/tasks/main.yml:24-28 |
| rule-002 | network:connect | permit | source_network=10.0.1.0/24 | port=8080, protocol=tcp, host_group=appservers, service=app | roles/app/tasks/main.yml:16-23 |
| rule-003 | user:create | permit | groups any_of [developers, sudo] | host_group=appservers | roles/app/tasks/main.yml:7-15 |
| rule-004 | ssh:login | permit | groups any_of [sudo] | host_group=dmz, service=ssh | roles/dmz/tasks/main.yml:30-34 |
| rule-005 | network:connect | permit | source_network=0.0.0.0/0 | port=443, protocol=tcp, host_group=dmz, service=https | roles/dmz/tasks/main.yml:22-29 |
| rule-006 | user:create | permit | groups any_of [sudo] | host_group=dmz | roles/dmz/tasks/main.yml:13-21 |
| rule-007 | ssh:login | permit | groups any_of [sudo, dba] | host_group=dbservers, service=ssh | roles/db/tasks/main.yml:41-45 |
| rule-008 | db:login | permit | groups any_of [dba] | database_privilege=SUPERUSER, service=postgresql | roles/db/tasks/main.yml:21-27 |
| rule-009 | db:login | permit | groups any_of [developers] | database_privilege=NOSUPERUSER, service=postgresql | roles/db/tasks/main.yml:28-34 |
| rule-010 | network:connect | permit | source_network=10.0.2.0/24 | port=5432, protocol=tcp, host_group=dbservers, service=postgresql | roles/db/tasks/main.yml:35-40 |
| rule-011 | * | deny | applies_to=all | applies_to=all | policy default-deny |

All permit rules are scoped to `environment=production` and `compliance_tier=pci`.

## 4. Vulnerability Assessment
15 CVEs were reviewed across the three pinned packages:

| Product | Pinned Version | CVEs Reviewed |
|---|---|---|
| nginx | 1.20.0 | CVE-2016-0746, CVE-2021-46461, CVE-2017-20005, CVE-2021-23017, CVE-2016-0742 |
| openssh | 9.1p1 | CVE-2000-0999, CVE-2001-0144, CVE-2000-0525, CVE-2003-0693, CVE-2003-0786 |
| postgresql | 16.2 | CVE-2007-3279, CVE-2002-1399, CVE-2024-1597, CVE-2013-1902, CVE-2013-1903 |

**Finding:** Based on heuristic version-string matching against CVE descriptions and affected-version fields, none of the above CVEs were confirmed to affect the pinned versions in this configuration.  
**Caveat:** This is a text-heuristic check, not a rigorous CPE comparison. A full vendor-CPE audit is recommended before production deployment.

## 5. Ambiguities & Gaps
- **No sudoers management:** The Ansible config restricts SSH via `AllowGroups` but does not define sudoers rules or `NOPASSWD` flags. Sudo elevation is therefore out of scope for this policy mine.
- **No session-logging / audit obligations:** No `profile.d` audit scripts or session-recording tasks were found in the roles, so no obligations could be attached to access rules.
- **Coarse database privileges:** The DB role only sets `SUPERUSER` vs `NOSUPERUSER`; no explicit `GRANT SELECT` or schema-level restrictions were mined.
- **Implicit network deny:** Firewall rules use `firewalld` to add allows, but there are no explicit deny rules; the default-deny policy rule captures this at the ABAC layer.
- **Filesystem ACLs:** Only one directory (`/var/lib/postgresql/data`) is created with mode `0700`. No additional ACL or file-permission tasks exist.
- **Heuristic vulnerability evaluation:** Confirmed safe only by string non-match; formal vendor advisory review advised.

## 6. Recommendations
1. **Add sudoers tasks** if users in the `sudo` group require privilege escalation, and mine `nopassword` flags explicitly.
2. **Harden pg_hba.conf** by adding explicit `REJECT` lines for unauthorized subnets rather than relying solely on implicit firewall/ABAC deny.
3. **Patch cadence:** Move pinned versions to a vendor-supported track with automated vulnerability monitoring (true CPE-based matching).
4. **Add audit tasks** (e.g., `tlog`, `auditd`, or `profile.d` logging) so session-logging obligations can be attached to SSH and DB access rules.
5. **Expand filesystem ACL tasks** if application users need scoped path-level read/write access beyond simple `owner/group/mode`.
