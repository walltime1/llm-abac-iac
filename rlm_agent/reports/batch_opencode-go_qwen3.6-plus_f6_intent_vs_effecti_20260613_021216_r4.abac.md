# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 02:18:53_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 16_  
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
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [
          "postgres"
        ],
        "clearance": "system",
        "department": "data",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "users_groups": {
      "domain": [
        "sudo",
        "developers",
        "dba",
        "postgres"
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
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
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
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all",
        "source": "group_vars/all.yml"
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
        "label": "Appservers subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "Internet-facing",
        "source": "group_vars/dmz.yml"
      }
    ],
    "host_roles": {
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "host_zones": {
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "host_groups": {
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "protocol_domain": {
      "domain": [
        "tcp",
        "udp"
      ],
      "source": "group_vars/*.yml"
    }
  },
  "environment": {
    "org": "segcorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
    "org_domain": [
      "segcorp"
    ],
    "environment_domain": [
      "production",
      "staging",
      "development"
    ],
    "compliance_tier_domain": [
      "pci",
      "hipaa",
      "sox",
      "internal"
    ],
    "source": "group_vars/all.yml; inventory.ini"
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
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
      },
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
        24,
        28
      ]
    }
  },
  {
    "rule_id": "rule-002",
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
      },
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
        41,
        45
      ]
    }
  },
  {
    "rule_id": "rule-003",
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
      },
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
        30,
        34
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
        16,
        22
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
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
      "compliance_tier": {
        "equals": "pci"
      },
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
        22,
        28
      ]
    }
  },
  {
    "rule_id": "rule-006",
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
      "port": {
        "equals": 5432
      },
      "database": {
        "equals": "all"
      },
      "schema": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "audit",
        "description": "SUPERUSER role - full database privileges"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        21,
        26
      ]
    }
  },
  {
    "rule_id": "rule-007",
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
      "port": {
        "equals": 5432
      },
      "database": {
        "equals": "all"
      },
      "schema": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "audit",
        "description": "NOSUPERUSER role - read-only access"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        28,
        33
      ]
    }
  },
  {
    "rule_id": "rule-008",
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
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
        35,
        39
      ]
    }
  },
  {
    "rule_id": "rule-009",
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
      "compliance_tier": {
        "equals": "pci"
      },
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
        19
      ]
    }
  },
  {
    "rule_id": "rule-010",
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
      "compliance_tier": {
        "equals": "pci"
      },
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
        14
      ]
    }
  },
  {
    "rule_id": "rule-011",
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
      "compliance_tier": {
        "equals": "pci"
      },
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
        20
      ]
    }
  },
  {
    "rule_id": "rule-012",
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
      "lines": [
        0,
        0
      ]
    }
  },
  {
    "id": "rule-001",
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
      "compliance_tier": {
        "equals": "pci"
      },
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
    "id": "rule-002",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
    "id": "rule-003",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
    "id": "rule-004",
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
      },
      "port": {
        "equals": 5432
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "is_remote": true,
    "description": "TLS renegotiation vulnerability in nginx and other servers allowing MiTM attacks.",
    "remediation": "Disable unsafe renegotiation or update to patched version.",
    "affects_pinned_version": false,
    "recommendation": "CVE-2009-3555 does not affect nginx 1.20.0 (fixed in 0.7.64+). No action needed."
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.8,
    "is_kev": false,
    "is_remote": true,
    "description": "Buffer overflow in nginx resolver allowing denial of service.",
    "remediation": "Update to nginx 1.9.10 or later.",
    "affects_pinned_version": false,
    "recommendation": "CVE-2016-0746 does not affect nginx 1.20.0 (fixed in 1.9.10+). No action needed."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "medium",
    "cvss_score": 5.3,
    "is_kev": false,
    "is_remote": true,
    "description": "ngx_http_mp4_module buffer over-read in nginx.",
    "remediation": "Update to nginx 1.21.5 or later.",
    "affects_pinned_version": false,
    "recommendation": "CVE-2021-46461 does not affect nginx 1.20.0 with current config (module not used). Monitor for mp4 module usage."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "is_remote": true,
    "description": "Improper limitation of recursive references in yaml_load in nginx.",
    "remediation": "Update to patched version.",
    "affects_pinned_version": false,
    "recommendation": "CVE-2017-20005 does not affect nginx 1.20.0 (fixed in 1.17.3+). No action needed."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.7,
    "is_kev": false,
    "is_remote": true,
    "description": "Off-by-one buffer overflow in the DNS resolver of nginx.",
    "remediation": "Update to nginx 1.20.1 or later.",
    "affects_pinned_version": false,
    "recommendation": "CVE-2021-23017 does not affect nginx 1.20.0 (fixed in 1.20.1+). Recommend upgrading to 1.20.1+."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_kev": false,
    "is_remote": true,
    "description": "Integer overflow in PostgreSQL 7.2.1 and earlier when processing invalid integer input.",
    "remediation": "Update to PostgreSQL 7.2.3 or later.",
    "affects_pinned_version": false,
    "recommendation": "CVE-2002-1399 does not affect PostgreSQL 16.2 (fixed in 7.2.3+). No action needed."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL 8.1 with plpgsql grants privileges to PUBLIC allowing remote code execution.",
    "remediation": "Restrict PUBLIC privileges on plpgsql language or update PostgreSQL.",
    "affects_pinned_version": false,
    "recommendation": "CVE-2007-3279 does not affect PostgreSQL 16.2 (fixed in 8.1+). No action needed."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "is_remote": true,
    "description": "Heap buffer overflow in PostgreSQL full-text search (FTS) via tsvector_update_trigger.",
    "remediation": "Update to PostgreSQL 16.3+ or 15.7+.",
    "affects_pinned_version": true,
    "recommendation": "CVE-2024-1597 AFFECTS PostgreSQL 16.2. UPGRADE to 16.3+ immediately. Active exploitation confirmed (KEV)."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 9.0,
    "is_kev": false,
    "is_remote": true,
    "description": "Multiple buffer overflow vulnerabilities in PostgreSQL pgcrypto module.",
    "remediation": "Update to PostgreSQL 9.2.4+ or 9.1.9+.",
    "affects_pinned_version": false,
    "recommendation": "CVE-2013-1903 does not affect PostgreSQL 16.2 (fixed in 9.2.4+). No action needed."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 9.0,
    "is_kev": false,
    "is_remote": true,
    "description": "Buffer overflow in PostgreSQL XML parsing functions.",
    "remediation": "Update to PostgreSQL 9.2.4+ or 9.1.9+.",
    "affects_pinned_version": false,
    "recommendation": "CVE-2013-1902 does not affect PostgreSQL 16.2 (fixed in 9.2.4+). No action needed."
  }
]
```

## Report

# ABAC Policy Report — segcorp Production (PCI)

## Executive Summary

This report documents the mined ABAC policy from the segcorp Ansible configuration deployed in a **production** environment with **PCI** compliance tier. The policy covers SSH access control, network firewall rules, PostgreSQL database access, and filesystem permissions across three host zones (DMZ, app, data).

## Policy Scope

- **Organization:** segcorp
- **Environment:** production
- **Compliance Tier:** pci
- **Log Retention:** 365 days
- **Policy Goal:** all (full coverage)

## Attribute Catalog Summary

### Subjects
- **Users (4):** admin (sudo/operations/secret), developer (developers/engineering/confidential), dba (dba/data/secret), postgres (system/data)
- **Groups:** sudo, developers, dba, postgres
- **Clearance Levels:** secret, confidential, system

### Resources
- **Hosts (3):** proxy01.lab.local (dmz/reverse_proxy), app01.lab.local (app/application), db01.lab.local (data/primary)
- **Services:** ssh (22/tcp), nginx (443/tcp), app (8080/tcp), postgresql (5432/tcp)
- **Paths:** /var/lib/postgresql/data (postgres:postgres, 0700)
- **Networks:** 10.0.1.0/24 (dmz), 10.0.2.0/24 (app), 0.0.0.0/0 (internet)

## Rule Summary (12 rules)

| ID | Action | Subject | Resource | Effect |
|----|--------|---------|----------|--------|
| rule-001 | ssh:login | sudo, developers | appservers | permit |
| rule-002 | ssh:login | sudo, dba | dbservers | permit |
| rule-003 | ssh:login | sudo | dmz | permit |
| rule-004 | network:connect | 10.0.1.0/24 | appservers:8080 | permit |
| rule-005 | network:connect | 0.0.0.0/0 | dmz:443 | permit |
| rule-006 | db:login (SUPERUSER) | dba | dbservers:postgresql | permit |
| rule-007 | db:login (NOSUPERUSER) | developers | dbservers:postgresql | permit |
| rule-008 | network:connect | 10.0.2.0/24 | dbservers:5432 | permit |
| rule-009 | filesystem:read | postgres | /var/lib/postgresql/data | permit |
| rule-010 | user:create | sudo, developers | appservers | permit |
| rule-011 | user:create | sudo | dmz | permit |
| rule-012 | * | all | all | deny |

## Vulnerability Assessment

### Pinned Software Versions
| Product | Pinned Version | Status |
|---------|---------------|--------|
| nginx | 1.20.0 | ⚠️ CVE-2021-23017 (HIGH, fixed in 1.20.1) — recommend upgrade |
| openssh-server | 9.1p1 | ✅ No critical/remote CVEs found |
| postgresql | 16.2 | 🚨 **CVE-2024-1597 (CRITICAL, KEV)** — affects 16.2, upgrade to 16.3+ immediately |

### Active Exploits (KEV)
- **CVE-2024-1597** (PostgreSQL): Heap buffer overflow in full-text search. Actively exploited in the wild. PostgreSQL 16.2 is vulnerable. **IMMEDIATE ACTION REQUIRED.**
- **CVE-2009-3555** (nginx): TLS renegotiation MiTM. Listed in KEV but does not affect nginx 1.20.0.

## Security Observations

1. **Defense in Depth:** SSH access is restricted per host group using AllowGroups — dmz only allows sudo, appservers allows sudo+developers, dbservers allows sudo+dba.
2. **Network Segmentation:** Firewall rules enforce zone-based access: DMZ→app (10.0.1.0/24→8080), app→db (10.0.2.0/24→5432), internet→dmz (0.0.0.0/0→443).
3. **Database Privilege Separation:** DBAs get SUPERUSER, developers get NOSUPERUSER (read-only).
4. **Filesystem Hardening:** PostgreSQL data directory is mode 0700, owned by postgres:postgres.
5. **Default Deny:** Explicit catch-all deny rule ensures no implicit permits.

## Ambiguities

1. **No hardcoded credentials detected** in the scanned Ansible files. No vault-encrypted variables or plaintext passwords were found in the role tasks or group_vars.
2. **System user `postgres`** is referenced as filesystem owner but not defined in the `users` list in `group_vars/all.yml`. Added to catalog as system account.
3. **SSH port (22)** is assumed as standard; not explicitly configured in any task file.
4. **pg_hba.conf** is written via `lineinfile` with `host all all <cidr> scram-sha-256` but no explicit deny-all line is present. PostgreSQL default is to reject unlisted connections, so implicit deny is assumed.
5. **Audit/logging obligations:** No explicit audit logging tasks were found in role configurations (e.g., no session recording, no auditd rules). The `default_log_retention_days: 365` is set but enforcement is not visible.
6. **SELinux/AppArmor:** No mandatory access control policies found in the configuration.

## Recommendations

1. **CRITICAL:** Upgrade PostgreSQL from 16.2 to 16.3+ to patch CVE-2024-1597 (active exploitation).
2. **HIGH:** Upgrade nginx from 1.20.0 to 1.20.1+ to patch CVE-2021-23017 (DNS resolver buffer overflow).
3. Consider implementing explicit pg_hba deny-all rules for clarity.
4. Add session logging/audit obligations to SSH access rules.
5. Consider enabling SELinux policies for defense-in-depth on all zones.
