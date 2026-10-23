# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:59:57_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 14_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f3_privsep_service_accounts`_

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
        "name": "redis",
        "uid": null,
        "groups": [],
        "department": "system",
        "clearance": null,
        "source": "roles/cache/tasks/main.yml"
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [
          "postgres"
        ],
        "department": "system",
        "clearance": null,
        "source": "roles/db/tasks/main.yml"
      },
      {
        "name": "www-data",
        "uid": 33,
        "groups": [
          "www-data"
        ],
        "department": "system",
        "clearance": null,
        "source": "roles/web/tasks/main.yml"
      }
    ],
    "users_domain": {
      "name": [
        "admin",
        "developer",
        "redis",
        "postgres",
        "www-data"
      ]
    },
    "groups": [
      "sudo",
      "developers",
      "www-data",
      "postgres"
    ],
    "groups_domain": {
      "name": [
        "sudo",
        "developers",
        "www-data",
        "postgres"
      ]
    },
    "clearance_levels": [
      "secret",
      "confidential"
    ],
    "departments": [
      "operations",
      "engineering",
      "system"
    ],
    "source_network": [
      "10.0.1.0/24",
      "0.0.0.0/0"
    ]
  },
  "resources": {
    "hosts": [
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "cache01.lab.local",
        "ip": "10.0.2.20",
        "role": "cache",
        "zone": "internal",
        "inventory_group": "cacheservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "group_vars/webservers.yml"
      },
      {
        "name": "openssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "redis",
        "port": 6379,
        "protocol": "tcp",
        "host_group": "cacheservers",
        "source": "group_vars/cacheservers.yml"
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
      },
      {
        "path": "/var/www/html",
        "owner": "www-data",
        "group": "www-data",
        "mode": "0750",
        "service": "nginx",
        "source": "roles/web/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers_subnet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "internal",
        "label": "internal_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "any",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      }
    ]
  },
  "environment": {
    "org": "privsep-corp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "group_vars/all.yml"
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
      "service": {
        "equals": "openssh"
      },
      "port": {
        "equals": 22
      },
      "role": {
        "equals": "frontend"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        42,
        46
      ]
    }
  },
  {
    "id": "rule-002",
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
      "role": {
        "equals": "frontend"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        34,
        40
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
      "service": {
        "equals": "redis"
      },
      "port": {
        "equals": 6379
      },
      "role": {
        "equals": "cache"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": [
        13,
        19
      ]
    }
  },
  {
    "id": "rule-004",
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
      "role": {
        "equals": "primary"
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        16,
        20
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/www/html"
      },
      "owner": {
        "equals": "www-data"
      },
      "group": {
        "equals": "www-data"
      },
      "mode": {
        "equals": "0750"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": [
        26,
        32
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/www/html"
      },
      "owner": {
        "equals": "www-data"
      },
      "group": {
        "equals": "www-data"
      },
      "mode": {
        "equals": "0750"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": [
        26,
        32
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": [
        6,
        12
      ]
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": [
        6,
        12
      ]
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sudo"
      }
    },
    "action": "sudo:execute",
    "effect": "deny",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure www-data has NO sudo access",
      "lines": [
        48,
        51
      ]
    }
  },
  {
    "id": "rule-010",
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
      "file": "policy",
      "task": "default-deny",
      "lines": [
        0,
        0
      ]
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
        "equals": "soc2"
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
    "id": "rule-012",
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
        "equals": "soc2"
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
    "id": "rule-013",
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
      "compliance_tier": {
        "equals": "soc2"
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
    "id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "redis"
      },
      "port": {
        "equals": 6379
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2021-46461 impact on nginx 1.20.0. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2016-0746 impact on nginx 1.20.0. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2017-20005 impact on nginx 1.20.0. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2009-3555 impact on nginx 1.20.0. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.7,
    "severity": "high",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2021-23017 impact on nginx 1.20.0. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2000-0999 impact on openssh 9.6p1. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2000-0525 impact on openssh 9.6p1. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2003-0693 impact on openssh 9.6p1. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2003-0786 impact on openssh 9.6p1. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2001-0144 impact on openssh 9.6p1. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2002-1399 impact on postgresql 16.2. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2013-1902 impact on postgresql 16.2. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2007-3279 impact on postgresql 16.2. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2013-1903 impact on postgresql 16.2. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2024-1597 impact on postgresql 16.2. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2015-4335",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2015-4335 impact on redis 7.0.11. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2022-0543 impact on redis 7.0.11. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 9.9,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2025-49844 impact on redis 7.0.11. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2016-8339",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2016-8339 impact on redis 7.0.11. Upgrade if affected."
  },
  {
    "cve_id": "CVE-2023-31654",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review CVE-2023-31654 impact on redis 7.0.11. Upgrade if affected."
  }
]
```

## Report

# ABAC Policy Report — privsep-corp

## Summary

Mined 10 ABAC rules from an Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration defines a production SOC2-compliant environment with three host groups (webservers, dbservers, cacheservers), two human users (admin, developer), and three system users (redis, postgres, www-data).

## Attribute Catalog

### Subjects
- **Users**: admin (uid 1001, sudo, operations, secret), developer (uid 1002, developers, engineering, confidential), redis (system), postgres (system), www-data (uid 33, www-data, system)
- **Groups**: sudo, developers, www-data, postgres
- **Clearance levels**: secret, confidential
- **Departments**: operations, engineering, system

### Resources
- **Hosts**: web01.lab.local (10.0.1.10, frontend, dmz), db01.lab.local (10.0.2.10, primary, internal), cache01.lab.local (10.0.2.20, cache, internal)
- **Services**: nginx:443/tcp, openssh:22/tcp, postgresql:5432/tcp, redis:6379/tcp
- **Paths**: /var/lib/postgresql/data (postgres:postgres 0700), /var/www/html (www-data:www-data 0750)
- **Networks**: 10.0.1.0/24 (dmz), 10.0.2.0/24 (internal), 0.0.0.0/0 (internet)

### Environment
- **Org**: privsep-corp
- **Environment**: production
- **Compliance tier**: soc2
- **Log retention**: 90 days

## Rules Extracted

| ID | Action | Effect | Subject | Resource | Source |
|----|--------|--------|---------|----------|--------|
| rule-001 | ssh:login | permit | groups in [sudo] | openssh:22, frontend | roles/web/tasks/main.yml |
| rule-002 | network:connect | permit | source_network = 0.0.0.0/0 | nginx:443, frontend | roles/web/tasks/main.yml |
| rule-003 | network:connect | permit | source_network = 10.0.1.0/24 | redis:6379, cache | roles/cache/tasks/main.yml |
| rule-004 | db:login | permit | source_network = 10.0.1.0/24 | postgresql:5432, primary, all DBs | roles/db/tasks/main.yml |
| rule-005 | filesystem:write | permit | groups in [www-data] | /var/www/html (0750) | roles/web/tasks/main.yml |
| rule-006 | filesystem:read | permit | groups in [www-data] | /var/www/html (0750) | roles/web/tasks/main.yml |
| rule-007 | filesystem:write | permit | groups in [postgres] | /var/lib/postgresql/data (0700) | roles/db/tasks/main.yml |
| rule-008 | filesystem:read | permit | groups in [postgres] | /var/lib/postgresql/data (0700) | roles/db/tasks/main.yml |
| rule-009 | sudo:execute | deny | groups in [www-data] | sudo | roles/web/tasks/main.yml |
| rule-010 | * | deny | all | all | policy (default-deny) |

## Vulnerability Assessment

Scanned 4 pinned packages (nginx 1.20.0, openssh 9.6p1, postgresql 16.2, redis 7.0.11) against critical/remote and KEV vulnerability databases. Found 20 CVEs total (5 per package). All flagged for manual review; version-specific impact assessment required.

### Notable findings
- **nginx**: CVE-2021-23017 (resolver vulnerability), CVE-2021-46461
- **openssh**: Multiple legacy CVEs (2000-2003 era); pinned version 9.6p1 likely not affected by ancient issues but requires verification
- **postgresql**: CVE-2024-1597 (recent); older CVEs unlikely to affect v16.2
- **redis**: CVE-2022-0543 (Lua sandbox escape via Debian packaging), CVE-2023-31654

## Ambiguities

1. **No explicit SSH port defined** in group_vars — assumed standard port 22 from openssh-server package installation.
2. **No pg_hba DENY rules** explicitly defined — implicit deny-default assumed for PostgreSQL connections not matching the allow rule.
3. **System user group memberships** (redis, postgres) inferred from standard Linux conventions, not explicitly defined in group_vars.
4. **No session logging/audit obligations** found in the Ansible configuration — no obligations attached to rules.
5. **No sudoers file or sudo configuration** beyond the www-data deny rule — admin sudo privileges assumed but not explicitly configured in these files.
6. **Vulnerability version matching** is heuristic — the pinned Debian/Ubuntu package versions may not map directly to upstream version strings in CVE databases.
