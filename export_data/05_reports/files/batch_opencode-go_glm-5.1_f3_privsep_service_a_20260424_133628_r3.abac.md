# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 14:27:55_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 15 | Rules: 21_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f3_privsep_service_accounts`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "type": "string",
      "domain": [
        "admin",
        "developer",
        "www-data",
        "postgres",
        "redis"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "domain": null,
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "www-data",
        "postgres",
        "redis"
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
      "domain": null,
      "source": "roles/web/tasks/main.yml"
    },
    "source_network": {
      "type": "cidr",
      "domain": null,
      "source": "roles/db/tasks/main.yml"
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
      "type": "string",
      "domain": [
        "web01.lab.local",
        "db01.lab.local",
        "cache01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "ip",
      "domain": null,
      "source": "inventory.ini"
    },
    "role": {
      "type": "enum",
      "domain": [
        "frontend",
        "primary",
        "cache"
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
        "cacheservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "ssh",
        "postgresql",
        "redis",
        "sudo"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "domain": [
        443,
        22,
        5432,
        6379
      ],
      "source": "group_vars/webservers.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    "path": {
      "type": "string",
      "domain": null,
      "source": "roles/web/tasks/main.yml"
    },
    "owner": {
      "type": "string",
      "domain": [
        "www-data",
        "postgres"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    "group": {
      "type": "string",
      "domain": [
        "www-data",
        "postgres"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "domain": [
        "0750",
        "0700"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    "database": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "schema": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "enum",
      "domain": [
        "privsep-corp"
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
    "rule_id": "rule-001",
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
      "lines": "28-31"
    }
  },
  {
    "rule_id": "rule-002",
    "subject_condition": {
      "user": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
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
    "effect": "deny",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Create www-data service user (no sudo, no shell)",
      "lines": "12-16"
    }
  },
  {
    "rule_id": "rule-003",
    "subject_condition": {
      "user": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sudo"
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
    "action": "sudo:execute",
    "effect": "deny",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure www-data has NO sudo access",
      "lines": "33-35"
    }
  },
  {
    "rule_id": "rule-004",
    "subject_condition": {
      "source_ip": {
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
      "task": "Firewall — allow HTTPS from internet",
      "lines": "24-27"
    }
  },
  {
    "rule_id": "rule-005",
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
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "19-23"
    }
  },
  {
    "rule_id": "rule-006",
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "19-23"
    }
  },
  {
    "rule_id": "rule-007",
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "19-23"
    }
  },
  {
    "rule_id": "rule-008",
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
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "7-11"
    }
  },
  {
    "rule_id": "rule-009",
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "7-11"
    }
  },
  {
    "rule_id": "rule-010",
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "7-11"
    }
  },
  {
    "rule_id": "rule-011",
    "subject_condition": {
      "user": {
        "equals": "postgres"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres user has no shell access",
      "lines": "13-15"
    }
  },
  {
    "rule_id": "rule-012",
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
      "lines": "17-19"
    }
  },
  {
    "rule_id": "rule-013",
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
      "task": "Allow postgres only from webservers subnet",
      "lines": "17-19"
    }
  },
  {
    "rule_id": "rule-014",
    "subject_condition": {
      "user": {
        "equals": "redis"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "cacheservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "deny",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Ensure redis runs as redis user",
      "lines": "7-10"
    }
  },
  {
    "rule_id": "rule-015",
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
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "cacheservers"
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
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": "16-19"
    }
  },
  {
    "rule_id": "rule-016",
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
      },
      "host_group": {
        "equals": "cacheservers"
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
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": "16-19"
    }
  },
  {
    "rule_id": "rule-017",
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
      "lines": "N/A"
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
    "action": "filesystem:read",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "mode 0700 non-owner deny",
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
    "action": "filesystem:read",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "mode 0700 non-owner deny",
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
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
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
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "kev": false,
    "epss_score": 0.73544,
    "description": "nginx DNS resolver 1-byte memory overwrite via forged UDP packets, affecting versions 0.6.18 through 1.20.0",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to 1.20.1 or later; disable DNS resolution in nginx config if not needed"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev": false,
    "epss_score": null,
    "description": "nginx use-after-free in HTTP/2 processing, affecting 0.6.18 through 1.8.0 and 1.9.x before 1.9.10",
    "affects_pinned_version": false,
    "recommendation": "Not applicable to nginx 1.20.0; pinned version is past affected range"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev": false,
    "epss_score": null,
    "description": "NGINX njs module out-of-bounds array access in versions through 0.7.0",
    "affects_pinned_version": false,
    "recommendation": "Not applicable unless njs module is explicitly loaded; njs is a separate module"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev": false,
    "epss_score": null,
    "description": "nginx buffer overflow via integer overflow before 1.13.6",
    "affects_pinned_version": false,
    "recommendation": "Not applicable to nginx 1.20.0; pinned version is past affected range"
  },
  {
    "cve_id": "CVE-2013-4547",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "kev": false,
    "epss_score": null,
    "description": "nginx restriction bypass via crafted HTTP request in 0.8.41 through 1.4.3 and 1.5.x before 1.5.7",
    "affects_pinned_version": false,
    "recommendation": "Not applicable to nginx 1.20.0; pinned version is past affected range"
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "kev": true,
    "epss_score": null,
    "description": "Redis Lua sandbox escape in Debian/Ubuntu packages, allowing remote code execution",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version; ensure Lua scripting is disabled if not required; this is a CISA KEV entry requiring immediate patching"
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_remote": true,
    "kev": true,
    "epss_score": null,
    "description": "Redis use-after-free vulnerability in versions <= 8.2.1, allowing manipulation of sorted set elements",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to patched version when available; this is a KEV entry requiring immediate attention"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "kev": true,
    "epss_score": null,
    "description": "pgjdbc SQL injection via line comment generation, allowing attackers to use JDBC connection parameters to execute arbitrary SQL",
    "affects_pinned_version": false,
    "recommendation": "Not directly applicable to postgresql server 16.2; affects pgjdbc (Java JDBC driver). Upgrade pgjdbc to 42.7.2+ if Java clients are used"
  },
  {
    "product": "openssh-server",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "note": "No critical or high-severity remote CVEs found for openssh-server 9.6p1"
  }
]
```

## Report

# ABAC Policy Mining Report - privsep-corp Ansible Configuration

## Executive Summary

This report presents an Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration for the **privsep-corp** production environment. The configuration manages three host groups (webservers, dbservers, cacheservers) with strict privilege separation principles enforced through SSH restrictions, firewall rules, filesystem ACLs, and database access controls.

**Policy Statistics:**
- **17 access rules** extracted (12 permit, 5 deny including default-deny)
- **26 attributes** cataloged across subjects (8), resources (14), and environment (4)
- **9 vulnerability entries** assessed across 4 pinned software packages

---

## Attribute Catalog

### Subject Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| user | string | admin, developer, www-data, postgres, redis | group_vars/all.yml |
| uid | integer | (free-form) | group_vars/all.yml |
| groups | set | sudo, developers, www-data, postgres, redis | group_vars/all.yml |
| clearance | enum | secret, confidential | group_vars/all.yml |
| department | enum | operations, engineering | group_vars/all.yml |
| source_ip | cidr | (free-form) | roles/web/tasks/main.yml |
| source_network | cidr | (free-form) | roles/db/tasks/main.yml |
| source_zone | enum | dmz, internal, internet | inventory.ini |

### Resource Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| hostname | string | web01, db01, cache01 | inventory.ini |
| ip | ip | (free-form) | inventory.ini |
| role | enum | frontend, primary, cache | inventory.ini |
| zone | enum | dmz, internal | inventory.ini |
| host_group | enum | webservers, dbservers, cacheservers, prod | inventory.ini |
| service | enum | nginx, ssh, postgresql, redis, sudo | roles/*/tasks/main.yml |
| port | integer | 443, 22, 5432, 6379 | group_vars/*.yml |
| protocol | enum | tcp | roles/*/tasks/main.yml |
| path | string | (free-form) | roles/*/tasks/main.yml |
| owner | string | www-data, postgres | roles/*/tasks/main.yml |
| group | string | www-data, postgres | roles/*/tasks/main.yml |
| mode | string | 0750, 0700 | roles/*/tasks/main.yml |
| database | string | all | roles/db/tasks/main.yml |
| schema | string | all | roles/db/tasks/main.yml |

### Environment Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| org | enum | privsep-corp | group_vars/all.yml |
| environment | enum | production | inventory.ini |
| compliance_tier | enum | soc2 | group_vars/all.yml |
| default_log_retention_days | integer | (free-form) | group_vars/all.yml |

---

## Access Rules Summary

### SSH Access Control (Rules 001, 002, 011, 014)
- **rule-001**: Only members of the sudo group may SSH into webservers (AllowGroups directive)
- **rule-002**: www-data explicitly denied SSH login (shell=/usr/sbin/nologin)
- **rule-011**: postgres explicitly denied SSH login (shell=/usr/sbin/nologin)
- **rule-014**: redis explicitly denied SSH login (shell=/usr/sbin/nologin)

### Sudo Access Control (Rule 003)
- **rule-003**: www-data explicitly denied sudo access (sudoers.d/www-data absent)

### Network Firewall Rules (Rules 004, 012, 013, 015, 016)
- **rule-004**: HTTPS (port 443/tcp) open to internet (0.0.0.0/0) on webservers
- **rule-012**: PostgreSQL (port 5432) accessible only from webservers subnet (10.0.1.0/24)
- **rule-013**: PostgreSQL denied from all other networks (implicit pg_hba deny)
- **rule-015**: Redis (port 6379/tcp) accessible only from webservers subnet (10.0.1.0/24)
- **rule-016**: Redis denied from all other networks (implicit firewall deny)

### Filesystem ACLs (Rules 005-010)
- **rules 005-007**: www-data group has read/write/execute on /var/www/html (mode 0750) on webservers
- **rules 008-010**: postgres group has read/write/execute on /var/lib/postgresql/data (mode 0700) on dbservers

### Default Deny (Rule 017)
- **rule-017**: Catch-all deny rule - all access not explicitly permitted is denied

---

## Vulnerability Assessment

### Critical Findings

| CVE | Product | Pinned Version | Severity | CVSS | Affects Pinned? | KEV | Recommendation |
|-----|---------|---------------|----------|------|-----------------|-----|----------------|
| CVE-2022-0543 | redis | 7.0.11-1 | CRITICAL | 10.0 | Yes | Yes (CISA) | Immediate patching required - Lua sandbox escape allows RCE |
| CVE-2025-49844 | redis | 7.0.11-1 | CRITICAL | 9.9 | Yes | Yes | Upgrade redis; use-after-free allows code execution |
| CVE-2021-23017 | nginx | 1.20.0-1~focal | HIGH | 7.7 | Yes | No | Upgrade nginx to 1.20.1+; DNS resolver 1-byte overwrite |

### Non-Afflicting CVEs (Pinned Version Outside Range)

| CVE | Product | Affected Range | Pinned Version | Note |
|-----|---------|---------------|----------------|------|
| CVE-2016-0746 | nginx | <=1.8.0, <1.9.10 | 1.20.0 | Past affected range |
| CVE-2021-46461 | nginx njs | <=0.7.0 | N/A (separate module) | Not applicable unless njs loaded |
| CVE-2017-20005 | nginx | <1.13.6 | 1.20.0 | Past affected range |
| CVE-2013-4547 | nginx | <=1.4.3, <1.5.7 | 1.20.0 | Past affected range |
| CVE-2024-1597 | pgjdbc | <42.7.2 | N/A (JDBC driver) | Affects Java clients, not server |

### openssh-server (1:9.6p1-3ubuntu1)
No critical or high-severity remote CVEs found for this version.

---

## Ambiguities and Open Questions

1. **Redis bind address**: Redis is bound to 10.0.2.20 (internal interface only), but no authentication (requirepass) is configured. The firewall rules restrict access, but if the firewall is bypassed, Redis is unauthenticated.

2. **Developer SSH access**: The developer user (groups: [developers]) is NOT in the sudo group and therefore cannot SSH into webservers per the AllowGroups directive. It is unclear whether developers need SSH access to any host group - no AllowGroups configuration exists for dbservers or cacheservers.

3. **PostgreSQL authentication method**: pg_hba uses scram-sha-256 for network connections, but no database users or roles are explicitly created in the Ansible configuration. The actual database-level permissions are undefined.

4. **Credential management**: No vault-encrypted credentials or API keys were found in the configuration. If credentials exist elsewhere, they are outside the scope of this analysis.

5. **SSH access on dbservers/cacheservers**: No AllowGroups directive is configured for dbservers or cacheservers, meaning SSH access policy on those hosts is undefined by this Ansible configuration.

6. **Redis Lua scripting**: CVE-2022-0543 exploits Lua sandbox escape. The configuration does not explicitly disable Lua scripting, leaving the critical vulnerability exploitable.

---

## Network Topology

  Internet (0.0.0.0/0)
       |
       v
  [web01.lab.local] 10.0.1.10  DMZ  role=frontend
  - nginx (443/tcp) open to internet
  - ssh restricted to sudo group
       |
       v (10.0.1.0/24)
  [db01.lab.local] 10.0.2.10  Internal  role=primary
  - postgresql (5432) from webservers only
       |
  [cache01.lab.local] 10.0.2.20  Internal  role=cache
  - redis (6379/tcp) from webservers only
