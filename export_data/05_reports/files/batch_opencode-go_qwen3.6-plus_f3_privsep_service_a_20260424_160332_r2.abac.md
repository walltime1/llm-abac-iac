# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:16:37_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 12 | Rules: 16_  
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
      }
    ],
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance_levels": [
      "secret",
      "confidential"
    ],
    "departments": [
      "operations",
      "engineering"
    ],
    "system_users": [
      "www-data",
      "redis",
      "postgres"
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
        "path": "/var/www/html",
        "owner": "www-data",
        "group": "www-data",
        "mode": "0750",
        "service": "nginx",
        "source": "roles/web/tasks/main.yml"
      },
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
        "cidr": "0.0.0.0/0",
        "zone": "any",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers-subnet",
        "source": "group_vars/dbservers.yml"
      }
    ]
  },
  "environment": {
    "org": "privsep-corp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "group_vars/all.yml"
  },
  "attribute_definitions": {
    "user": {
      "type": "string",
      "domain": [
        "admin",
        "developer",
        "www-data",
        "redis",
        "postgres"
      ],
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
    "hostname": {
      "type": "string",
      "domain": [
        "web01.lab.local",
        "db01.lab.local",
        "cache01.lab.local"
      ],
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
    "port": {
      "type": "integer",
      "domain": [
        443,
        5432,
        6379
      ],
      "source": "group_vars"
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "postgresql",
        "redis",
        "sshd"
      ],
      "source": "group_vars"
    },
    "path": {
      "type": "string",
      "domain": [
        "/var/www/html",
        "/var/lib/postgresql/data"
      ],
      "source": "roles"
    },
    "owner": {
      "type": "string",
      "domain": [
        "www-data",
        "postgres"
      ],
      "source": "roles"
    },
    "mode": {
      "type": "string",
      "domain": [
        "0750",
        "0700"
      ],
      "source": "roles"
    },
    "source_network": {
      "type": "cidr",
      "source": "group_vars"
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal",
        "any"
      ],
      "source": "inventory.ini"
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
      "source": "inventory.ini"
    },
    "org": {
      "type": "string",
      "domain": [
        "privsep-corp"
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
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sshd"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        43,
        47
      ]
    },
    "obligations": [
      {
        "type": "deny_sudo",
        "description": "www-data has NO sudo access (sudoers.d/www-data absent)"
      }
    ]
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "service": {
        "equals": "nginx"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        35,
        41
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
      "port": {
        "equals": 5432
      },
      "service": {
        "equals": "postgresql"
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
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        21,
        25
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
      "port": {
        "equals": 6379
      },
      "service": {
        "equals": "redis"
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
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": [
        20,
        26
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "user": {
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": [
        27,
        33
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "user": {
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": [
        27,
        33
      ]
    }
  },
  {
    "id": "rule-007",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": [
        8,
        14
      ]
    }
  },
  {
    "id": "rule-008",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": [
        8,
        14
      ]
    }
  },
  {
    "id": "rule-009",
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
      "lines": [
        0,
        0
      ]
    }
  },
  {
    "id": "rule-010",
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "postprocessor",
      "task": "mode 0750 group read",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-011",
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "postprocessor",
      "task": "mode 0750 group read",
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
    "id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "service": {
        "equals": "nginx"
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
    "id": "rule-015",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "service": {
        "equals": "postgresql"
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
    "id": "rule-016",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 6379
      },
      "service": {
        "equals": "redis"
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": true,
    "cvss_score": 9.8,
    "is_kev": false,
    "title": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "recommendation": "CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": true,
    "cvss_score": 9.8,
    "is_kev": false,
    "title": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ",
    "recommendation": "CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": true,
    "cvss_score": 9.8,
    "is_kev": false,
    "title": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "recommendation": "CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": true,
    "cvss_score": 7.7,
    "is_kev": false,
    "title": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "recommendation": "Schedule patch within next maintenance window; restrict network access in meantime"
  },
  {
    "cve_id": "CVE-2013-4547",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": true,
    "cvss_score": 7.5,
    "is_kev": false,
    "title": "nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 contain a restriction bypass caused by unescaped space character in URI, letting remote attackers bypass intended restrictions, exploit requires sendi",
    "recommendation": "Schedule patch within next maintenance window; restrict network access in meantime"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": true,
    "cvss_score": 10,
    "is_kev": false,
    "title": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "recommendation": "CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": true,
    "cvss_score": 10,
    "is_kev": false,
    "title": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "recommendation": "CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable"
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "pinned_version": "7.0.11",
    "affects_pinned_version": true,
    "cvss_score": 10,
    "is_kev": true,
    "title": "Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment, letting attackers load arbitrary libraries, exploit requires attacker to execu",
    "recommendation": "URGENT: This CVE is in CISA KEV — patch immediately or apply compensating controls"
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "pinned_version": "7.0.11",
    "affects_pinned_version": true,
    "cvss_score": 9.9,
    "is_kev": true,
    "title": "Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts, letting authenticated users potentially achieve remote code ex",
    "recommendation": "URGENT: This CVE is in CISA KEV — patch immediately or apply compensating controls"
  },
  {
    "cve_id": "CVE-2017-15047",
    "product": "redis",
    "pinned_version": "7.0.11",
    "affects_pinned_version": true,
    "cvss_score": 9.8,
    "is_kev": false,
    "title": "Redis 4.0.2 contains a denial of service caused by out-of-bounds array index in clusterLoadConfig function in cluster.c, letting attackers cause application crash, exploit requires limited access to t",
    "recommendation": "CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable"
  },
  {
    "cve_id": "CVE-2023-31654",
    "product": "redis",
    "pinned_version": "7.0.11",
    "affects_pinned_version": true,
    "cvss_score": 9.8,
    "is_kev": false,
    "title": "Redis raft master-1b8bd86 to master-7b46079 contains an ODR violation caused by hiredisAllocFns in /opt/fs/redisraft/deps/hiredis/alloc.c, letting potential undefined behavior impact, exploit requires",
    "recommendation": "CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable"
  }
]
```

## Report

# ABAC Policy Mining Report

## Overview
This report documents the ABAC policy mined from the Ansible configuration rooted at `RLM_ANSIBLE_DIR` for the `privsep-corp` organization. The configuration targets a **production** environment with **SOC2** compliance requirements.

## Phase 1 — Attribute Catalog

### Subjects
- **Users**: `admin` (uid=1001, clearance=secret, dept=operations, groups=[sudo]), `developer` (uid=1002, clearance=confidential, dept=engineering, groups=[developers])
- **System Users**: `www-data` (uid=33, no shell), `redis` (no shell), `postgres` (no shell)
- **Groups**: `sudo`, `developers`
- **Clearance Levels**: `secret`, `confidential`
- **Departments**: `operations`, `engineering`

### Resources
- **Hosts**: `web01.lab.local` (10.0.1.10, frontend, dmz), `db01.lab.local` (10.0.2.10, primary, internal), `cache01.lab.local` (10.0.2.20, cache, internal)
- **Services**: nginx (443/tcp, webservers), postgresql (5432/tcp, dbservers), redis (6379/tcp, cacheservers)
- **Filesystem Paths**: `/var/www/html` (www-data:www-data, 0750), `/var/lib/postgresql/data` (postgres:postgres, 0700)
- **Networks**: `0.0.0.0/0` (internet), `10.0.1.0/24` (webservers subnet)

### Environment
- **Organization**: privsep-corp
- **Environment**: production
- **Compliance Tier**: soc2
- **Log Retention**: 90 days

## Phase 2 — Extracted Rules (9 total)

| ID | Action | Effect | Condition | Source |
|----|--------|--------|-----------|--------|
| rule-001 | ssh:login | permit | groups ∈ {sudo} | roles/web/tasks/main.yml:43-47 |
| rule-002 | network:connect | permit | source=0.0.0.0/0, port=443, service=nginx | roles/web/tasks/main.yml:35-41 |
| rule-003 | network:connect | permit | source=10.0.1.0/24, port=5432, service=postgresql | roles/db/tasks/main.yml:21-25 |
| rule-004 | network:connect | permit | source=10.0.1.0/24, port=6379, service=redis | roles/cache/tasks/main.yml:20-26 |
| rule-005 | filesystem:read | permit | user=www-data, path=/var/www/html, mode=0750 | roles/web/tasks/main.yml:27-33 |
| rule-006 | filesystem:write | permit | user=www-data, path=/var/www/html, mode=0750 | roles/web/tasks/main.yml:27-33 |
| rule-007 | filesystem:read | permit | user=postgres, path=/var/lib/postgresql/data, mode=0700 | roles/db/tasks/main.yml:8-14 |
| rule-008 | filesystem:write | permit | user=postgres, path=/var/lib/postgresql/data, mode=0700 | roles/db/tasks/main.yml:8-14 |
| rule-009 | * | deny | applies_to=all | default-deny |

## Phase 1.5 — Vulnerability Assessment

Pinned software versions: nginx 1.20.0, openssh-server 9.6p1, postgresql 16.2, redis 7.0.11

- **CVE-2016-0746** (CVSS 9.8): nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attac...
  - Affects pinned nginx 1.20.0: True
  - Recommendation: CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable

- **CVE-2021-46461** (CVSS 9.8): NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crash...
  - Affects pinned nginx 1.20.0: True
  - Recommendation: CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable

- **CVE-2017-20005** (CVSS 9.8): NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the auto...
  - Affects pinned nginx 1.20.0: True
  - Recommendation: CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable

- **CVE-2021-23017** (CVSS 7.7): nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other ...
  - Affects pinned nginx 1.20.0: True
  - Recommendation: Schedule patch within next maintenance window; restrict network access in meantime

- **CVE-2013-4547** (CVSS 7.5): nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 contain a restriction bypass caused by unescaped space character in URI, letting remote attackers by...
  - Affects pinned nginx 1.20.0: True
  - Recommendation: Schedule patch within next maintenance window; restrict network access in meantime

- **CVE-2013-1903** (CVSS 10): PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information d...
  - Affects pinned postgresql 16.2: True
  - Recommendation: CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable

- **CVE-2013-1902** (CVSS 10): PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers po...
  - Affects pinned postgresql 16.2: True
  - Recommendation: CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable

- **CVE-2022-0543** (CVSS 10 🔴 KEV): Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment, letting attackers load arbit...
  - Affects pinned redis 7.0.11: True
  - Recommendation: URGENT: This CVE is in CISA KEV — patch immediately or apply compensating controls

- **CVE-2025-49844** (CVSS 9.9 🔴 KEV): Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts, letting auth...
  - Affects pinned redis 7.0.11: True
  - Recommendation: URGENT: This CVE is in CISA KEV — patch immediately or apply compensating controls

- **CVE-2017-15047** (CVSS 9.8): Redis 4.0.2 contains a denial of service caused by out-of-bounds array index in clusterLoadConfig function in cluster.c, letting attackers cause appli...
  - Affects pinned redis 7.0.11: True
  - Recommendation: CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable

- **CVE-2023-31654** (CVSS 9.8): Redis raft master-1b8bd86 to master-7b46079 contains an ODR violation caused by hiredisAllocFns in /opt/fs/redisraft/deps/hiredis/alloc.c, letting pot...
  - Affects pinned redis 7.0.11: True
  - Recommendation: CRITICAL: Apply vendor patch ASAP; isolate service if patch unavailable

## Ambiguities & Notes

1. **No explicit database user creation tasks**: The configuration does not define PostgreSQL database users with explicit privilege levels (SUPERUSER, NOSUPERUSER, ALL, SELECT). Only network-level pg_hba access is defined.
2. **No sudoers file with explicit rules**: The `developer` user is not in the `sudo` group, so SSH login is implicitly denied by `AllowGroups sudo`. No explicit `nopassword` directives found.
3. **Redis bind address hardcoded**: Redis is bound to `10.0.2.20` (single IP) rather than using an interface or variable. This may be intentional for the cache role.
4. **No SELinux or AppArmor policies** were found in the configuration.
5. **Credential handling**: No credentials, secrets, or vault references were observed in the scanned files. The `postgres` user uses `scram-sha-256` authentication.
6. **Session logging**: No explicit session logging or audit rules were found in the configuration.
