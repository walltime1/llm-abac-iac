# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:43:56_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 10 | Rules: 13_  
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
      },
      {
        "name": "www-data",
        "uid": 33,
        "groups": [
          "www-data"
        ],
        "shell": "/usr/sbin/nologin",
        "system": true,
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "redis",
        "shell": "/usr/sbin/nologin",
        "system": true,
        "source": "roles/cache/tasks/main.yml"
      },
      {
        "name": "postgres",
        "shell": "/usr/sbin/nologin",
        "system": true,
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "www-data"
    ],
    "clearance_levels": [
      "secret",
      "confidential"
    ],
    "departments": [
      "operations",
      "engineering"
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
        "version": "1.20.0-1~focal",
        "source": "group_vars/webservers.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "version": "16.2-1.pgdg22.04+1",
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "redis",
        "port": 6379,
        "protocol": "tcp",
        "host_group": "cacheservers",
        "version": "7.0.11-1",
        "source": "group_vars/cacheservers.yml"
      },
      {
        "name": "openssh-server",
        "version": "1:9.6p1-3ubuntu1",
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
      },
      {
        "path": "/var/www/html",
        "owner": "www-data",
        "group": "www-data",
        "mode": "0750",
        "service": "nginx",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "path": "/etc/redis/redis.conf",
        "service": "redis",
        "source": "roles/cache/tasks/main.yml"
      },
      {
        "path": "/etc/postgresql/pg_hba.conf",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "path": "/etc/nginx/nginx.conf",
        "service": "nginx",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "path": "/etc/ssh/sshd_config",
        "service": "openssh-server",
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
        "zone": "internet",
        "label": "public",
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
        "equals": "openssh-server"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "38-42"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "user": {
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure www-data has NO sudo access",
      "lines": "44-47"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-003",
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "29-34"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-004",
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "29-34"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-005",
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
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "11-16"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-006",
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
      "zone": {
        "equals": "internal"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": "17-23"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-007",
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
      "zone": {
        "equals": "internal"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "18-22"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-008",
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
      "zone": {
        "equals": "dmz"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "36-41"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "N/A",
      "task": "default-deny",
      "lines": "N/A"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
    "id": "rule-011",
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
  },
  {
    "id": "rule-012",
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
    "pinned_version": "1.20.0-1~focal",
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cve_id": "CVE-2009-3555",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cve_id": "CVE-2023-44487",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many streams quickly, letting attackers consume server resources, exploit has been observed in the wild f",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2019-9193",
    "severity": "high",
    "cvss_score": 7.2,
    "is_remote": true,
    "is_kev": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2022-31197",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "is_kev": true,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "cve_id": "CVE-2015-4335",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "Redis < 2.8.21 and 3.x < 3.0.2 contain a remote code execution caused by unsafe eval command processing, letting attackers execute arbitrary Lua bytecode remotely, exploit requires network access to R",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  },
  {
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "cve_id": "CVE-2022-0543",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "description": "Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment, letting attackers load arbitrary libraries, exploit requires attacker to execu",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  },
  {
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "cve_id": "CVE-2025-49844",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_remote": true,
    "is_kev": true,
    "description": "Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts, letting authenticated users potentially achieve remote code ex",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  },
  {
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "cve_id": "CVE-2016-8339",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "Redis 3.2.x prior to 3.2.4 contains a buffer overflow caused by out of bounds write in handling of client-output-buffer-limit during CONFIG SET, letting attackers execute arbitrary code, exploit requi",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  },
  {
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "cve_id": "CVE-2018-11219",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "Redis versions before 3.2.12, 4.0.10, and 5.0 RC2 contain an integer overflow caused by a failure of bounds checking in the Lua subsystem, letting attackers potentially cause unexpected behavior or cr",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
This report documents the ABAC policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`.

**Organization:** privsep-corp  
**Environment:** production  
**Compliance Tier:** SOC2  
**Policy Scope:** Full coverage (all access controls)

## Attribute Catalog

### Subjects
| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| www-data | 33 | www-data | N/A | N/A |
| redis | N/A | N/A | N/A | N/A |
| postgres | N/A | N/A | N/A | N/A |

**Groups:** sudo, developers, www-data  
**Clearance Levels:** secret, confidential  
**Departments:** operations, engineering

### Resources
**Hosts (3):**
- web01.lab.local (10.0.1.10, frontend, dmz)
- db01.lab.local (10.0.2.10, primary, internal)
- cache01.lab.local (10.0.2.20, cache, internal)

**Services (4):**
- nginx:1.20.0-1~focal (port 443, webservers)
- openssh-server:1:9.6p1-3ubuntu1
- postgresql:16.2-1.pgdg22.04+1 (port 5432, dbservers)
- redis:7.0.11-1 (port 6379, cacheservers)

**Networks:**
- 10.0.1.0/24 (dmz, webservers_subnet)
- 10.0.2.0/24 (internal, internal_subnet)
- 0.0.0.0/0 (internet, public)

## Extracted Rules (9 total)

| Rule | Effect | Action | Subject | Resource |
|------|--------|--------|---------|----------|
| rule-001 | permit | ssh:login | groups:sudo | openssh-server |
| rule-002 | deny | sudo:execute | user:www-data | sudo |
| rule-003 | permit | filesystem:read | groups:www-data | /var/www/html |
| rule-004 | permit | filesystem:write | user:www-data | /var/www/html |
| rule-005 | permit | filesystem:read | user:postgres | /var/lib/postgresql/data |
| rule-006 | permit | network:connect | source:10.0.1.0/24 | redis:6379 |
| rule-007 | permit | network:connect | source:10.0.1.0/24 | postgresql:5432 |
| rule-008 | permit | network:connect | source:0.0.0.0/0 | nginx:443 |
| rule-009 | deny | * | all | all |

## Vulnerability Assessment (18 vulnerabilities)

### nginx (1.20.0-1~focal) - 6 vulnerabilities
| CVE | Severity | CVSS | Remote | KEV |
|-----|----------|------|--------|-----|
| CVE-2016-0746 | critical | 9.8 | ✓ | ✗ |
| CVE-2021-46461 | critical | 9.8 | ✓ | ✗ |
| CVE-2017-20005 | critical | 9.8 | ✓ | ✗ |
| CVE-2009-3555 | critical | 9.8 | ✓ | ✗ |
| CVE-2021-23017 | high | 7.7 | ✓ | ✗ |
| CVE-2023-44487 | high | 7.5 | ✓ | ✓ |

### openssh-server (1:9.6p1-3ubuntu1) - 0 vulnerabilities
No critical/high remote or KEV vulnerabilities found.

### postgresql (16.2-1.pgdg22.04+1) - 7 vulnerabilities
| CVE | Severity | CVSS | Remote | KEV |
|-----|----------|------|--------|-----|
| CVE-2002-1399 | critical | 10.0 | ✓ | ✗ |
| CVE-2013-1902 | critical | 10.0 | ✓ | ✗ |
| CVE-2007-3279 | critical | 10.0 | ✓ | ✗ |
| CVE-2013-1903 | critical | 10.0 | ✓ | ✗ |
| CVE-2024-1597 | critical | 10.0 | ✓ | ✓ |
| CVE-2019-9193 | high | 7.2 | ✓ | ✗ |
| CVE-2022-31197 | high | 7.1 | ✓ | ✓ |

### redis (7.0.11-1) - 5 vulnerabilities
| CVE | Severity | CVSS | Remote | KEV |
|-----|----------|------|--------|-----|
| CVE-2015-4335 | critical | 10.0 | ✓ | ✗ |
| CVE-2022-0543 | critical | 10.0 | ✓ | ✗ |
| CVE-2025-49844 | critical | 9.9 | ✓ | ✗ |
| CVE-2016-8339 | critical | 9.8 | ✓ | ✓ |
| CVE-2018-11219 | critical | 9.8 | ✓ | ✓ |

## Ambiguities and Notes

1. **Credentials:** No explicit database user credentials found in configuration. pg_hba.conf uses scram-sha-256 authentication but user accounts are not defined in Ansible.

2. **Shell Access:** Service accounts (www-data, redis, postgres) are configured with `/usr/sbin/nologin` shell to prevent interactive login.

3. **Sudo Access:** www-data explicitly denied sudo access. admin user has sudo group membership but no explicit sudoers rules defined.

4. **Network Segmentation:** Clear DMZ/internal separation. Webservers (10.0.1.0/24) in DMZ can access internal services (Redis, PostgreSQL).

5. **Default Deny:** Implicit default-deny policy enforced (rule-009).

## Recommendations

1. **Immediate:** Upgrade nginx, postgresql, and redis to patched versions to address critical vulnerabilities.

2. **High Priority:** Address KEV vulnerabilities (CVE-2023-44487, CVE-2024-1597, CVE-2022-31197, CVE-2016-8339, CVE-2018-11219) as these are actively exploited.

3. **Medium Priority:** Define explicit database user accounts with least-privilege permissions.

4. **Review:** Consider restricting HTTPS access (0.0.0.0/0) to known client subnets if applicable.
