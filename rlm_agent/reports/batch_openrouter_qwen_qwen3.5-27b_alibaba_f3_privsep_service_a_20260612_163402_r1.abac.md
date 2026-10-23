# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:37:27_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 15_  
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
        "name": "postgres",
        "shell": "/usr/sbin/nologin",
        "system": true,
        "source": "roles/db/tasks/main.yml"
      },
      {
        "name": "redis",
        "shell": "/usr/sbin/nologin",
        "system": true,
        "source": "roles/cache/tasks/main.yml"
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
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
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
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers",
        "source": "inventory.ini"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "internal",
        "label": "internal_servers",
        "source": "inventory.ini"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
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
        "equals": "ssh"
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "36-40"
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "20-24"
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
      "zone": {
        "equals": "internal"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": "16-22"
    }
  },
  {
    "id": "rule-004",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "28-34"
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "22-27"
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "22-27"
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "9-14"
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "9-14"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "deny",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure www-data has NO sudo access",
      "lines": "41-44"
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
      "file": "implicit",
      "task": "default-deny",
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
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
    "version": "1.20.0-1~focal",
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "version": "1.20.0-1~focal",
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "version": "1.20.0-1~focal",
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "version": "1.20.0-1~focal",
    "cve_id": "CVE-2009-3555",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "version": "1.20.0-1~focal",
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "postgresql",
    "version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "redis",
    "version": "7.0.11-1",
    "cve_id": "CVE-2015-4335",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Redis < 2.8.21 and 3.x < 3.0.2 contain a remote code execution caused by unsafe eval command processing, letting attackers execute arbitrary Lua bytecode remotely, exploit requires network access to R",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  },
  {
    "product": "redis",
    "version": "7.0.11-1",
    "cve_id": "CVE-2022-0543",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment, letting attackers load arbitrary libraries, exploit requires attacker to execu",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  },
  {
    "product": "redis",
    "version": "7.0.11-1",
    "cve_id": "CVE-2025-49844",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_remote": true,
    "description": "Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts, letting authenticated users potentially achieve remote code ex",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  },
  {
    "product": "redis",
    "version": "7.0.11-1",
    "cve_id": "CVE-2016-8339",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Redis 3.2.x prior to 3.2.4 contains a buffer overflow caused by out of bounds write in handling of client-output-buffer-limit during CONFIG SET, letting attackers execute arbitrary code, exploit requi",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  },
  {
    "product": "redis",
    "version": "7.0.11-1",
    "cve_id": "CVE-2018-11219",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Redis versions before 3.2.12, 4.0.10, and 5.0 RC2 contain an integer overflow caused by a failure of bounds checking in the Lua subsystem, letting attackers potentially cause unexpected behavior or cr",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
Mined ABAC policy from Ansible configuration at RLM_ANSIBLE_DIR. Found **10 access control rules** and **15 vulnerabilities** across 4 software packages.

## Environment
- **Organization**: privsep-corp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Inventory Summary
- **Hosts**: 3 (web01 in DMZ, db01/cache01 in internal zone)
- **Users**: 2 human (admin, developer) + 3 system (www-data, postgres, redis)
- **Groups**: sudo, developers, www-data
- **Services**: nginx (443), PostgreSQL (5432), Redis (6379), SSH (22)

## Access Control Rules (10 total)

### Network Access Rules
| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-001 | groups: sudo | ssh service (dmz) | ssh:login | permit |
| rule-002 | source: 10.0.1.0/24 | PostgreSQL (internal) | network:connect | permit |
| rule-003 | source: 10.0.1.0/24 | Redis (internal) | network:connect | permit |
| rule-004 | source: 0.0.0.0/0 | nginx HTTPS (dmz) | network:connect | permit |

### Filesystem Rules
| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-005 | groups: www-data | /var/www/html (0750) | filesystem:read | permit |
| rule-006 | groups: www-data | /var/www/html (0750) | filesystem:write | permit |
| rule-007 | groups: postgres | /var/lib/postgresql/data (0700) | filesystem:read | permit |
| rule-008 | groups: postgres | /var/lib/postgresql/data (0700) | filesystem:write | permit |

### Deny Rules
| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-009 | groups: www-data | all | sudo:execute | deny |
| rule-010 | all | all | * | deny (default) |

## Vulnerability Assessment (15 total)

### Critical/Remote Vulnerabilities
| Product | CVE | CVSS | Severity |
|---------|-----|------|----------|
| nginx | CVE-2016-0746 | 9.8 | critical |
| nginx | CVE-2021-46461 | 9.8 | critical |
| postgresql | Multiple | 9.0+ | critical/high |
| redis | Multiple | 9.0+ | critical/high |

### Known Exploited Vulnerabilities (KEV)
| Product | CVE Count | Status |
|---------|-----------|--------|
| nginx | 4 | Actively exploited |
| openssh-server | 1 | Actively exploited |
| postgresql | 4 | Actively exploited |
| redis | 4 | Actively exploited |

## Security Observations

### Strengths
1. SSH access restricted to sudo group only
2. Database access limited to webservers subnet (10.0.1.0/24)
3. Redis bound to internal interface only
4. System users have no shell access (/usr/sbin/nologin)
5. www-data explicitly denied sudo access

### Concerns
1. **HTTPS open to internet (0.0.0.0/0)** - Consider rate limiting or WAF
2. **Multiple critical vulnerabilities** in pinned package versions
3. **No explicit deny rules** for database connections from other zones

## Recommendations
1. **URGENT**: Patch all KEV vulnerabilities immediately
2. Review firewall rule allowing 0.0.0.0/0 to HTTPS
3. Consider adding explicit deny rules for database access
4. Implement network segmentation between DMZ and internal zones

## Ambiguities
- No explicit sudo rules found for admin user (assumed via sudo group membership)
- No database user credentials found in configuration (likely managed externally)
- No session logging/audit obligations explicitly defined
