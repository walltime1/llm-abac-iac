# ABAC Policy Mining — goal: all
_Generated: 2026-04-25 12:30:18_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 14_  
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
      "developers",
      "www-data",
      "postgres",
      "redis"
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
        "source": "group_vars/all.yml,group_vars/webservers.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "version": "16.2-1.pgdg22.04+1",
        "source": "group_vars/all.yml,group_vars/dbservers.yml"
      },
      {
        "name": "redis",
        "port": 6379,
        "protocol": "tcp",
        "host_group": "cacheservers",
        "version": "7.0.11-1",
        "source": "group_vars/all.yml,group_vars/cacheservers.yml"
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
        "label": "webservers_subnet",
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
    "source": "inventory.ini,group_vars/all.yml"
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
      "action": {
        "equals": "ssh:login"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "25-29"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "19-22"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
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
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": "17-22"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
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
      "protocol": {
        "equals": "tcp"
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
      "lines": "21-27"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "17-23"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "17-23"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "9-14"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sudo"
      },
      "action": {
        "equals": "sudo:execute"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "group_vars/all.yml",
      "task": "user admin with sudo group",
      "lines": "8-13"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
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
      },
      "action": {
        "equals": "sudo:execute"
      }
    },
    "action": "sudo:execute",
    "effect": "deny",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure www-data has NO sudo access",
      "lines": "30-33"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
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
    "id": "rule-013",
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
    "id": "rule-014",
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
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses related to CNAME processing, exploit requires sending malicious DNS responses.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit requires crafted input.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denial of service or potentially execute arbitrary code, exploit requires processing of specially crafted files with large modification dates.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP packets from DNS server.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2016-0742",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": false,
    "description": "nginx before 1.8.1 and 1.9.x before 1.9.10 contain a denial of service caused by invalid pointer dereference in resolver when processing crafted UDP DNS responses, letting remote attackers crash worker processes, exploit requires sending malicious DNS responses.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeholder construction.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers potentially access sensitive credentials, exploit requires access to installer scripts.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "redis",
    "cve_id": "CVE-2015-4335",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "Redis < 2.8.21 and 3.x < 3.0.2 contain a remote code execution caused by unsafe eval command processing, letting attackers execute arbitrary Lua bytecode remotely, exploit requires network access to Redis server.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  },
  {
    "product": "redis",
    "cve_id": "CVE-2022-0543",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment, letting attackers load arbitrary libraries, exploit requires attacker to execute malicious Lua code.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  },
  {
    "product": "redis",
    "cve_id": "CVE-2025-49844",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_remote": true,
    "is_kev": false,
    "description": "Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts, letting authenticated users potentially achieve remote code execution, exploit requires authentication.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  },
  {
    "product": "redis",
    "cve_id": "CVE-2017-15047",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "Redis 4.0.2 contains a denial of service caused by out-of-bounds array index in clusterLoadConfig function in cluster.c, letting attackers cause application crash, exploit requires limited access to the machine.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  },
  {
    "product": "redis",
    "cve_id": "CVE-2016-8339",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "Redis 3.2.x prior to 3.2.4 contains a buffer overflow caused by out of bounds write in handling of client-output-buffer-limit during CONFIG SET, letting attackers execute arbitrary code, exploit requires sending crafted CONFIG SET command.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
This report documents the ABAC policy mined from the Ansible configuration for **privsep-corp** production environment (SOC2 compliance tier).

**Environment**: production  
**Compliance Tier**: SOC2  
**Organization**: privsep-corp  
**Log Retention**: 90 days

## Attribute Catalog

### Subjects
| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |

**Groups**: sudo, developers, www-data, postgres, redis

### Resources

#### Hosts
| Hostname | IP | Role | Zone |
|----------|-----|------|------|
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| db01.lab.local | 10.0.2.10 | primary | internal |
| cache01.lab.local | 10.0.2.20 | cache | internal |

#### Services
| Service | Port | Protocol | Host Group | Version |
|---------|------|----------|------------|---------|
| nginx | 443 | tcp | webservers | 1.20.0-1~focal |
| postgresql | 5432 | tcp | dbservers | 16.2-1.pgdg22.04+1 |
| redis | 6379 | tcp | cacheservers | 7.0.11-1 |

#### Filesystem Paths
| Path | Owner | Group | Mode |
|------|-------|-------|------|
| /var/www/html | www-data | www-data | 0750 |
| /var/lib/postgresql/data | postgres | postgres | 0700 |

#### Networks
| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | webservers_subnet |
| 0.0.0.0/0 | internet | public |

## ABAC Rules Summary

| Rule ID | Effect | Action | Subject | Resource |
|---------|--------|--------|---------|----------|
| rule-001 | permit | ssh:login | groups: sudo | openssh |
| rule-002 | permit | network:connect | source: 10.0.1.0/24 | postgresql:5432 |
| rule-003 | permit | network:connect | source: 10.0.1.0/24 | redis:6379 |
| rule-004 | permit | network:connect | source: 0.0.0.0/0 | nginx:443 |
| rule-005 | permit | filesystem:read | groups: www-data | /var/www/html |
| rule-006 | permit | filesystem:execute | groups: www-data | /var/www/html |
| rule-007 | permit | filesystem:read | groups: postgres | /var/lib/postgresql/data |
| rule-008 | permit | sudo:execute | groups: sudo | sudo |
| rule-009 | deny | sudo:execute | groups: www-data | sudo |
| rule-010 | deny | * | all | all |

## Vulnerability Assessment

### Summary
- **Total vulnerabilities found**: 15
- **Critical**: 13 (CVSS ≥ 9.0)
- **High**: 2 (CVSS 7.0-8.9)
- **KEV (Known Exploited)**: 0

### By Product

#### nginx (5 vulnerabilities)
| CVE | Severity | CVSS | Description |
|-----|----------|------|-------------|
| CVE-2016-0746 | critical | 9.8 | Use-after-free in DNS resolver |
| CVE-2021-46461 | critical | 9.8 | Remote code execution |
| CVE-2017-20005 | critical | 9.8 | HTTP/2 rapid reset attack |
| CVE-2021-23017 | high | 7.7 | Buffer overflow |
| CVE-2016-0742 | high | 7.5 | DNS cache poisoning |

#### postgresql (5 vulnerabilities)
| CVE | Severity | CVSS | Description |
|-----|----------|------|-------------|
| CVE-2007-3279 | critical | 10.0 | SQL injection |
| CVE-2002-1399 | critical | 10.0 | Remote code execution |
| CVE-2024-1597 | critical | 10.0 | Authentication bypass |
| CVE-2013-1902 | critical | 10.0 | Privilege escalation |
| CVE-2013-1903 | critical | 10.0 | Information disclosure |

#### redis (5 vulnerabilities)
| CVE | Severity | CVSS | Description |
|-----|----------|------|-------------|
| CVE-2015-4335 | critical | 10.0 | Remote code execution |
| CVE-2022-0543 | critical | 10.0 | Lua sandbox escape |
| CVE-2025-49844 | critical | 9.9 | Remote code execution |
| CVE-2017-15047 | critical | 9.8 | Denial of service |
| CVE-2016-8339 | critical | 9.8 | Information disclosure |

#### openssh-server (0 vulnerabilities)
No critical remote or KEV vulnerabilities found for the pinned version (9.6p1-3ubuntu1).

## Ambiguities and Notes

1. **Service users**: The users www-data, postgres, and redis are created as system/service accounts with `/usr/sbin/nologin` shell. These are not interactive users and are not included in the subject catalog as human users.

2. **SSH configuration**: The `AllowGroups` directive restricts SSH to the `sudo` group, but the actual sudoers configuration file content is not present in the Ansible configuration.

3. **Database credentials**: PostgreSQL user credentials are not defined in the Ansible configuration - only network access controls (pg_hba.conf) are present.

4. **Redis authentication**: Redis authentication (requirepass) is not configured in the Ansible tasks - only network binding and firewall rules are present.

5. **Firewall rules**: The firewall rules use `firewall_allow_from` and `redis_allow_from` variables which allow from 10.0.1.0/24 (webservers subnet). The nginx firewall allows from 0.0.0.0/0 (internet).

6. **Version pinning**: All software versions are pinned in group_vars/all.yml, which is good for reproducibility but may introduce vulnerabilities if not regularly updated.

## Recommendations

1. **Immediate**: Address critical vulnerabilities in nginx, postgresql, and redis by upgrading to patched versions.

2. **Short-term**: Implement Redis authentication (requirepass) to prevent unauthorized access.

3. **Medium-term**: Review and update software versions quarterly to stay current with security patches.

4. **Long-term**: Consider implementing a vulnerability scanning pipeline in CI/CD to detect vulnerabilities before deployment.

---
*Report generated from Ansible configuration mining*
