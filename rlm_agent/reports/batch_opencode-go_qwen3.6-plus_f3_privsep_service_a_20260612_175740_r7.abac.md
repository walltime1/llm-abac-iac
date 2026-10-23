# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:06:49_  
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
      "www-data",
      "postgres"
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
        "name": "redis",
        "port": 6379,
        "protocol": "tcp",
        "host_group": "cacheservers",
        "source": "group_vars/cacheservers.yml"
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
        "host_group": "webservers",
        "source": "group_vars/webservers.yml"
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
        "zone": "internal",
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
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
    "default_log_retention_days": 90
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
      "port": {
        "equals": 22
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
      "lines": [
        43,
        47
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
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
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
    "id": "rule-005",
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
      "lines": [
        8,
        14
      ]
    }
  },
  {
    "id": "rule-006",
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
      "lines": [
        8,
        14
      ]
    }
  },
  {
    "id": "rule-007",
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
      "applies_to": {
        "equals": "all"
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
    "id": "rule-008",
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
      "applies_to": {
        "equals": "all"
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
      "lines": [
        49,
        52
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
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "cvss_score": 9.8,
    "pinned_version": "1.20.0",
    "affects_pinned_version": true,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crash",
    "recommendation": "Upgrade nginx past 1.20.0 to address CVE-2021-46461",
    "kev": false
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "cvss_score": 9.8,
    "pinned_version": "1.20.0",
    "affects_pinned_version": true,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attac",
    "recommendation": "Upgrade nginx past 1.20.0 to address CVE-2016-0746",
    "kev": false
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "cvss_score": 9.8,
    "pinned_version": "1.20.0",
    "affects_pinned_version": true,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the auto",
    "recommendation": "Upgrade nginx past 1.20.0 to address CVE-2017-20005",
    "kev": false
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "cvss_score": 9.8,
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiatio",
    "recommendation": "Upgrade nginx past 1.20.0 to address CVE-2009-3555",
    "kev": false
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "cvss_score": 7.7,
    "pinned_version": "1.20.0",
    "affects_pinned_version": true,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other ",
    "recommendation": "Upgrade nginx past 1.20.0 to address CVE-2021-23017",
    "kev": false
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "cvss_score": 10,
    "pinned_version": "9.6",
    "affects_pinned_version": true,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging ",
    "recommendation": "Upgrade openssh past 9.6 to address CVE-2000-0999",
    "kev": false
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "cvss_score": 10,
    "pinned_version": "9.6",
    "affects_pinned_version": true,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary comma",
    "recommendation": "Upgrade openssh past 9.6 to address CVE-2000-0525",
    "kev": false
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "cvss_score": 10,
    "pinned_version": "9.6",
    "affects_pinned_version": true,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrar",
    "recommendation": "Upgrade openssh past 9.6 to address CVE-2001-0144",
    "kev": false
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "cvss_score": 10,
    "pinned_version": "9.6",
    "affects_pinned_version": true,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbi",
    "recommendation": "Upgrade openssh past 9.6 to address CVE-2003-0693",
    "kev": false
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "cvss_score": 10,
    "pinned_version": "9.6",
    "affects_pinned_version": true,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privileg",
    "recommendation": "Upgrade openssh past 9.6 to address CVE-2003-0786",
    "kev": false
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "cvss_score": 10,
    "pinned_version": "16.2",
    "affects_pinned_version": true,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions,",
    "recommendation": "Upgrade postgresql past 16.2 to address CVE-2007-3279",
    "kev": false
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "cvss_score": 10,
    "pinned_version": "16.2",
    "affects_pinned_version": true,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers po",
    "recommendation": "Upgrade postgresql past 16.2 to address CVE-2013-1902",
    "kev": false
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "cvss_score": 10,
    "pinned_version": "16.2",
    "affects_pinned_version": true,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information d",
    "recommendation": "Upgrade postgresql past 16.2 to address CVE-2013-1903",
    "kev": false
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10,
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling",
    "recommendation": "Upgrade postgresql past 16.2 to address CVE-2024-1597",
    "kev": false
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "cvss_score": 10,
    "pinned_version": "16.2",
    "affects_pinned_version": true,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as",
    "recommendation": "Upgrade postgresql past 16.2 to address CVE-2002-1399",
    "kev": false
  },
  {
    "cve_id": "CVE-2015-4335",
    "product": "redis",
    "cvss_score": 10,
    "pinned_version": "7.0.11",
    "affects_pinned_version": true,
    "description": "Redis < 2.8.21 and 3.x < 3.0.2 contain a remote code execution caused by unsafe eval command processing, letting attackers execute arbitrary Lua bytec",
    "recommendation": "Upgrade redis past 7.0.11 to address CVE-2015-4335",
    "kev": false
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "cvss_score": 10,
    "pinned_version": "7.0.11",
    "affects_pinned_version": true,
    "description": "Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment, letting attackers load arbit",
    "recommendation": "Upgrade redis past 7.0.11 to address CVE-2022-0543",
    "kev": false
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "cvss_score": 9.9,
    "pinned_version": "7.0.11",
    "affects_pinned_version": true,
    "description": "Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts, letting auth",
    "recommendation": "Upgrade redis past 7.0.11 to address CVE-2025-49844",
    "kev": false
  },
  {
    "cve_id": "CVE-2016-8339",
    "product": "redis",
    "cvss_score": 9.8,
    "pinned_version": "7.0.11",
    "affects_pinned_version": true,
    "description": "Redis 3.2.x prior to 3.2.4 contains a buffer overflow caused by out of bounds write in handling of client-output-buffer-limit during CONFIG SET, letti",
    "recommendation": "Upgrade redis past 7.0.11 to address CVE-2016-8339",
    "kev": false
  },
  {
    "cve_id": "CVE-2023-31654",
    "product": "redis",
    "cvss_score": 9.8,
    "pinned_version": "7.0.11",
    "affects_pinned_version": true,
    "description": "Redis raft master-1b8bd86 to master-7b46079 contains an ODR violation caused by hiredisAllocFns in /opt/fs/redisraft/deps/hiredis/alloc.c, letting pot",
    "recommendation": "Upgrade redis past 7.0.11 to address CVE-2023-31654",
    "kev": false
  }
]
```

## Report

# ABAC Policy Report — privsep-corp Ansible Configuration

## Overview
- **Organization:** privsep-corp
- **Environment:** production
- **Compliance Tier:** SOC2
- **Log Retention:** 90 days

## Attribute Catalog Summary
- **Users:** admin (secret, operations), developer (confidential, engineering)
- **Service Accounts:** www-data, postgres, redis (all nologin)
- **Hosts:** web01 (dmz), db01 (internal), cache01 (internal)
- **Services:** nginx (443/tcp), ssh (22/tcp), postgresql (5432/tcp), redis (6379/tcp)

## Rules Extracted (10 total)
1. `rule-001` PERMIT ssh:login — groups in [sudo]
2. `rule-002` PERMIT network:connect — 0.0.0.0/0 → nginx:443
3. `rule-003` PERMIT network:connect — 10.0.1.0/24 → redis:6379
4. `rule-004` PERMIT db:login — 10.0.1.0/24 → postgresql:5432
5. `rule-005` PERMIT filesystem:read — postgres group → /var/lib/postgresql/data (0700)
6. `rule-006` PERMIT filesystem:write — postgres group → /var/lib/postgresql/data (0700)
7. `rule-007` PERMIT filesystem:read — www-data group → /var/www/html (0750)
8. `rule-008` PERMIT filesystem:write — www-data group → /var/www/html (0750)
9. `rule-009` DENY sudo:execute — www-data group
10. `rule-010` DENY * — default-deny (catch-all)

## Vulnerabilities
- Pinned versions analyzed: nginx 1.20.0, openssh 9.6, postgresql 16.2, redis 7.0.11
- Total CVEs found: 20
- Critical/Remote and KEV entries processed. See `vulnerabilities` output for details.

## Ambiguities & Notes
- **Credentials:** No plaintext credentials observed in the configuration.
- **pg_hba:** Uses `host all all` — permits all databases/schemas from the allowed subnet. Consider scoping to specific DBs.
- **Redis bind:** Bound to `10.0.2.20` (cache01 IP) rather than a loopback or group-scoped interface.
- **SSH:** `openssh-server` version pinned, but no explicit `PermitRootLogin` or `PasswordAuthentication` settings observed.
- **Session Logging:** No explicit audit/obligation tasks found (e.g., profile.d scripts, bash history logging).
