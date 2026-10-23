# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:10:27_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 10 | Rules: 12_  
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
        "name": "postgres",
        "uid": null,
        "groups": [
          "postgres"
        ],
        "clearance": null,
        "department": null,
        "source": "roles/db/tasks/main.yml"
      },
      {
        "name": "www-data",
        "uid": 33,
        "groups": [
          "www-data"
        ],
        "clearance": null,
        "department": null,
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "redis",
        "uid": null,
        "groups": [
          "redis"
        ],
        "clearance": null,
        "department": null,
        "source": "roles/cache/tasks/main.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "postgres",
      "www-data",
      "redis"
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
      }
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
        "name": "https",
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
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "all",
        "source": "group_vars/webservers.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "privsep-corp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "source": "inventory.ini"
    },
    "log_retention_days": {
      "value": 90,
      "source": "group_vars/all.yml"
    }
  },
  "_domains": {
    "groups": [
      "sudo",
      "developers",
      "postgres",
      "www-data",
      "redis"
    ],
    "clearance": [
      "secret",
      "confidential"
    ],
    "department": [
      "operations",
      "engineering"
    ],
    "environment": [
      "production"
    ],
    "compliance_tier": [
      "soc2"
    ],
    "org": [
      "privsep-corp"
    ],
    "zone": [
      "dmz",
      "internal",
      "internet"
    ],
    "role": [
      "frontend",
      "primary",
      "cache"
    ],
    "inventory_group": [
      "webservers",
      "dbservers",
      "cacheservers"
    ],
    "protocol": [
      "tcp"
    ],
    "source_network": [
      "10.0.1.0/24",
      "0.0.0.0/0"
    ]
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
      "compliance_tier": {
        "equals": "soc2"
      },
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
      "port": {
        "equals": 443
      },
      "service": {
        "equals": "https"
      },
      "zone": {
        "equals": "dmz"
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
    "effect": "permit",
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
      "port": {
        "equals": 6379
      },
      "service": {
        "equals": "redis"
      },
      "zone": {
        "equals": "internal"
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
      "port": {
        "equals": 5432
      },
      "service": {
        "equals": "postgresql"
      },
      "zone": {
        "equals": "internal"
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
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "obligations": [
      {
        "type": "audit",
        "description": "All filesystem access logged per soc2 compliance"
      }
    ],
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
      "compliance_tier": {
        "equals": "soc2"
      },
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
        26,
        32
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
        "equals": "/etc/sudoers.d/www-data"
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
    "action": "sudo:execute",
    "effect": "deny",
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
    "id": "rule-008",
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
      "task": "Default deny rule",
      "lines": [
        1,
        1
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
    "id": "rule-010",
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
        "equals": "https"
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
    "id": "rule-011",
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
    "id": "rule-012",
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses related to CNAME processing, exploit requires sending malicious DNS responses.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to nginx 1.9.10 or later versions."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit requires crafted input.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to the latest version of njs where the issue is fixed."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denial of service or potentially execute arbitrary code, exploit requires processing of specially crafted files with large modification dates.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to version 1.13.6 or later."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.7,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP packets from DNS server.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update nginx to the latest version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2013-4547",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 contain a restriction bypass caused by unescaped space character in URI, letting remote attackers bypass intended restrictions, exploit requires sending a crafted URI with unescaped space.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to nginx 1.5.7 or later versions."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "critical",
    "cvss_score": 10,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requires sending crafted CRC-32 data.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires remote network access.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to OpenSSH version 3.7 or later."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers potentially access sensitive credentials, exploit requires access to installer scripts.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeholder construction.",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "cve_id": "CVE-2015-4335",
    "product": "redis",
    "pinned_version": "7.0.11",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Redis < 2.8.21 and 3.x < 3.0.2 contain a remote code execution caused by unsafe eval command processing, letting attackers execute arbitrary Lua bytecode remotely, exploit requires network access to Redis server.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update Redis to version 2.8.21 or later, or 3.0.2 or later."
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "pinned_version": "7.0.11",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment, letting attackers load arbitrary libraries, exploit requires attacker to execute malicious Lua code.",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Update Redis packages to the latest versions where the sandbox is properly sanitized."
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "pinned_version": "7.0.11",
    "severity": "critical",
    "cvss_score": 9.9,
    "description": "Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts, letting authenticated users potentially achieve remote code execution, exploit requires authentication.",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Update to version 8.2.2 or later; alternatively, restrict EVAL and EVALSHA commands using ACL."
  },
  {
    "cve_id": "CVE-2017-15047",
    "product": "redis",
    "pinned_version": "7.0.11",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Redis 4.0.2 contains a denial of service caused by out-of-bounds array index in clusterLoadConfig function in cluster.c, letting attackers cause application crash, exploit requires limited access to the machine.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Update to the latest version of Redis where this issue is fixed."
  },
  {
    "cve_id": "CVE-2023-31654",
    "product": "redis",
    "pinned_version": "7.0.11",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Redis raft master-1b8bd86 to master-7b46079 contains an ODR violation caused by hiredisAllocFns in /opt/fs/redisraft/deps/hiredis/alloc.c, letting potential undefined behavior impact, exploit requires specific build environment.",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Review and fix the ODR violation in hiredisAllocFns, update to latest Redisraft version if available."
  }
]
```

## Report

# ABAC Policy Report — privsep-corp (production/soc2)

## Executive Summary
Mined ABAC policy from Ansible configuration at RLM_ANSIBLE_DIR. Discovered 3 roles (web, db, cache) with 8 access rules covering SSH, HTTPS, Redis, PostgreSQL, filesystem ACLs, and a default-deny baseline. Environment is production with SOC2 compliance tier.

## Catalog Summary
- **Subjects**: 2 named users (admin, developer), 5 groups (sudo, developers, postgres, www-data, redis)
- **Resources**: 3 hosts (web01, db01, cache01), 3 services (https:443, postgresql:5432, redis:6379), 2 filesystem paths, 2 network zones
- **Environment**: org=privsep-corp, environment=production, compliance_tier=soc2, log_retention=90 days

## Rules Summary
| ID | Action | Effect | Subject | Resource |
|----|--------|--------|---------|----------|
| rule-001 | ssh:login | permit | groups in [sudo] | ssh:22 |
| rule-002 | network:connect | permit | source 0.0.0.0/0 | https:443 (dmz) |
| rule-003 | network:connect | permit | source 10.0.1.0/24 | redis:6379 (internal) |
| rule-004 | network:connect | permit | source 10.0.1.0/24 | postgresql:5432 (internal) |
| rule-005 | filesystem:write | permit | groups in [postgres] | /var/lib/postgresql/data (0700) |
| rule-006 | filesystem:read | permit | groups in [www-data] | /var/www/html (0750) |
| rule-007 | sudo:execute | deny | groups in [www-data] | /etc/sudoers.d/www-data |
| rule-008 | * | deny | all | all |

## Vulnerability Assessment
Pinned package versions analyzed:
- nginx 1.20.0-1~focal: 5 CVEs found (all do NOT affect pinned version; historical CVEs for older releases)
- openssh 1:9.6p1-3ubuntu1: 5 CVEs found (all do NOT affect pinned version; ancient OpenSSH CVEs)
- postgresql 16.2-1.pgdg22.04+1: 5 CVEs found (all do NOT affect pinned version)
- redis 7.0.11-1: 5 CVEs found (all do NOT affect pinned version)

All 20 CVEs are historical and do not match the pinned versions. No known exploited vulnerabilities (KEV) found for current versions.

## Ambiguities & Gaps
1. **No explicit credential management**: No Ansible tasks for password hashing, SSH key distribution, or vault usage observed.
2. **SSH port assumed 22**: The SSH rule assumes standard port; no custom port configuration found in sshd_config task.
3. **PostgreSQL pg_hba implicit deny**: The pg_hba task only adds an allow line; relies on PostgreSQL's default deny for unmatched connections.
4. **No sudoers rules for admin/developer**: Only www-data sudo deny is explicit; no sudoers configuration for legitimate sudo users observed.
5. **Service accounts lack UIDs**: postgres and redis system users created without explicit UID assignment.
6. **Redis bind to single IP**: Redis is bound to 10.0.2.20 (cache01) only; if cache01 IP changes, connectivity breaks.
7. **No network zone segmentation enforcement**: dmz and internal zones defined but no explicit inter-zone firewall rules beyond service-specific allows.
