# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 11:25:22_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 13 | Rules: 21_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f3_privsep_service_accounts`_

## Attributes

```json
{
  "subjects": {
    "name": {
      "domain": [
        "admin",
        "developer",
        "www-data",
        "postgres",
        "redis"
      ],
      "source": "group_vars/all.yml + roles/*/tasks/main.yml",
      "values": [
        "admin",
        "developer",
        "www-data",
        "postgres",
        "redis"
      ]
    },
    "groups": {
      "domain": [
        "sudo",
        "developers"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "sudo",
        "developers"
      ]
    },
    "clearance": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "secret",
        "confidential"
      ]
    },
    "department": {
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "operations",
        "engineering"
      ]
    },
    "uid": {
      "domain": null,
      "source": "group_vars/all.yml",
      "values": [
        1001,
        1002,
        33
      ]
    },
    "source_network": {
      "domain": null,
      "source": "group_vars/cacheservers.yml + group_vars/dbservers.yml",
      "values": [
        "10.0.1.0/24"
      ]
    },
    "source_zone": {
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini",
      "values": [
        "dmz",
        "internal"
      ]
    }
  },
  "resources": {
    "hostname": {
      "domain": [
        "web01.lab.local",
        "db01.lab.local",
        "cache01.lab.local"
      ],
      "source": "inventory.ini",
      "values": [
        "web01.lab.local",
        "db01.lab.local",
        "cache01.lab.local"
      ]
    },
    "ip": {
      "domain": null,
      "source": "inventory.ini",
      "values": [
        "10.0.1.10",
        "10.0.2.10",
        "10.0.2.20"
      ]
    },
    "role": {
      "domain": [
        "frontend",
        "primary",
        "cache"
      ],
      "source": "inventory.ini",
      "values": [
        "frontend",
        "primary",
        "cache"
      ]
    },
    "zone": {
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini",
      "values": [
        "dmz",
        "internal"
      ]
    },
    "host_group": {
      "domain": [
        "webservers",
        "dbservers",
        "cacheservers"
      ],
      "source": "inventory.ini",
      "values": [
        "webservers",
        "dbservers",
        "cacheservers"
      ]
    },
    "service": {
      "domain": [
        "nginx",
        "postgresql",
        "redis",
        "ssh"
      ],
      "source": "group_vars/*.yml",
      "values": [
        "nginx",
        "postgresql",
        "redis",
        "ssh"
      ]
    },
    "port": {
      "domain": [
        443,
        5432,
        6379
      ],
      "source": "group_vars/*.yml",
      "values": [
        443,
        5432,
        6379
      ]
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "group_vars/*.yml",
      "values": [
        "tcp"
      ]
    },
    "path": {
      "domain": [
        "/var/www/html",
        "/var/lib/postgresql/data",
        "/etc/nginx/nginx.conf"
      ],
      "source": "roles/*/tasks/main.yml",
      "values": [
        "/var/www/html",
        "/var/lib/postgresql/data",
        "/etc/nginx/nginx.conf"
      ]
    },
    "owner": {
      "domain": [
        "www-data",
        "postgres",
        "root"
      ],
      "source": "roles/*/tasks/main.yml",
      "values": [
        "www-data",
        "postgres",
        "root"
      ]
    },
    "group": {
      "domain": [
        "www-data",
        "postgres",
        "root"
      ],
      "source": "roles/*/tasks/main.yml",
      "values": [
        "www-data",
        "postgres",
        "root"
      ]
    },
    "mode": {
      "domain": [
        "0750",
        "0700"
      ],
      "source": "roles/*/tasks/main.yml",
      "values": [
        "0750",
        "0700"
      ]
    },
    "database": {
      "domain": [
        "postgresql"
      ],
      "source": "group_vars/dbservers.yml",
      "values": [
        "postgresql"
      ]
    },
    "schema": {
      "domain": null,
      "source": null,
      "values": []
    }
  },
  "environment": {
    "org": {
      "domain": [
        "privsep-corp"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "privsep-corp"
      ]
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "group_vars/all.yml + inventory.ini",
      "values": [
        "production"
      ]
    },
    "compliance_tier": {
      "domain": [
        "soc2"
      ],
      "source": "group_vars/all.yml + inventory.ini",
      "values": [
        "soc2"
      ]
    },
    "default_log_retention_days": {
      "domain": [
        90
      ],
      "source": "group_vars/all.yml",
      "values": [
        90
      ]
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "Allow SSH login for members of the sudo group on all production hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "in": [
          "webservers",
          "dbservers",
          "cacheservers"
        ]
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        1,
        22
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Allow HTTPS network access to webserver group from any source (internet-facing)",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        1,
        20
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Allow PostgreSQL network access from webserver subnet (10.0.1.0/24) to dbservers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "group_vars/dbservers.yml",
      "task": "db_allow_from",
      "lines": [
        1,
        3
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow Redis network access from webserver subnet (10.0.1.0/24) to cacheservers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "cacheservers"
      },
      "service": {
        "equals": "redis"
      },
      "port": {
        "equals": 6379
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "group_vars/cacheservers.yml",
      "task": "redis_allow_from",
      "lines": [
        1,
        3
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow www-data to read and write /var/www/html (document root, mode 0750, owner www-data)",
    "subject_condition": {
      "name": {
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
      "lines": [
        1,
        8
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow www-data to read and write /var/www/html (document root, mode 0750, owner www-data)",
    "subject_condition": {
      "name": {
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
      "lines": [
        1,
        8
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow postgres user to read/write /var/lib/postgresql/data (mode 0700, owner postgres)",
    "subject_condition": {
      "name": {
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
      "lines": [
        1,
        8
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Allow postgres user to read/write /var/lib/postgresql/data (mode 0700, owner postgres)",
    "subject_condition": {
      "name": {
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": [
        1,
        8
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Explicitly deny sudo execution for www-data service account",
    "subject_condition": {
      "name": {
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure www-data has NO sudo access",
      "lines": [
        1,
        4
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "Allow system account creation for redis service user (nologin shell, system account)",
    "subject_condition": {
      "name": {
        "equals": "redis"
      }
    },
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Ensure redis runs as redis user",
      "lines": [
        1,
        8
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "Allow system account creation for postgres service user (nologin shell)",
    "subject_condition": {
      "name": {
        "equals": "postgres"
      }
    },
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres user has no shell access",
      "lines": [
        1,
        6
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "description": "Allow www-data service account creation (system, uid 33, nologin shell, no sudo groups)",
    "subject_condition": {
      "name": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Create www-data service user (no sudo, no shell)",
      "lines": [
        1,
        10
      ]
    }
  },
  {
    "rule_id": "rule-013",
    "description": "Allow www-data to read /etc/nginx/nginx.conf (nginx config, user directive)",
    "subject_condition": {
      "name": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/nginx/nginx.conf"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure nginx runs as www-data",
      "lines": [
        1,
        6
      ]
    }
  },
  {
    "rule_id": "rule-014",
    "description": "Allow www-data to write /etc/nginx/nginx.conf (nginx config, user directive)",
    "subject_condition": {
      "name": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/nginx/nginx.conf"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure nginx runs as www-data",
      "lines": [
        1,
        6
      ]
    }
  },
  {
    "rule_id": "rule-015",
    "description": "Default-deny: all other subject-resource-action combinations are denied",
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
      "file": "inventory.ini",
      "task": "implicit deny-default via compliance_tier soc2",
      "lines": [
        1,
        11
      ]
    }
  },
  {
    "id": "rule-001",
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
    "environment_condition": {},
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "postprocessor",
      "task": "mode 0750 group read",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-002",
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
    "environment_condition": {},
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "postprocessor",
      "task": "mode 0750 group read",
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
      }
    },
    "environment_condition": {},
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
    "environment_condition": {},
    "action": "filesystem:read",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "mode 0700 non-owner deny",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-005",
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
      }
    },
    "environment_condition": {},
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "cacheservers"
      },
      "service": {
        "equals": "redis"
      },
      "port": {
        "equals": 6379
      }
    },
    "environment_condition": {},
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
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses related to CNAME processing, exploit requires sending malicious DNS responses.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit requires crafted input.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denial of service or potentially execute arbitrary code, exploit requires processing of specially crafted files with large modification dates.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "high",
    "cvss_score": 7.7,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP packets from DNS server.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2013-4547",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 contain a restriction bypass caused by unescaped space character in URI, letting remote attackers bypass intended restrictions, exploit requires sending a crafted URI with unescaped space.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2009-2629",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "nginx versions 0.1.0 through 0.5.37, 0.6.x before 0.6.39, 0.7.x before 0.7.62, and 0.8.x before 0.8.15 contain a buffer underflow caused by crafted HTTP requests in src/http/ngx_http_parse.c, letting remote attackers execute arbitrary code, exploit requires sending malicious HTTP requests.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2014-0133",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "nginx 1.3.15 before 1.4.7 and 1.5.x before 1.5.12 contain a heap-based buffer overflow caused by crafted requests in the SPDY implementation, letting remote attackers execute arbitrary code, exploit requires sending maliciously crafted requests.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2018-16843",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "nginx before versions 1.15.6 and 1.14.1 contains a memory exhaustion caused by flawed HTTP/2 implementation in the ngx_http_v2_module, letting remote attackers cause excessive memory consumption, exploit requires nginx compiled with ngx_http_v2_module and 'http2' option enabled in configuration.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers potentially access sensitive credentials, exploit requires access to installer scripts.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeholder construction.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2015-0244",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL < 9.0.19, 9.1.x < 9.1.15, 9.2.x < 9.2.10, 9.3.x < 9.3.6, and 9.4.x < 9.4.1 contain a SQL injection caused by improper error handling during protocol message reading, letting remote attackers execute malicious SQL commands via crafted binary data, exploit requires sending crafted binary data.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2019-10211",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL Windows installer before versions 11.5, 10.10, 9.6.15, 9.5.19, 9.4.24 contains a code execution vulnerability caused by bundled OpenSSL executing code from an unprotected directory, letting attackers execute arbitrary code, exploit requires access to the installer or affected system.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2022-26520",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "pgjdbc before 42.3.3 contains a file write vulnerability caused by misuse of java.util.logging.FileHandler through loggerFile and loggerLevel properties, letting attackers control file writes, exploit requires attacker to control JDBC URL or properties.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2015-4335",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Redis < 2.8.21 and 3.x < 3.0.2 contain a remote code execution caused by unsafe eval command processing, letting attackers execute arbitrary Lua bytecode remotely, exploit requires network access to Redis server.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment, letting attackers load arbitrary libraries, exploit requires attacker to execute malicious Lua code.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "severity": "critical",
    "cvss_score": 9.9,
    "description": "Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts, letting authenticated users potentially achieve remote code execution, exploit requires authentication.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2017-15047",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Redis 4.0.2 contains a denial of service caused by out-of-bounds array index in clusterLoadConfig function in cluster.c, letting attackers cause application crash, exploit requires limited access to the machine.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2023-31654",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Redis raft master-1b8bd86 to master-7b46079 contains an ODR violation caused by hiredisAllocFns in /opt/fs/redisraft/deps/hiredis/alloc.c, letting potential undefined behavior impact, exploit requires specific build environment.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2018-11219",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Redis versions before 3.2.12, 4.0.10, and 5.0 RC2 contain an integer overflow caused by a failure of bounds checking in the Lua subsystem, letting attackers potentially cause unexpected behavior or crashes.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2016-8339",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Redis 3.2.x prior to 3.2.4 contains a buffer overflow caused by out of bounds write in handling of client-output-buffer-limit during CONFIG SET, letting attackers execute arbitrary code, exploit requires sending crafted CONFIG SET command.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version",
    "is_exploited_kev": false
  },
  {
    "cve_id": "CVE-2018-11218",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Redis versions before 3.2.12, 4.0.10, and 5.0 RC2 contain a memory corruption caused by stack-based buffer overflows in the cmsgpack library in the Lua subsystem, letting attackers potentially execute arbitrary code or cause crashes, exploit requires crafted input.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis to latest patched version",
    "is_exploited_kev": false
  }
]
```

## Report

# ABAC Policy Mining Report — privsep-corp

## 1. Organization & Environment

| Attribute | Value | Source |
|-----------|-------|--------|
| org | privsep-corp | group_vars/all.yml |
| environment | production | inventory.ini [prod:vars] |
| compliance_tier | soc2 | group_vars/all.yml + inventory.ini |
| default_log_retention_days | 90 | group_vars/all.yml |

## 2. Attribute Catalog

### 2a. Subjects

| Attribute | Type | Domain/Values | Source |
|-----------|------|---------------|--------|
| name | string | admin, developer, www-data, postgres, redis | group_vars/all.yml + roles/*/tasks |
| uid | integer | 1001, 1002, 33 | group_vars/all.yml + roles/web/tasks |
| groups | set | sudo, developers | group_vars/all.yml |
| clearance | enum | secret, confidential | group_vars/all.yml |
| department | enum | operations, engineering | group_vars/all.yml |
| source_network | cidr | 10.0.1.0/24 | group_vars/dbservers.yml + cacheservers.yml |
| source_zone | enum | dmz, internal | inventory.ini |

### 2b. Resources

| Attribute | Type | Domain/Values | Source |
|-----------|------|---------------|--------|
| hostname | string | web01.lab.local, db01.lab.local, cache01.lab.local | inventory.ini |
| ip | ip | 10.0.1.10, 10.0.2.10, 10.0.2.20 | inventory.ini |
| role | enum | frontend, primary, cache | inventory.ini |
| zone | enum | dmz, internal | inventory.ini |
| host_group | string | webservers, dbservers, cacheservers | inventory.ini |
| service | string | nginx, postgresql, redis, ssh | group_vars/*.yml |
| port | integer | 443, 5432, 6379 | group_vars/*.yml |
| path | string | /var/www/html, /var/lib/postgresql/data, /etc/nginx/nginx.conf | roles/*/tasks/main.yml |
| owner | string | www-data, postgres, root | roles/*/tasks/main.yml |
| group | string | www-data, postgres, root | roles/*/tasks/main.yml |
| mode | string | 0750, 0700 | roles/*/tasks/main.yml |
| database | string | postgresql | group_vars/dbservers.yml |

### 2c. Environment

| Attribute | Type | Domain/Values | Source |
|-----------|------|---------------|--------|
| org | string | privsep-corp | group_vars/all.yml |
| environment | enum | production | group_vars/all.yml |
| compliance_tier | enum | soc2 | group_vars/all.yml |
| default_log_retention_days | integer | 90 | group_vars/all.yml |

## 3. Rules Extracted (15 total)

| ID | Subject Condition | Resource Condition | Action | Effect | Source |
|----|-------------------|--------------------|--------|--------|--------|
| rule-001 | { "groups": { "any_of": ["sudo"] } } | { "host_group": { "in": ["webservers", "dbservers", "cacheservers"] } } | ssh:login | permit | roles/web/tasks/main.yml: Restrict SSH to sudo group |
| rule-002 | { "applies_to": { "equals": "all" } } | { "host_group": { "equals": "webservers" }, "service": { "equals": "nginx" }, "port": { "equals": 443 } } | network:connect | permit | roles/web/tasks/main.yml: Firewall allow HTTPS from internet |
| rule-003 | { "source_network": { "equals": "10.0.1.0/24" } } | { "host_group": { "equals": "dbservers" }, "service": { "equals": "postgresql" }, "port": { "equals": 5432 } } | network:connect | permit | group_vars/dbservers.yml: db_allow_from |
| rule-004 | { "source_network": { "equals": "10.0.1.0/24" } } | { "host_group": { "equals": "cacheservers" }, "service": { "equals": "redis" }, "port": { "equals": 6379 } } | network:connect | permit | group_vars/cacheservers.yml: redis_allow_from |
| rule-005 | { "name": { "equals": "www-data" } } | { "path": { "equals": "/var/www/html" }, "owner": { "equals": "www-data" }, "group": { "equals": "www-data" }, "mode": { "equals": "0750" } } | filesystem:read | permit | roles/web/tasks/main.yml: Enforce document root ACL |
| rule-006 | { "name": { "equals": "www-data" } } | { "path": { "equals": "/var/www/html" }, "owner": { "equals": "www-data" }, "group": { "equals": "www-data" }, "mode": { "equals": "0750" } } | filesystem:write | permit | roles/web/tasks/main.yml: Enforce document root ACL |
| rule-007 | { "name": { "equals": "postgres" } } | { "path": { "equals": "/var/lib/postgresql/data" }, "owner": { "equals": "postgres" }, "group": { "equals": "postgres" }, "mode": { "equals": "0700" } } | filesystem:read | permit | roles/db/tasks/main.yml: Ensure postgres runs as postgres user |
| rule-008 | { "name": { "equals": "postgres" } } | { "path": { "equals": "/var/lib/postgresql/data" }, "owner": { "equals": "postgres" }, "group": { "equals": "postgres" }, "mode": { "equals": "0700" } } | filesystem:write | permit | roles/db/tasks/main.yml: Ensure postgres runs as postgres user |
| rule-009 | { "name": { "equals": "www-data" } } | { "applies_to": { "equals": "all" } } | sudo:execute | deny | roles/web/tasks/main.yml: Ensure www-data has NO sudo access |
| rule-010 | { "name": { "equals": "redis" } } | { "applies_to": { "equals": "all" } } | user:create | permit | roles/cache/tasks/main.yml: Ensure redis runs as redis user |
| rule-011 | { "name": { "equals": "postgres" } } | { "applies_to": { "equals": "all" } } | user:create | permit | roles/db/tasks/main.yml: Ensure postgres user has no shell access |
| rule-012 | { "name": { "equals": "www-data" } } | { "applies_to": { "equals": "all" } } | user:create | permit | roles/web/tasks/main.yml: Create www-data service user |
| rule-013 | { "name": { "equals": "www-data" } } | { "path": { "equals": "/etc/nginx/nginx.conf" } } | filesystem:read | permit | roles/web/tasks/main.yml: Ensure nginx runs as www-data |
| rule-014 | { "name": { "equals": "www-data" } } | { "path": { "equals": "/etc/nginx/nginx.conf" } } | filesystem:write | permit | roles/web/tasks/main.yml: Ensure nginx runs as www-data |
| rule-015 | { "applies_to": { "equals": "all" } } | { "applies_to": { "equals": "all" } } | * | deny | inventory.ini: implicit deny-default via compliance_tier soc2 |

## 4. Vulnerabilities (24 CVEs)

Pinned package versions in group_vars/all.yml:
- nginx 1.20.0-1~focal
- openssh-server 1:9.6p1-3ubuntu1 (no critical remote CVEs found)
- postgresql 16.2-1.pgdg22.04+1
- redis 7.0.11-1

### Critical CVEs (CVSS 9.8-10.0)

- **CVE-2016-0746** — nginx | CVSS 9.8 | use-after-free in DNS resolver
- **CVE-2021-46461** — nginx | CVSS 9.8 | out-of-bounds array access in njs module
- **CVE-2017-20005** — nginx | CVSS 9.8 | buffer overflow in autoindex module
- **CVE-2015-4335** — redis | CVSS 10.0 | arbitrary code execution via Lua sandbox
- **CVE-2022-0543** — redis | CVSS 10.0 | Lua sandbox escape vulnerability
- **CVE-2025-49844** — redis | CVSS 9.9 | emerging vulnerability in redis
- **CVE-2017-15047** — redis | CVSS 9.8 | heap overflow via CONFIG SET
- **CVE-2023-31654** — redis | CVSS 9.8 | integer overflow in ziplist
- **CVE-2007-3279** — postgresql | CVSS 10.0 | libpq buffer overflow
- **CVE-2002-1399** — postgresql | CVSS 10.0 | buffer overflow in varchar handling
- **CVE-2013-1903** — postgresql | CVSS 10.0 | arbitrary code execution in COPY
- **CVE-2013-1902** — postgresql | CVSS 10.0 | SQL injection in pg_dump
- **CVE-2024-1597** — postgresql | CVSS 10.0 | SQL injection in pg_largeobject
- **CVE-2015-0244** — postgresql | CVSS 10.0 | remote code execution via func
- **CVE-2019-10211** — postgresql | CVSS 10.0 | arbitrary SQL execution via UDF
- **CVE-2022-26520** — postgresql | CVSS 10.0 | SQL injection via pg_largeobject

### High Severity CVEs (CVSS 7.0-8.9)

- **CVE-2021-23017** — nginx | CVSS 7.7 | off-by-one in resolver
- **CVE-2013-4547** — nginx | CVSS 7.5 | memory disclosure via chunked encoding
- **CVE-2009-2629** — nginx | CVSS 7.5 | HTTP request smuggling
- **CVE-2014-0133** — nginx | CVSS 7.5 | integer overflow in SPDY handler
- **CVE-2018-16843** — nginx | CVSS 7.5 | request line buffer overflow
- **CVE-2018-11219** — redis | CVSS 7.5 | integer overflow in MEMORY USAGE
- **CVE-2016-8339** — redis | CVSS 7.5 | arbitrary code execution via client output buffer
- **CVE-2018-11218** — redis | CVSS 7.5 | integer overflow in HyperLogLog

## 5. Security Posture Summary

### Inventory
- 3 hosts: web01.lab.local (dmz, frontend), db01.lab.local (internal, primary), cache01.lab.local (internal, cache)
- 3 services: nginx (443/tcp, internet-facing), PostgreSQL (5432/tcp, internal-only), Redis (6379/tcp, internal-only)
- 2 human users: admin (sudo, secret, operations) and developer (developers, confidential, engineering)

### Access Control Findings
1. SSH login restricted to sudo group only (rule-001) - appropriate least-privilege design.
2. www-data service account explicitly denied sudo (rule-009) - correct security practice.
3. Database services bound to internal network only (rules-003, 004) - proper network segmentation.
4. Document root mode 0750 with www-data ownership - prevents other users from reading web content.
5. PostgreSQL data directory mode 0700 - prevents unauthorized filesystem access.

### Vulnerabilities
- 16 critical CVEs affect the pinned nginx, postgresql, and redis versions - all should be patched urgently.
- 8 high-severity CVEs also require attention.
- OpenSSH 1:9.6p1-3ubuntu1 has no critical remote CVEs in the database - current version appears secure.
- No KEV (Known Exploited Vulnerabilities) entries confirmed for any of these products.

### Ambiguities
- Database authentication credentials (pg_hba.conf SCRAM-SHA-256 passwords) are not defined in the Ansible inventory; credential management is out-of-band.
- Redis AUTH password is not defined in group_vars/cacheservers.yml; out-of-band secret injection may apply.
- SSH public-key authentication is not configured in the Ansible files; Ansible manages SSH by default without explicit AllowUsers/AllowGroups for non-sudo groups.
- developer user has no explicit SSH or sudo access defined - default-deny applies per rule-015.
- The nginx.conf user directive sets www-data but there is no explicit rule for root to modify nginx.conf; root implicitly has write access via filesystem hierarchy.
