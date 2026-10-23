# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:07:48_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 15 | Rules: 24_  
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
        "department": null,
        "clearance": null,
        "source": "roles/web/tasks/main.yml",
        "is_service_account": true
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [
          "postgres"
        ],
        "department": null,
        "clearance": null,
        "source": "roles/db/tasks/main.yml",
        "is_service_account": true
      },
      {
        "name": "redis",
        "uid": null,
        "groups": [
          "redis"
        ],
        "department": null,
        "clearance": null,
        "source": "roles/cache/tasks/main.yml",
        "is_service_account": true
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
      {
        "name": "secret",
        "domain": [
          "secret",
          "confidential",
          "restricted",
          "public"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "name": "confidential",
        "domain": [
          "secret",
          "confidential",
          "restricted",
          "public"
        ],
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "name": "operations",
        "domain": [
          "operations",
          "engineering",
          "security",
          "hr"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "name": "engineering",
        "domain": [
          "operations",
          "engineering",
          "security",
          "hr"
        ],
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
        "label": "web_subnet",
        "source": "inventory.ini"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "internal",
        "label": "internal_subnet",
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
    "org": {
      "value": "privsep-corp",
      "domain": [
        "privsep-corp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "domain": [
        "production",
        "staging",
        "development"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "domain": [
        "soc2",
        "pci-dss",
        "hipaa",
        "iso27001"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "value": 90,
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
      "inventory_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "Log all SSH sessions per SOC2"
      }
    ],
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
    "rule_id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "ssh:login",
    "effect": "deny",
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
    "rule_id": "rule-003",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
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
        34,
        41
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
      "inventory_group": {
        "equals": "dbservers"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
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
        18,
        23
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "cacheservers"
      },
      "port": {
        "equals": 6379
      },
      "protocol": {
        "equals": "tcp"
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
        18,
        23
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
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
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        19,
        21
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "in": [
          "db01.lab.local",
          "cache01.lab.local"
        ]
      },
      "service": {
        "in": [
          "postgresql",
          "redis"
        ]
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
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        19,
        21
      ]
    }
  },
  {
    "rule_id": "rule-008",
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
    "action": "filesystem:write",
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
    "rule_id": "rule-009",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
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
        26,
        32
      ]
    }
  },
  {
    "rule_id": "rule-010",
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
    "action": "filesystem:execute",
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
    "rule_id": "rule-011",
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
        13
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
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": [
        8,
        13
      ]
    }
  },
  {
    "rule_id": "rule-013",
    "subject_condition": {
      "name": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "deny",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Create www-data service user (no sudo, no shell)",
      "lines": [
        13,
        18
      ]
    }
  },
  {
    "rule_id": "rule-014",
    "subject_condition": {
      "name": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
    "rule_id": "rule-015",
    "subject_condition": {
      "name": {
        "equals": "postgres"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres user has no shell access",
      "lines": [
        15,
        17
      ]
    }
  },
  {
    "rule_id": "rule-016",
    "subject_condition": {
      "name": {
        "equals": "redis"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "deny",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Ensure redis runs as redis user",
      "lines": [
        8,
        11
      ]
    }
  },
  {
    "rule_id": "rule-017",
    "subject_condition": {
      "source_ip": {
        "equals": "10.0.2.20"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "cache01.lab.local"
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
    "action": "network:bind",
    "effect": "permit",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Bind redis to internal interface only",
      "lines": [
        13,
        16
      ]
    }
  },
  {
    "rule_id": "rule-018",
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
      "file": "inventory.ini",
      "task": "[prod:vars] default-deny policy",
      "lines": [
        1,
        16
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
    "id": "rule-004",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
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
    "id": "rule-005",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
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
    "id": "rule-006",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 6379
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
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses related to CNAME processing, exploit requires sending malicious DNS responses.",
    "affects_pinned_version": false,
    "recommendation": "nginx 1.20.0 not affected."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denial of service or potentially execute arbitrary code, exploit requires processing of specially crafted",
    "affects_pinned_version": false,
    "recommendation": "nginx 1.20.0 not affected."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of renegotiation handshakes with existing connections, letting man-in-the-middle attackers inject data ",
    "affects_pinned_version": false,
    "recommendation": "nginx 1.20.0 not affected."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit requires crafted input.",
    "affects_pinned_version": true,
    "recommendation": "URGENT: nginx 1.20.0 affected. Patch immediately."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP packets from DNS server.",
    "affects_pinned_version": true,
    "recommendation": "URGENT: nginx 1.20.0 affected. Patch immediately."
  },
  {
    "cve_id": "CVE-2017-7529",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "Nginx versions 0.5.6 to 1.13.2 contain an integer overflow caused by the range filter module, letting attackers leak sensitive information, exploit requires sending a specially crafted request.",
    "affects_pinned_version": false,
    "recommendation": "nginx 1.20.0 not affected."
  },
  {
    "cve_id": "CVE-2016-0742",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "nginx before 1.8.1 and 1.9.x before 1.9.10 contain a denial of service caused by invalid pointer dereference in resolver when processing crafted UDP DNS responses, letting remote attackers crash worker processes, exploit requires sending malicious DNS responses.",
    "affects_pinned_version": false,
    "recommendation": "nginx 1.20.0 not affected."
  },
  {
    "cve_id": "CVE-2014-0088",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "nginx 1.5.10 before 1.5.11 with the ngx_http_spdy_module contains a buffer overflow caused by crafted request in SPDY implementation, letting remote attackers execute arbitrary code, exploit requires sending a malicious request.",
    "affects_pinned_version": false,
    "recommendation": "nginx 1.20.0 not affected."
  },
  {
    "cve_id": "CVE-2013-0337",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "nginx <= 1.3.13 contains a misconfiguration causing access.log and error.log files to be world-readable, letting local users read sensitive information, exploit requires local access.",
    "affects_pinned_version": false,
    "recommendation": "nginx 1.20.0 not affected."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many streams quickly, letting attackers consume server resources, exploit has been observed in the wild from August to October 2023.",
    "affects_pinned_version": true,
    "recommendation": "URGENT: nginx 1.20.0 affected. Patch immediately."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires remote network access.",
    "affects_pinned_version": false,
    "recommendation": "openssh 9.6p1 not affected."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled.",
    "affects_pinned_version": false,
    "recommendation": "openssh 9.6p1 not affected."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input.",
    "affects_pinned_version": false,
    "recommendation": "openssh 9.6p1 not affected."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requires sending crafted CRC-32 data.",
    "affects_pinned_version": false,
    "recommendation": "openssh 9.6p1 not affected."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input.",
    "affects_pinned_version": false,
    "recommendation": "openssh 9.6p1 not affected."
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentication, letting remote attackers execute arbitrary code, exploit requires specific PAM configuration.",
    "affects_pinned_version": false,
    "recommendation": "openssh 9.6p1 not affected."
  },
  {
    "cve_id": "CVE-2016-1908",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "OpenSSH < 7.2 mishandles failed cookie generation for untrusted X11 forwarding caused by reliance on local X11 server for access control, letting remote X11 clients trigger fallback and gain trusted forwarding privileges, exploit requires configuration issues on the X11 server.",
    "affects_pinned_version": false,
    "recommendation": "openssh 9.6p1 not affected."
  },
  {
    "cve_id": "CVE-2023-28531",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "OpenSSH before 9.3 contains a vulnerability in ssh-add that adds smartcard keys to ssh-agent without enforcing per-hop destination constraints, letting attackers potentially escalate privileges or access unauthorized systems, exploit requires attacker to have access to the smartcard keys.",
    "affects_pinned_version": false,
    "recommendation": "openssh 9.6p1 not affected."
  },
  {
    "cve_id": "CVE-2002-0639",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "OpenSSH 2.9.9 through 3.3 contains an integer overflow caused by improper handling during challenge response authentication in sshd, letting remote attackers execute arbitrary code when using SKEY or BSD_AUTH, exploit requires remote access to sshd.",
    "affects_pinned_version": false,
    "recommendation": "openssh 9.6p1 not affected."
  },
  {
    "cve_id": "CVE-2010-4478",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "OpenSSH 5.6 and earlier with J-PAKE enabled contains a validation bypass caused by improper validation of public parameters in the J-PAKE protocol, letting remote attackers authenticate without knowledge of the shared secret, exploit requires sending crafted values in each protocol round.",
    "affects_pinned_version": false,
    "recommendation": "openssh 9.6p1 not affected."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "affects_pinned_version": false,
    "recommendation": "postgresql 16.2 not affected."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers ",
    "affects_pinned_version": false,
    "recommendation": "postgresql 16.2 not affected."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified.",
    "affects_pinned_version": false,
    "recommendation": "postgresql 16.2 not affected."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "is_poc": false,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeh",
    "affects_pinned_version": false,
    "recommendation": "postgresql 16.2 not affected."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation.",
    "affects_pinned_version": false,
    "recommendation": "postgresql 16.2 not affected."
  },
  {
    "cve_id": "CVE-2015-3166",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "PostgreSQL versions before 9.0.20, 9.1.x before 9.1.16, 9.2.x before 9.2.11, 9.3.x before 9.3.7, and 9.4.x before 9.4.2 contain a snprintf handling issue caused by improper error handling in system calls, letting attackers potentially obtain sensitive information or cause other impacts via unknown v",
    "affects_pinned_version": false,
    "recommendation": "postgresql 16.2 not affected."
  },
  {
    "cve_id": "CVE-2018-16850",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "PostgreSQL before versions 11.1, 10.6 contains a sql_injection caused by crafted trigger definitions in pg_upgrade and pg_dump via CREATE TRIGGER ... REFERENCING, letting attackers execute arbitrary SQL statements with superuser privileges, exploit requires attacker to craft specific trigger definit",
    "affects_pinned_version": false,
    "recommendation": "postgresql 16.2 not affected."
  },
  {
    "cve_id": "CVE-2017-7546",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "PostgreSQL versions before 9.2.22, 9.3.18, 9.4.13, 9.5.8, and 9.6.4 contain an incorrect authentication flaw caused by improper password validation, letting remote attackers access database accounts with empty passwords, exploit requires network access.",
    "affects_pinned_version": false,
    "recommendation": "postgresql 16.2 not affected."
  },
  {
    "cve_id": "CVE-2019-10211",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "PostgreSQL Windows installer before versions 11.5, 10.10, 9.6.15, 9.5.19, 9.4.24 contains a code execution vulnerability caused by bundled OpenSSL executing code from an unprotected directory, letting attackers execute arbitrary code, exploit requires access to the installer or affected system.",
    "affects_pinned_version": false,
    "recommendation": "postgresql 16.2 not affected."
  },
  {
    "cve_id": "CVE-2015-0244",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "PostgreSQL < 9.0.19, 9.1.x < 9.1.15, 9.2.x < 9.2.10, 9.3.x < 9.3.6, and 9.4.x < 9.4.1 contain a SQL injection caused by improper error handling during protocol message reading, letting remote attackers execute malicious SQL commands via crafted binary data, exploit requires sending crafted binary da",
    "affects_pinned_version": false,
    "recommendation": "postgresql 16.2 not affected."
  },
  {
    "cve_id": "CVE-2015-4335",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "Redis < 2.8.21 and 3.x < 3.0.2 contain a remote code execution caused by unsafe eval command processing, letting attackers execute arbitrary Lua bytecode remotely, exploit requires network access to Redis server.",
    "affects_pinned_version": false,
    "recommendation": "redis 7.0.11 not affected."
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "description": "Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment, letting attackers load arbitrary libraries, exploit requires attacker to execute malicious Lua code.",
    "affects_pinned_version": true,
    "recommendation": "URGENT: redis 7.0.11 affected. Patch immediately."
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 9.9,
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "description": "Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts, letting authenticated users potentially achieve remote code execution, exploit requires authentication.",
    "affects_pinned_version": true,
    "recommendation": "URGENT: redis 7.0.11 affected. Patch immediately."
  },
  {
    "cve_id": "CVE-2016-8339",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "Redis 3.2.x prior to 3.2.4 contains a buffer overflow caused by out of bounds write in handling of client-output-buffer-limit during CONFIG SET, letting attackers execute arbitrary code, exploit requires sending crafted CONFIG SET command.",
    "affects_pinned_version": false,
    "recommendation": "redis 7.0.11 not affected."
  },
  {
    "cve_id": "CVE-2018-11219",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "Redis versions before 3.2.12, 4.0.10, and 5.0 RC2 contain an integer overflow caused by a failure of bounds checking in the Lua subsystem, letting attackers potentially cause unexpected behavior or crashes.",
    "affects_pinned_version": false,
    "recommendation": "redis 7.0.11 not affected."
  },
  {
    "cve_id": "CVE-2023-31654",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "Redis raft master-1b8bd86 to master-7b46079 contains an ODR violation caused by hiredisAllocFns in /opt/fs/redisraft/deps/hiredis/alloc.c, letting potential undefined behavior impact, exploit requires specific build environment.",
    "affects_pinned_version": true,
    "recommendation": "URGENT: redis 7.0.11 affected. Patch immediately."
  },
  {
    "cve_id": "CVE-2017-15047",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "Redis 4.0.2 contains a denial of service caused by out-of-bounds array index in clusterLoadConfig function in cluster.c, letting attackers cause application crash, exploit requires limited access to the machine.",
    "affects_pinned_version": false,
    "recommendation": "redis 7.0.11 not affected."
  },
  {
    "cve_id": "CVE-2018-11218",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "Redis versions before 3.2.12, 4.0.10, and 5.0 RC2 contain a memory corruption caused by stack-based buffer overflows in the cmsgpack library in the Lua subsystem, letting attackers potentially execute arbitrary code or cause crashes, exploit requires crafted input.",
    "affects_pinned_version": false,
    "recommendation": "redis 7.0.11 not affected."
  },
  {
    "cve_id": "CVE-2026-25243",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 8.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "description": "Redis redis-server <= 8.6.3 contains a remote code execution caused by improper validation of serialized values in the RESTORE command, letting authenticated attackers execute arbitrary code remotely, exploit requires RESTORE command permission.",
    "affects_pinned_version": true,
    "recommendation": "URGENT: redis 7.0.11 affected. Patch immediately."
  },
  {
    "cve_id": "CVE-2026-23479",
    "product": "redis",
    "pinned_version": "7.0.11",
    "cvss_score": 8.8,
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "description": "Redis redis-server 7.2.0 to 8.6.3 contains a use-after-free caused by improper error handling in unblock client flow during blocked command re-execution, letting authenticated attackers achieve remote code execution.",
    "affects_pinned_version": false,
    "recommendation": "redis 7.0.11 not affected."
  }
]
```

## Report

# ABAC Policy Report — privsep-corp

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration for the **privsep-corp** production environment. The deployment consists of three tiers: webservers (DMZ), dbservers (internal), and cacheservers (internal), with explicit service account privilege separation.

**Environment**: production | **Compliance**: SOC2 | **Organization**: privsep-corp

## 1. Attribute Catalog

### 1.1 Subjects
- **Users**: 5 defined (2 human: admin, developer; 3 service accounts: www-data, postgres, redis)
- **Groups**: sudo, developers, www-data, postgres, redis
- **Clearance Levels**: secret, confidential
- **Departments**: operations, engineering

### 1.2 Resources
- **Hosts**: web01.lab.local (DMZ), db01.lab.local (internal), cache01.lab.local (internal)
- **Services**: nginx (443/tcp), ssh (22/tcp), postgresql (5432/tcp), redis (6379/tcp)
- **Paths**: /var/www/html (0750), /var/lib/postgresql/data (0700)
- **Networks**: 10.0.1.0/24 (DMZ), 10.0.2.0/24 (internal), 0.0.0.0/0 (internet)

### 1.3 Environment
- org: privsep-corp
- environment: production
- compliance_tier: soc2
- default_log_retention_days: 90

## 2. Access Rules Summary

| Rule ID | Action | Effect | Subject | Resource | Source |
|---------|--------|--------|---------|----------|--------|
| rule-001 | ssh:login | permit | groups: sudo | webservers | roles/web/tasks/main.yml |
| rule-002 | ssh:login | deny | groups: developers | webservers | roles/web/tasks/main.yml |
| rule-003 | network:connect | permit | source: 0.0.0.0/0 | webservers:443 | roles/web/tasks/main.yml |
| rule-004 | network:connect | permit | source: 10.0.1.0/24 | dbservers:5432 | roles/db/tasks/main.yml |
| rule-005 | network:connect | permit | source: 10.0.1.0/24 | cacheservers:6379 | roles/cache/tasks/main.yml |
| rule-006 | db:login | permit | source: 10.0.1.0/24 | db01.lab.local | roles/db/tasks/main.yml |
| rule-007 | network:connect | deny | source: 10.0.1.0/24 | db/cache services | roles/db/tasks/main.yml |
| rule-008 | filesystem:write | permit | groups: www-data | /var/www/html | roles/web/tasks/main.yml |
| rule-009 | filesystem:read | permit | groups: sudo | /var/www/html | roles/web/tasks/main.yml |
| rule-010 | filesystem:execute | permit | groups: www-data | /var/www/html | roles/web/tasks/main.yml |
| rule-011 | filesystem:write | permit | groups: postgres | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| rule-012 | filesystem:read | deny | applies_to: all | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| rule-013 | ssh:login | deny | user: www-data | ssh service | roles/web/tasks/main.yml |
| rule-014 | sudo:execute | deny | user: www-data | web01.lab.local | roles/web/tasks/main.yml |
| rule-015 | ssh:login | deny | user: postgres | ssh service | roles/db/tasks/main.yml |
| rule-016 | ssh:login | deny | user: redis | ssh service | roles/cache/tasks/main.yml |
| rule-017 | network:bind | permit | source: 10.0.2.20 | cache01.lab.local | roles/cache/tasks/main.yml |
| rule-018 | * | deny | applies_to: all | applies_to: all | inventory.ini |

**Total rules**: 18 (9 permit, 9 deny including default-deny)

## 3. Vulnerability Assessment

### 3.1 Pinned Software Versions
| Package | Pinned Version | Status |
|---------|---------------|--------|
| nginx | 1.20.0 | 3 CVEs affecting |
| openssh | 9.6p1 | 0 CVEs affecting |
| postgresql | 16.2 | 0 CVEs affecting |
| redis | 7.0.11 | 3 CVEs affecting |

### 3.2 Critical Vulnerabilities (Affecting Pinned Versions)

| CVE | Product | CVSS | Remote | KEV | Description |
|-----|---------|------|--------|-----|-------------|
| CVE-2022-0543 | redis 7.0.11 | 10.0 | Yes | Yes | Debian/Ubuntu Redis Lua sandbox escape |
| CVE-2025-49844 | redis 7.0.11 | 9.9 | Yes | No | Redis use-after-free via manipulation |
| CVE-2021-46461 | nginx 1.20.0 | 9.8 | Yes | No | nginx njs out-of-bounds array access |
| CVE-2023-31654 | redis 7.0.11 | 9.8 | Yes | No | Redis raft ODR violation |
| CVE-2026-25243 | redis 7.0.11 | 8.8 | Yes | No | Redis RCE via serialized values in RESTORE |
| CVE-2021-23017 | nginx 1.20.0 | 7.7 | Yes | No | nginx resolver 1-byte memory overwrite |
| CVE-2023-44487 | nginx 1.20.0 | 7.5 | Yes | No | HTTP/2 rapid reset DoS |

**Recommendation**: Redis 7.0.11 requires immediate patching due to CVE-2022-0543 (CVSS 10.0, KEV-listed Lua sandbox escape) and multiple RCE/UAF vulnerabilities. nginx 1.20.0 should be upgraded to ≥1.21.1 for resolver fixes.

## 4. Ambiguities and Notes

- **SSH Port**: The SSH port (22) is not explicitly defined in group_vars; it is inferred from the standard convention.
- **Redis Service Account UID**: The `redis` user creation task uses `system: true` but does not specify a UID; the system-assigned UID is unknown.
- **PostgreSQL pg_hba.conf**: The pg_hba entry uses `host all all` which allows all databases and users from the permitted subnet — no per-database or per-user granularity is configured.
- **Firewall Default State**: The firewalld tasks only explicitly ENABLE rules; no default-deny firewall policy is defined in the Ansible configuration (the default-deny is assumed at the policy level).
- **Credential Management**: No credential management tasks (e.g., password hashing, key distribution) were found in the scanned files.
- **SELinux**: No SELinux configuration tasks were found in the role files.
- **Obligations**: Session logging is attached to the SSH permit rule (rule-001) as a SOC2 compliance obligation, not as a standalone rule.

## 5. Security Posture Assessment

**Strengths**:
- Explicit service account privilege separation (www-data, postgres, redis with nologin shells)
- Network segmentation enforced via firewalld and pg_hba
- Filesystem permissions restrict access to service-specific directories
- SSH restricted to sudo group only
- Default-deny policy in place

**Risks**:
- Redis 7.0.11 has multiple critical/remote vulnerabilities including a KEV-listed CVE
- nginx 1.20.0 has resolver and njs module vulnerabilities
- PostgreSQL pg_hba allows all databases from web subnet (no per-database restriction)
- No explicit firewall default-deny rule found in Ansible tasks
