# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 13:36:28_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 20 | Rules: 18_  
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
        "clearance": null,
        "department": null,
        "source": "roles/web/tasks/main.yml"
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
        "source": "group_vars/webservers.yml"
      },
      {
        "name": "openssh-server",
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
        "source": "group_vars/cacheservers.yml"
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
  },
  "subject_attributes": [
    {
      "name": "user",
      "type": "enum",
      "domain": [
        "admin",
        "developer",
        "www-data",
        "postgres",
        "redis"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "uid",
      "type": "integer",
      "source": "group_vars/all.yml"
    },
    {
      "name": "groups",
      "type": "enum_set",
      "domain": [
        "sudo",
        "developers",
        "www-data",
        "postgres",
        "redis"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "clearance",
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "department",
      "type": "enum",
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "source_ip",
      "type": "cidr",
      "source": "group_vars/webservers.yml"
    },
    {
      "name": "source_network",
      "type": "cidr",
      "source": "group_vars/webservers.yml"
    },
    {
      "name": "source_zone",
      "type": "enum",
      "domain": [
        "dmz",
        "internal",
        "internet"
      ],
      "source": "inventory.ini"
    }
  ],
  "resource_attributes": [
    {
      "name": "hostname",
      "type": "enum",
      "domain": [
        "web01.lab.local",
        "db01.lab.local",
        "cache01.lab.local"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "zone",
      "type": "enum",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "role",
      "type": "enum",
      "domain": [
        "frontend",
        "primary",
        "cache"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "host_group",
      "type": "enum",
      "domain": [
        "webservers",
        "dbservers",
        "cacheservers"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "service",
      "type": "enum",
      "domain": [
        "nginx",
        "openssh-server",
        "postgresql",
        "redis"
      ],
      "source": "group_vars/webservers.yml"
    },
    {
      "name": "port",
      "type": "integer",
      "source": "group_vars/webservers.yml"
    },
    {
      "name": "path",
      "type": "string",
      "source": "roles/web/tasks/main.yml"
    },
    {
      "name": "owner",
      "type": "enum",
      "domain": [
        "www-data",
        "postgres"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    {
      "name": "group",
      "type": "enum",
      "domain": [
        "www-data",
        "postgres"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    {
      "name": "mode",
      "type": "enum",
      "domain": [
        "0750",
        "0700"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    {
      "name": "database",
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    {
      "name": "schema",
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    }
  ],
  "environment_attributes": [
    {
      "name": "environment",
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    {
      "name": "compliance_tier",
      "type": "enum",
      "domain": [
        "soc2"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "org",
      "type": "enum",
      "domain": [
        "privsep-corp"
      ],
      "source": "group_vars/all.yml"
    }
  ]
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
        "equals": "openssh-server"
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
      "lines": "36-39"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-002",
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
      "lines": "29-34"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-003",
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
      "lines": "18-23"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-004",
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
      "host_group": {
        "equals": "dbservers"
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
      "lines": "20-22"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-005",
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
    "action": "db:login",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet (implicit deny-default)",
      "lines": "20-22"
    },
    "obligations": []
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
      "lines": "23-27"
    },
    "obligations": []
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
      "lines": "23-27"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-008",
    "subject_condition": {
      "user": {
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
      "lines": "40-42"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-009",
    "subject_condition": {
      "user": {
        "equals": "postgres"
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
    "action": "ssh:login",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres user has no shell access",
      "lines": "14-16"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-010",
    "subject_condition": {
      "user": {
        "equals": "redis"
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
    "action": "ssh:login",
    "effect": "deny",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Ensure redis runs as redis user (no shell)",
      "lines": "10-13"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-011",
    "subject_condition": {
      "user": {
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
    "action": "ssh:login",
    "effect": "deny",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Create www-data service user (no sudo, no shell)",
      "lines": "10-15"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-012",
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
      "task": "Bind redis to internal interface only + Firewall allow from webservers only (implicit deny-default)",
      "lines": "15-23"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-013",
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
      "lines": "10-13"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-014",
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
      "lines": "10-13"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-015",
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
      "lines": "0-0"
    },
    "obligations": []
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "NGINX memory disclosure vulnerability",
    "affects_pinned_version": false,
    "kev": false,
    "recommendation": "Verify version range; fixed in 1.9.10 — pinned version 1.20.0 is NOT affected"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "NGINX DNS resolver off-by-one error",
    "affects_pinned_version": false,
    "kev": false,
    "recommendation": "Verify version range; typically affects resolver usage — upgrade to latest stable nginx"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "NGINX vulnerability in http_mp4 module",
    "affects_pinned_version": false,
    "kev": false,
    "recommendation": "Verify version range; older issue — monitor for relevance"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "description": "DNS resolver 1-byte overwrite via forged UDP packets",
    "affects_pinned_version": true,
    "kev": false,
    "recommendation": "Upgrade nginx to 1.21.3+ or 1.22.0+; pinned 1.20.0 is vulnerable"
  },
  {
    "cve_id": "CVE-2013-4547",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "description": "NGINX request line parsing vulnerability",
    "affects_pinned_version": false,
    "kev": false,
    "recommendation": "Fixed in older releases — pinned 1.20.0 is NOT affected"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "description": "HTTP/2 Rapid Reset attack (DoS)",
    "affects_pinned_version": true,
    "kev": true,
    "recommendation": "Actively exploited; upgrade nginx and apply HTTP/2 patches — pinned 1.20.0 is vulnerable"
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "medium",
    "cvss_score": 5.8,
    "is_remote": true,
    "description": "TLS renegotiation vulnerability",
    "affects_pinned_version": false,
    "kev": true,
    "recommendation": "Older TLS renegotiation issue — pinned 1.20.0 likely NOT affected"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "description": "PostgreSQL vulnerability",
    "affects_pinned_version": false,
    "kev": false,
    "recommendation": "Very old CVE — pinned 16.2 is NOT affected"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "description": "PostgreSQL vulnerability",
    "affects_pinned_version": false,
    "kev": false,
    "recommendation": "Very old CVE — pinned 16.2 is NOT affected"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "description": "PostgreSQL vulnerability",
    "affects_pinned_version": false,
    "kev": false,
    "recommendation": "Very old CVE — pinned 16.2 is NOT affected"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "description": "PostgreSQL vulnerability",
    "affects_pinned_version": false,
    "kev": false,
    "recommendation": "Very old CVE — pinned 16.2 is NOT affected"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql_jdbc_driver",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "description": "pgjdbc SQL injection vulnerability",
    "affects_pinned_version": false,
    "kev": true,
    "recommendation": "Affects PostgreSQL JDBC driver, NOT the server — pinned postgresql 16.2 is NOT affected"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "high",
    "cvss_score": 7.2,
    "is_remote": true,
    "description": "PostgreSQL COPY PROGRAM privilege escalation",
    "affects_pinned_version": false,
    "kev": true,
    "recommendation": "Fixed in earlier versions — pinned 16.2 is NOT affected"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "description": "PostgreSQL vulnerability",
    "affects_pinned_version": false,
    "kev": true,
    "recommendation": "Verify version range — pinned 16.2 is likely NOT affected"
  },
  {
    "cve_id": "CVE-2015-4335",
    "product": "redis",
    "pinned_version": "7.0.11",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "description": "Redis Lua sandbox escape",
    "affects_pinned_version": false,
    "kev": false,
    "recommendation": "Very old CVE — pinned 7.0.11 is NOT affected"
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "pinned_version": "7.0.11",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "description": "Debian/Ubuntu Redis Lua sandbox escape",
    "affects_pinned_version": false,
    "kev": true,
    "recommendation": "Debian-specific packaging issue — check if using Debian packages; upgrade to patched version if applicable"
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "pinned_version": "7.0.11",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_remote": true,
    "description": "Redis use-after-free in garbage collector via Lua scripts",
    "affects_pinned_version": true,
    "kev": true,
    "recommendation": "Actively exploited; affects Redis <= 8.2.1 — upgrade Redis immediately"
  },
  {
    "cve_id": "CVE-2017-15047",
    "product": "redis",
    "pinned_version": "7.0.11",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Redis vulnerability",
    "affects_pinned_version": false,
    "kev": false,
    "recommendation": "Old CVE — pinned 7.0.11 is NOT affected"
  },
  {
    "cve_id": "CVE-2023-31654",
    "product": "redis",
    "pinned_version": "7.0.11",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Redis vulnerability",
    "affects_pinned_version": false,
    "kev": false,
    "recommendation": "Verify version range — pinned 7.0.11 may NOT be affected"
  }
]
```

## Report

# ABAC Policy Mining Report — privsep-corp Ansible Configuration

## 1. Executive Summary

An ABAC policy was mined from the Ansible configuration for the privsep-corp production environment (SOC 2 compliance). The configuration defines a three-tier architecture — webservers (DMZ), dbservers (internal), cacheservers (internal) — with strictly scoped network access, service account privilege separation, and SSH restrictions.

- **15 ABAC rules** extracted (13 explicit + 1 implicit deny + 1 default-deny)
- **5 user identities**: 2 human (admin, developer) + 3 service (www-data, postgres, redis)
- **19 CVEs** identified; **3 affect pinned versions**, **7 are KEV** (actively exploited)
- Network segmentation: public HTTPS → webservers only; webservers → db/cache on internal network
- Service accounts denied SSH and sudo by explicit configuration

## 2. Attribute Catalog

### 2.1 Subject Attributes

| Attribute | Type | Domain |
|-----------|------|--------|
| user | enum | admin, developer, www-data, postgres, redis |
| uid | integer | — |
| groups | enum_set | sudo, developers, www-data, postgres, redis |
| clearance | enum | secret, confidential |
| department | enum | operations, engineering |
| source_ip | cidr | — |
| source_network | cidr | — |
| source_zone | enum | dmz, internal, internet |

### 2.2 Resource Attributes

| Attribute | Type | Domain |
|-----------|------|--------|
| hostname | enum | web01.lab.local, db01.lab.local, cache01.lab.local |
| zone | enum | dmz, internal |
| role | enum | frontend, primary, cache |
| host_group | enum | webservers, dbservers, cacheservers |
| service | enum | nginx, openssh-server, postgresql, redis |
| port | integer | — |
| path | string | — |
| owner | enum | www-data, postgres |
| group | enum | www-data, postgres |
| mode | enum | 0750, 0700 |
| database | string | — |
| schema | string | — |

### 2.3 Environment Attributes

| Attribute | Type | Domain |
|-----------|------|--------|
| environment | enum | production |
| compliance_tier | enum | soc2 |
| org | enum | privsep-corp |

## 3. Policy Rules

| Rule | Effect | Action | Subject | Resource | Source |
|------|--------|--------|---------|----------|--------|
| rule-001 | permit | ssh:login | groups ∈ {sudo} | openssh-server, webservers | web/tasks/main.yml:36-39 |
| rule-002 | permit | network:connect | source=0.0.0.0/0 | nginx:443, webservers | web/tasks/main.yml:29-34 |
| rule-003 | permit | network:connect | source=10.0.1.0/24 | redis:6379, cacheservers | cache/tasks/main.yml:18-23 |
| rule-004 | permit | db:login | source=10.0.1.0/24 | postgresql:5432, dbservers | db/tasks/main.yml:20-22 |
| rule-005 | deny | db:login | all | postgresql:5432, dbservers | db/tasks/main.yml:20-22 (implicit) |
| rule-006 | permit | filesystem:write | groups ∈ {www-data} | /var/www/html, 0750 | web/tasks/main.yml:23-27 |
| rule-007 | permit | filesystem:read | groups ∈ {www-data} | /var/www/html, 0750 | web/tasks/main.yml:23-27 |
| rule-008 | deny | sudo:execute | user=www-data | all | web/tasks/main.yml:40-42 |
| rule-009 | deny | ssh:login | user=postgres | all | db/tasks/main.yml:14-16 |
| rule-010 | deny | ssh:login | user=redis | all | cache/tasks/main.yml:10-13 |
| rule-011 | deny | ssh:login | user=www-data | all | web/tasks/main.yml:10-15 |
| rule-012 | deny | network:connect | all | redis:6379, cacheservers | cache/tasks/main.yml:15-23 (implicit) |
| rule-013 | permit | filesystem:write | groups ∈ {postgres} | /var/lib/postgresql/data, 0700 | db/tasks/main.yml:10-13 |
| rule-014 | permit | filesystem:read | groups ∈ {postgres} | /var/lib/postgresql/data, 0700 | db/tasks/main.yml:10-13 |
| rule-015 | deny | * | all | all | implicit default-deny |

## 4. Vulnerability Assessment

### 4.1 Critical Findings (Affect Pinned Versions)

| CVE | Product | Pinned | Severity | CVSS | Remote | KEV | Assessment |
|-----|---------|--------|----------|------|--------|-----|------------|
| CVE-2021-23017 | nginx | 1.20.0 | high | 7.7 | Yes | No | AFFECTS — DNS resolver 1-byte overwrite |
| CVE-2023-44487 | nginx | 1.20.0 | high | 7.5 | Yes | Yes | AFFECTS — HTTP/2 Rapid Reset DoS, KEV |
| CVE-2025-49844 | redis | 7.0.11 | critical | 9.9 | Yes | Yes | AFFECTS — use-after-free in Lua GC, KEV |

### 4.2 Recommendations

1. **Immediate**: Upgrade nginx from 1.20.0 to 1.25+ (CVE-2021-23017, CVE-2023-44487)
2. **Immediate**: Upgrade redis from 7.0.11 to 7.4+ (CVE-2025-49844, actively exploited KEV)
3. **Routine**: Monitor postgresql 16.2 and openssh-server 9.6p1 advisories

## 5. Ambiguities and Notes

1. **SSH access scope**: AllowGroups sudo only applied to webservers — unclear if dbservers/cacheservers also restrict SSH.
2. **PostgreSQL auth**: pg_hba grants all databases/users from 10.0.1.0/24 — no granular database RBAC defined.
3. **Redis auth**: No requirepass or ACL — any client on allowed subnet connects without authentication.
4. **Firewall scope**: No explicit firewall rules for dbservers — pg_hba.conf acts as network access control.
5. **Service account shells**: www-data, postgres, redis all use /usr/sbin/nologin (modeled as deny ssh:login).
6. **No monitoring/logging**: No session logging or audit tasks defined in Ansible config.
7. **No sudoers entries beyond removal**: Only sudoers.d/www-data removal — admin sudo relies on OS defaults.
