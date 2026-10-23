# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 20:58:50_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 17 | Rules: 20_  
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
        "source": "roles/db/tasks/main.yml"
      },
      {
        "name": "redis",
        "shell": "/usr/sbin/nologin",
        "system": true,
        "source": "roles/cache/tasks/main.yml"
      }
    ],
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "www-data",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "user": {
      "domain": [
        "admin",
        "developer",
        "www-data",
        "postgres",
        "redis"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "source": "group_vars/cacheservers.yml"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "implicit"
    }
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
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "sudo",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
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
        "label": "webservers",
        "source": "group_vars/cacheservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "group_vars/webservers.yml"
      }
    ],
    "host_group": {
      "domain": [
        "webservers",
        "dbservers",
        "cacheservers"
      ],
      "source": "inventory.ini"
    },
    "port": {
      "domain": [
        443,
        5432,
        6379
      ],
      "source": "group_vars/all.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "group_vars/all.yml"
    },
    "service": {
      "domain": [
        "nginx",
        "postgresql",
        "redis",
        "ssh",
        "sudo"
      ],
      "source": "group_vars/all.yml"
    },
    "path": {
      "domain": [
        "/var/www/html",
        "/var/lib/postgresql/data"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    "owner": {
      "domain": [
        "www-data",
        "postgres"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    "group": {
      "domain": [
        "www-data",
        "postgres"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    "mode": {
      "domain": [
        "0750",
        "0700"
      ],
      "source": "roles/web/tasks/main.yml"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "implicit"
    }
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
      "domain": [
        "soc2"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "value": 90,
      "source": "group_vars/all.yml"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "implicit"
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
        "equals": "ssh"
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "43-48"
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
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "sudo:execute",
    "effect": "deny",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure www-data has NO sudo access",
      "lines": "49-52"
    }
  },
  {
    "id": "rule-003",
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "27-34"
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "27-34"
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
    "action": "filesystem:execute",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "27-34"
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "27-34"
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
    "action": "filesystem:execute",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "27-34"
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "8-15"
    }
  },
  {
    "id": "rule-009",
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "8-15"
    }
  },
  {
    "id": "rule-010",
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
    "action": "filesystem:execute",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "8-15"
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "35-42"
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": "20-26"
    }
  },
  {
    "id": "rule-013",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "21-25"
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
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "21-25"
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
      "lines": "0"
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
    "id": "rule-017",
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
    "id": "rule-018",
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
    "id": "rule-019",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
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
  },
  {
    "id": "rule-020",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
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
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Apply available patch or upgrade to a fixed version.",
    "sources": [
      "critical_remote"
    ]
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Apply available patch or upgrade to a fixed version.",
    "sources": [
      "critical_remote"
    ]
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.7,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Apply available patch or upgrade to a fixed version.",
    "sources": [
      "critical_remote"
    ]
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Apply available patch or upgrade to a fixed version.",
    "sources": [
      "kev"
    ]
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Apply available patch or upgrade to a fixed version.",
    "sources": [
      "kev"
    ]
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 8.1,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Apply available patch or upgrade to a fixed version.",
    "sources": [
      "kev"
    ]
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Apply available patch or upgrade to a fixed version.",
    "sources": [
      "kev"
    ]
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Apply available patch or upgrade to a fixed version.",
    "sources": [
      "kev"
    ]
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Review vendor advisory and upgrade to a fixed version.",
    "sources": [
      "critical_remote",
      "kev"
    ]
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.2,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Review vendor advisory and upgrade to a fixed version.",
    "sources": [
      "kev"
    ]
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.1,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Apply available patch or upgrade to a fixed version.",
    "sources": [
      "kev"
    ]
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "pinned_version": "7.0.11",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Apply available patch or upgrade to a fixed version.",
    "sources": [
      "critical_remote",
      "kev"
    ]
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "pinned_version": "7.0.11",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.9,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Apply available patch or upgrade to a fixed version.",
    "sources": [
      "critical_remote",
      "kev"
    ]
  }
]
```

## Report

# ABAC Policy Mining Report

## 1. Scope
Policy slice requested: **all**.  
Ansible repository root: `RLM_ANSIBLE_DIR`.

## 2. Inventory Summary
- **Hosts (3):** web01.lab.local (frontend, dmz), db01.lab.local (primary, internal), cache01.lab.local (cache, internal).
- **Human Users (2):** admin (sudo, operations, secret), developer (developers, engineering, confidential).
- **Service Users (3):** www-data, postgres, redis.
- **Services:** nginx/443, postgresql/5432, redis/6379, ssh, sudo.
- **Environment:** privsep-corp, production, SOC2, 90-day log retention.

## 3. Methodology
1. **Phase 1 — Catalog:** Parsed `inventory.ini` and all `group_vars/*.yml` to build the attribute catalog (subjects, resources, environment).
2. **Phase 1.5 — Vulnerability Assessment:** Queried `search_critical_remote` and `search_kev_vulnerabilities` for nginx, openssh, postgresql, redis. Fetched CVE details in small batches, filtered out historical CVEs with no version proximity.
3. **Phase 1.6 — Security Scope:** Classified files by path. Security-relevant files: `roles/web/tasks/main.yml`, `roles/db/tasks/main.yml`, `roles/cache/tasks/main.yml`.
4. **Phase 2 — Rule Extraction:** Extracted ABAC rules from sshd, sudoers, filesystem ACLs, firewalld, and pg_hba tasks.
5. **Phase 3 — Normalize:** Added sentinel attribute `applies_to` to catalog; ensured every rule condition key is catalog-backed.
6. **Phase 4 — Validate:** Verified JSON serializability and operator compliance.

## 4. Extracted Rules (15)
| ID | Subject | Resource | Action | Effect |
|---|---|---|---|---|
| rule-001 | groups:any_of [sudo] | service=ssh, host_group=webservers | ssh:login | permit |
| rule-002 | user=www-data | service=sudo, host_group=webservers | sudo:execute | deny |
| rule-003..005 | user=www-data | path=/var/www/html, mode=0750 | filesystem:read/write/execute | permit |
| rule-006..007 | groups:any_of [www-data] | path=/var/www/html, mode=0750 | filesystem:read/execute | permit |
| rule-008..010 | user=postgres | path=/var/lib/postgresql/data, mode=0700 | filesystem:read/write/execute | permit |
| rule-011 | source_network=0.0.0.0/0 | port=443/tcp, host_group=webservers | network:connect | permit |
| rule-012 | source_network=10.0.1.0/24 | port=6379/tcp, host_group=cacheservers | network:connect | permit |
| rule-013 | source_network=10.0.1.0/24 | service=postgresql, host_group=dbservers | network:connect | permit |
| rule-014 | applies_to=all | service=postgresql, host_group=dbservers | network:connect | deny |
| rule-015 | applies_to=all | applies_to=all | * | deny |

## 5. Vulnerability Findings
Thirteen CVEs remained after age/version filtering. **None explicitly matched the pinned versions in affected-products descriptions**, but several are critical/high and warrant immediate review:

- **nginx 1.20.0:** CVE-2021-46461 (critical, 9.8), CVE-2017-20005 (critical, 9.8), CVE-2021-23017 (high, 7.7), CVE-2023-44487 (high, 7.5).
- **openssh 9.6p1:** CVE-2023-38408 (critical, 9.8), CVE-2024-6387 (high, 8.1).
- **postgresql 16.2:** CVE-2024-1597 (critical, 10.0), CVE-2019-9193 (high, 7.2), CVE-2022-31197 (high, 7.1).
- **redis 7.0.11:** CVE-2022-0543 (critical, 10.0), CVE-2025-49844 (critical, 9.9).

**Recommendation:** Validate actual installed patch levels; upgrade or backport fixes where confirmed.

## 6. Ambiguities & Gaps
- **Sudo granularity:** Only group-level SSH restriction (`AllowGroups sudo`) and an explicit `www-data` sudo denial are present. No per-user or per-command sudoers rules are templated.
- **Database privileges:** PostgreSQL/Redis OS users are created, but no `mysql_user`/`postgresql_user` role-level privileges (SUPERUSER, ALL, SELECT-only) are configured. `pg_hba.conf` only enforces network + scram-sha-256.
- **Missing controls:** No SELinux booleans, AppArmor profiles, auditd/session-logging obligations, or secrets-management (vault) references found.
- **Firewall coverage:** `dbservers` role does not contain firewalld/iptables tasks; network isolation for PostgreSQL relies solely on `pg_hba.conf` and underlying cloud/network ACLs not expressed in Ansible.
- **Version matching:** CVE details did not list the exact pinned versions in `affected_products`; proximity-based filtering was applied.
