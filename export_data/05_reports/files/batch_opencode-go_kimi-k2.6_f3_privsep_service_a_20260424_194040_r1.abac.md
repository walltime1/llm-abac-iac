# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 20:18:44_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 13 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f3_privsep_service_accounts`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "type": "list",
      "items": [
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
          "source": "roles/web/tasks/main.yml"
        },
        {
          "name": "postgres",
          "uid": null,
          "groups": [
            "postgres"
          ],
          "department": null,
          "clearance": null,
          "source": "roles/db/tasks/main.yml"
        },
        {
          "name": "redis",
          "uid": null,
          "groups": [
            "redis"
          ],
          "department": null,
          "clearance": null,
          "source": "roles/cache/tasks/main.yml"
        }
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "enum",
      "domain": [
        "sudo",
        "developers",
        "www-data",
        "postgres",
        "redis"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "type": "enum",
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "type": "free_form",
      "source": "group_vars/all.yml"
    },
    "applies_to": {
      "type": "sentinel",
      "domain": [
        "all"
      ],
      "source": "policy"
    }
  },
  "resources": {
    "hosts": {
      "type": "list",
      "items": [
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
      "source": "inventory.ini"
    },
    "services": {
      "type": "list",
      "items": [
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
      "source": "group_vars/all.yml"
    },
    "paths": {
      "type": "list",
      "items": [
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
        },
        {
          "path": "/etc/sudoers.d/www-data",
          "owner": null,
          "group": null,
          "mode": null,
          "service": null,
          "source": "roles/web/tasks/main.yml"
        },
        {
          "path": "/etc/nginx/nginx.conf",
          "owner": null,
          "group": null,
          "mode": null,
          "service": "nginx",
          "source": "roles/web/tasks/main.yml"
        },
        {
          "path": "/etc/postgresql/pg_hba.conf",
          "owner": null,
          "group": null,
          "mode": null,
          "service": "postgresql",
          "source": "roles/db/tasks/main.yml"
        },
        {
          "path": "/etc/redis/redis.conf",
          "owner": null,
          "group": null,
          "mode": null,
          "service": "redis",
          "source": "roles/cache/tasks/main.yml"
        }
      ],
      "source": "group_vars/all.yml"
    },
    "networks": {
      "type": "list",
      "items": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "webservers",
          "label": "webservers subnet",
          "source": "group_vars/dbservers.yml"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "internal",
          "label": "internal subnet",
          "source": "inventory.ini"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "internet",
          "label": "internet",
          "source": "group_vars/webservers.yml"
        }
      ],
      "source": "group_vars/all.yml"
    },
    "applies_to": {
      "type": "sentinel",
      "domain": [
        "all"
      ],
      "source": "policy"
    }
  },
  "environment": {
    "org": {
      "value": "privsep-corp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "domain": [
        "soc2"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "value": 90,
      "source": "group_vars/all.yml"
    },
    "applies_to": {
      "type": "sentinel",
      "domain": [
        "all"
      ],
      "source": "policy"
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
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
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
    "id": "rule-006",
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
    "id": "rule-010",
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
    "id": "rule-011",
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
    "id": "rule-012",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
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
    "id": "rule-013",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "redis"
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
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": "20-26"
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
      "file": "policy",
      "task": "default-deny",
      "lines": "0-0"
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
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Update nginx to 1.21.0 or later, or apply the vendor patch for the resolver vulnerability."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Update nginx to a patched version (1.25.3+ / 1.24.0+) or disable HTTP/2 if not required."
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "pinned_version": "7.0.11",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Update Redis to 8.2.2 or later, or restrict EVAL/EVALSHA commands via ACL rules."
  },
  {
    "cve_id": "CVE-2023-48795",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "medium",
    "cvss_score": 5.9,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned OpenSSH 9.6p1 already includes the Terrapin fix. Verify client compatibility."
  }
]
```

## Report

# ABAC Policy Mining Report — privsep-corp Ansible Configuration

## Scope
Mined the `all` slice from the Ansible repository rooted at `RLM_ANSIBLE_DIR`.

## Attribute Catalog
- **Subjects**: 5 users (admin, developer, www-data, postgres, redis), 5 groups, 2 clearance levels, 2 departments.
- **Resources**: 3 hosts, 4 services (nginx, postgresql, redis, ssh), 6 paths, 3 networks.
- **Environment**: production environment, SOC2 compliance tier, 90-day log retention.

## Rules Extracted
14 rules total:
- **Filesystem**: 3 permit rules for `/var/www/html` (www-data) and 3 permit rules for `/var/lib/postgresql/data` (postgres).
- **SSH**: 1 permit rule restricting login to the `sudo` group.
- **Sudoers**: 1 explicit deny rule preventing `www-data` from obtaining sudo access.
- **Network**: 3 permit rules for nginx (443), postgresql (5432), and redis (6379).
- **Implicit Deny**: 2 deny rules for postgresql and redis network connections from unauthorized sources.
- **Default Deny**: 1 catch-all deny rule.

## Vulnerabilities
Three CVEs affect pinned package versions:
- **CVE-2021-23017** (nginx 1.20.0) — High severity DNS resolver 1-byte overwrite.
- **CVE-2023-44487** (nginx 1.20.0) — High severity HTTP/2 Rapid Reset DoS (KEV).
- **CVE-2025-49844** (redis 7.0.11) — Critical severity use-after-free via Lua (KEV).

OpenSSH 9.6p1 is **not** affected by CVE-2023-48795 (Terrapin attack).

## Ambiguities and Notes
- PostgreSQL `pg_hba.conf` uses `all all` wildcards; no per-user or per-database granularity was configured in Ansible.
- Redis binds to `10.0.2.20` while firewall rules reference `10.0.1.0/24`; the effective client network may differ from the bind interface.
- No `sudoers` entries were defined for human users (admin/developer); only SSH `AllowGroups` restricts interactive access.
- Service users (www-data, postgres, redis) lack clearance and department metadata in the configuration.
- No session logging, audit obligations, or credential-management rules were found in the role tasks.
