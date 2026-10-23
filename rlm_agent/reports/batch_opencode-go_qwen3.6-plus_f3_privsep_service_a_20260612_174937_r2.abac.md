# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:00:51_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 17_  
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
        "name": "redis",
        "uid": null,
        "groups": [
          "redis"
        ],
        "clearance": null,
        "department": null,
        "source": "roles/cache/tasks/main.yml"
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
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "www-data",
      "redis",
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
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "internal",
        "label": "dbservers_subnet",
        "source": "inventory.ini"
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
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "openssh-server"
      }
    },
    "environment_condition": {
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
        34,
        37
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
      "host_group": {
        "equals": "webservers"
      },
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
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        28,
        32
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
      "host_group": {
        "equals": "cacheservers"
      },
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
    "effect": "permit",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": [
        17,
        23
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
      "host_group": {
        "equals": "dbservers"
      },
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        17,
        20
      ]
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
        20,
        26
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
        20,
        26
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
        20,
        26
      ]
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": [
        10,
        15
      ]
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
        10,
        15
      ]
    }
  },
  {
    "id": "rule-0010",
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": [
        10,
        15
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
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
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
    "id": "rule-013",
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
      "file": "postprocessor",
      "task": "mode 0700 non-owner deny",
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
      "file": "postprocessor",
      "task": "mode 0700 non-owner deny",
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
      "host_group": {
        "equals": "webservers"
      },
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
    "id": "rule-016",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "cacheservers"
      },
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
  },
  {
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "source": "critical_remote",
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Update to nginx 1.9.10 or later versions."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "source": "critical_remote",
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Update to version 1.13.6 or later."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "source": "critical_remote",
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest versions of affected products that fix the renegotiation handling issue."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "source": "critical_remote",
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Update nginx to the latest version where this issue is fixed."
  }
]
```

## Report

# ABAC Policy Mining Report — privsep-corp

## Executive Summary
This report documents the ABAC policy mined from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`.
The configuration manages a 3-host production environment (`webservers`, `dbservers`, `cacheservers`) under SOC2 compliance.

- **Attributes catalogued**: 5 users, 5 groups, 3 hosts, 4 services, 2 filesystem paths, 3 networks
- **ABAC rules extracted**: 10 permit rules + 1 default-deny rule
- **Vulnerabilities identified**: 4 relevant CVEs (all nginx)

## Attribute Catalog

### Subjects
| User | UID | Groups | Clearance | Department | Source |
|------|-----|--------|-----------|------------|--------|
| admin | 1001 | sudo | secret | operations | group_vars/all.yml |
| developer | 1002 | developers | confidential | engineering | group_vars/all.yml |
| www-data | 33 | www-data | — | — | roles/web/tasks/main.yml |
| redis | — | redis | — | — | roles/cache/tasks/main.yml |
| postgres | — | postgres | — | — | roles/db/tasks/main.yml |

**Enumerated groups**: sudo, developers, www-data, redis, postgres  
**Clearance levels**: secret, confidential  
**Departments**: operations, engineering

### Resources
| Host | IP | Role | Zone | Group |
|------|-----|------|------|-------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |
| cache01.lab.local | 10.0.2.20 | cache | internal | cacheservers |

| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| nginx | 443 | tcp | webservers |
| openssh-server | 22 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |
| redis | 6379 | tcp | cacheservers |

| Path | Owner | Group | Mode | Service |
|------|-------|-------|------|---------|
| /var/lib/postgresql/data | postgres | postgres | 0700 | postgresql |
| /var/www/html | www-data | www-data | 0750 | nginx |

### Environment
- **Org**: privsep-corp
- **Environment**: production
- **Compliance tier**: soc2
- **Log retention**: 90 days

## Extracted ABAC Rules

### rule-001: SSH Login (permit)
- **Subject**: groups intersect [sudo]
- **Resource**: host_group=webservers, service=openssh-server
- **Action**: ssh:login
- **Source**: `roles/web/tasks/main.yml` — "Restrict SSH to sudo group" (L34-37)

### rule-002: HTTPS Inbound (permit)
- **Subject**: source_network = 0.0.0.0/0
- **Resource**: host_group=webservers, port=443
- **Action**: network:connect
- **Source**: `roles/web/tasks/main.yml` — "Firewall — allow HTTPS from internet" (L28-32)

### rule-003: Redis from Webservers (permit)
- **Subject**: source_network = 10.0.1.0/24
- **Resource**: host_group=cacheservers, port=6379
- **Action**: network:connect
- **Source**: `roles/cache/tasks/main.yml` — "Firewall — allow redis from webservers only" (L17-23)

### rule-004: PostgreSQL from Webservers (permit)
- **Subject**: source_network = 10.0.1.0/24
- **Resource**: host_group=dbservers, port=5432
- **Action**: network:connect
- **Source**: `roles/db/tasks/main.yml` — "Allow postgres only from webservers subnet" (L17-20)

### rule-005 to 007: Web Root Filesystem Access (permit)
- **Subject**: groups intersect [www-data]
- **Resource**: path=/var/www/html, owner=www-data, group=www-data, mode=0750
- **Actions**: filesystem:read, filesystem:write, filesystem:execute
- **Source**: `roles/web/tasks/main.yml` — "Enforce document root ACL (www-data only)" (L20-26)

### rule-008 to 010: Postgres Data Filesystem Access (permit)
- **Subject**: groups intersect [postgres]
- **Resource**: path=/var/lib/postgresql/data, owner=postgres, group=postgres, mode=0700
- **Actions**: filesystem:read, filesystem:write, filesystem:execute
- **Source**: `roles/db/tasks/main.yml` — "Ensure postgres runs as postgres user" (L10-15)

### rule-011: Default Deny
- **Subject**: applies_to = all
- **Resource**: applies_to = all
- **Action**: *
- **Effect**: deny

## Vulnerability Assessment

| CVE | Product | Severity | CVSS | Affects Pinned | Source | Recommendation |
|-----|---------|----------|------|----------------|--------|----------------|
| CVE-2016-0746 | nginx | critical | 9.8 | No | critical_remote | Update to nginx 1.9.10 or later |
| CVE-2017-20005 | nginx | critical | 9.8 | No | critical_remote | Upgrade to patched version |
| CVE-2009-3555 | nginx | critical | 9.8 | Yes | critical_remote | Upgrade to latest version |
| CVE-2021-23017 | nginx | high | 7.7 | Yes | critical_remote | Upgrade to latest version |

**Note**: Two CVEs (CVE-2009-3555, CVE-2021-23017) affect the pinned nginx version 1.20.0. Immediate patching recommended. No relevant CVEs were found for openssh-server (9.6), postgresql (16.2), or redis (7.0.11).

## Ambiguities & Observations

1. **pg_hba.conf**: The `lineinfile` task appends a host entry but does not enforce `md5` or `reject` for other sources. The default-deny rule covers this at the policy level, but the actual PostgreSQL configuration may lack explicit DENY entries.
2. **No explicit sudo rules**: The playbook ensures `www-data` has NO sudo access (removes `/etc/sudoers.d/www-data`) but does not define sudo privileges for the `admin` user beyond group membership. Sudo policy is assumed to be managed outside this configuration.
3. **No credentials**: No hardcoded credentials, API keys, or secrets were found in the scanned files.
4. **Redis bind**: Redis is bound to `10.0.2.20` (specific host IP) rather than `0.0.0.0` or a loopback address, which limits exposure but ties the config to a specific host.
5. **Service users**: `www-data`, `redis`, and `postgres` are created as system users with `/usr/sbin/nologin` — no interactive login permitted. This is a security-positive finding but is not represented as an explicit ABAC rule (it is a system constraint).
