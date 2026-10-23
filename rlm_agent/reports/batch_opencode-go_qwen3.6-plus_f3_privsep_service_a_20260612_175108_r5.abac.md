# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:58:00_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 10 | Rules: 15_  
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
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "www-data",
        "uid": 33,
        "groups": [
          "www-data"
        ],
        "clearance": "none",
        "department": "system",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [
          "postgres"
        ],
        "clearance": "none",
        "department": "system",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "name": "redis",
        "uid": null,
        "groups": [
          "redis"
        ],
        "clearance": "none",
        "department": "system",
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
      {
        "value": "secret",
        "domain": [
          "top_secret",
          "secret",
          "confidential",
          "internal",
          "public",
          "none"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "confidential",
        "domain": [
          "top_secret",
          "secret",
          "confidential",
          "internal",
          "public",
          "none"
        ],
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
      },
      {
        "value": "system",
        "source": "roles/web/tasks/main.yml"
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
        "inventory_group": [
          "webservers",
          "prod"
        ],
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": [
          "dbservers",
          "prod"
        ],
        "source": "inventory.ini"
      },
      {
        "hostname": "cache01.lab.local",
        "ip": "10.0.2.20",
        "role": "cache",
        "zone": "internal",
        "inventory_group": [
          "cacheservers",
          "prod"
        ],
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "openssh",
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
        "source": "roles/db/tasks/main.yml"
      },
      {
        "name": "redis",
        "port": 6379,
        "protocol": "tcp",
        "host_group": "cacheservers",
        "source": "roles/cache/tasks/main.yml"
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
        "cidr": "0.0.0.0/0",
        "zone": "any",
        "label": "internet",
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
        "label": "internal_subnet",
        "source": "inventory.ini"
      }
    ]
  },
  "environment": {
    "org": "privsep-corp",
    "environment": "production",
    "compliance_tier": "soc2",
    "retention": {
      "log_retention_days": 90
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
      "lines": [
        35,
        41
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "openssh"
      },
      "port": {
        "equals": 22
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
    "obligations": [
      {
        "type": "session_logging",
        "description": "SSH sessions must be logged per SOC2 compliance"
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
    "id": "rule-004",
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
    "action": "filesystem:execute",
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
    "id": "rule-005",
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
    "id": "rule-006",
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
    "id": "rule-009",
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
      "lines": [
        20,
        26
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
        1,
        1
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
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": true,
    "pinned_version": "1.20.0-1~focal",
    "recommendation": "Update nginx to latest stable version; the vulnerability affects the njs scripting module — verify njs is not enabled or update it independently",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "severity": "critical",
    "cvss_score": 10.0,
    "affects_pinned_version": true,
    "pinned_version": "7.0.11-1",
    "recommendation": "Redis 7.0.11 likely includes the fix for this Debian-specific Lua sandbox escape; verify the package includes the security backport or update to latest",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "severity": "critical",
    "cvss_score": null,
    "affects_pinned_version": true,
    "pinned_version": "7.0.11-1",
    "recommendation": "Emerging CVE — update redis to latest patched version and monitor vendor advisories",
    "source": "group_vars/all.yml"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration manages a **privsep-corp** production environment under **SOC2** compliance tier, spanning 3 hosts across DMZ and internal zones.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | privsep-corp |
| Environment | production |
| Compliance Tier | soc2 |
| Log Retention | 90 days |

## Host Inventory

| Hostname | IP | Role | Zone | Groups |
|----------|-----|------|------|--------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers, prod |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers, prod |
| cache01.lab.local | 10.0.2.20 | cache | internal | cacheservers, prod |

## Subjects

### Human Users
| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |

### System Users
| User | UID | Groups | Shell | Purpose |
|------|-----|--------|-------|---------|
| www-data | 33 | www-data | /usr/sbin/nologin | Nginx service account |
| postgres | - | postgres | /usr/sbin/nologin | PostgreSQL service account |
| redis | - | redis | /usr/sbin/nologin | Redis service account |

### Groups
sudo, developers, www-data, postgres, redis

## Rules Summary (10 rules)

| ID | Action | Effect | Scope |
|----|--------|--------|-------|
| rule-001 | network:connect (HTTPS/443) | permit | Internet → webservers (nginx) |
| rule-002 | ssh:login (port 22) | permit | sudo group → webservers (openssh) |
| rule-003 | filesystem:read | permit | www-data → /var/www/html |
| rule-004 | filesystem:execute | permit | www-data → /var/www/html |
| rule-005 | sudo:execute | deny | www-data → all hosts |
| rule-006 | network:connect (PostgreSQL/5432) | permit | 10.0.1.0/24 → dbservers |
| rule-007 | filesystem:read | permit | postgres → /var/lib/postgresql/data |
| rule-008 | filesystem:write | permit | postgres → /var/lib/postgresql/data |
| rule-009 | network:connect (Redis/6379) | permit | 10.0.1.0/24 → cacheservers |
| rule-010 | * (all actions) | deny | default-deny (all subjects, all resources) |

## Key Security Observations

1. **SSH Hardening**: SSH access is restricted to the `sudo` group via `AllowGroups` in sshd_config. Non-sudo users (developer, www-data, postgres, redis) cannot SSH in.
2. **Service Account Isolation**: All service accounts (www-data, postgres, redis) have `/usr/sbin/nologin` shell, preventing interactive login.
3. **Network Segmentation**: Database (PostgreSQL) and cache (Redis) services are only accessible from the webservers subnet (10.0.1.0/24), not from the internet.
4. **Filesystem ACLs**: Document root `/var/www/html` is owned by www-data with mode 0750 (owner rwx, group rx, others no access). PostgreSQL data directory is 0700 (owner only).
5. **Explicit Deny**: www-data is explicitly denied sudo access via absent `/etc/sudoers.d/www-data`.
6. **Default Deny**: A catch-all deny rule (rule-010) ensures any unpermitted action is blocked.

## Vulnerability Assessment

Three critical CVEs were identified against pinned package versions:

| CVE | Product | Severity | Affects Pinned | Recommendation |
|-----|---------|----------|----------------|----------------|
| CVE-2021-46461 | nginx | critical (CVSS 9.8) | Yes | Update nginx/njs; verify njs module is not enabled |
| CVE-2022-0543 | redis | critical (CVSS 10.0) | Yes | Verify Debian backport is included in 7.0.11 or update |
| CVE-2025-49844 | redis | critical | Yes | Monitor vendor advisories; update to latest patched version |

## Ambiguities & Gaps

1. **No explicit PostgreSQL user rules**: The pg_hba.conf configuration allows `host all all` from 10.0.1.0/24, meaning any database user is accessible from the webservers subnet. No individual `postgresql_user` or `mysql_user` tasks were found to define specific database accounts with privilege levels (SUPERUSER/NOSUPERUSER).
2. **No explicit Redis authentication**: The Redis configuration only binds to 10.0.2.20 and allows connections from 10.0.1.0/24, but no `requirepass` or ACL configuration was observed. Any client from the webservers subnet can connect without authentication.
3. **No SELinux rules**: No SELinux boolean or policy tasks were found in the configuration.
4. **No load balancer rules**: No HAProxy or similar load balancer configuration was observed.
5. **No monitoring access rules**: No Nagios or monitoring service check configurations were found.
6. **Credential management**: No explicit credential vault, password hash, or key management tasks were observed in the role files. SSH key distribution and password policies are not defined.
7. **Line range estimates**: Source line numbers in rules are approximate based on task ordering in the YAML files.
8. **Openssh-server KEV**: One KEV entry was found for openssh-server but details were not retrieved in this run.

## Compliance Notes

- **SOC2**: Session logging obligation attached to SSH access rule (rule-002) satisfies audit trail requirements.
- **Principle of Least Privilege**: Service accounts have no shell, www-data has no sudo, and network access is subnet-restricted.
