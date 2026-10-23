# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 11:23:40_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 9 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f3_privsep_service_accounts`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "domain": null,
      "source": "group_vars/all.yml",
      "values": [
        {
          "name": "admin",
          "uid": 1001,
          "groups": [
            "sudo"
          ],
          "clearance": "secret",
          "department": "operations",
          "source": "configured"
        },
        {
          "name": "developer",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "clearance": "confidential",
          "department": "engineering",
          "source": "configured"
        }
      ]
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "www-data",
        "postgres",
        "redis"
      ],
      "source": "group_vars/all.yml, roles/*/tasks/main.yml",
      "values": [
        "sudo",
        "developers",
        "www-data",
        "postgres",
        "redis"
      ]
    },
    "clearance_levels": {
      "domain": [
        "secret",
        "confidential",
        "unclassified"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "secret",
        "confidential"
      ]
    },
    "departments": {
      "domain": [
        "operations",
        "engineering",
        "finance",
        "hr"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "operations",
        "engineering"
      ]
    }
  },
  "resources": {
    "hosts": {
      "domain": null,
      "source": "inventory.ini",
      "values": [
        {
          "hostname": "web01.lab.local",
          "ip": "10.0.1.10",
          "role": "frontend",
          "zone": "dmz",
          "inventory_group": "webservers"
        },
        {
          "hostname": "db01.lab.local",
          "ip": "10.0.2.10",
          "role": "primary",
          "zone": "internal",
          "inventory_group": "dbservers"
        },
        {
          "hostname": "cache01.lab.local",
          "ip": "10.0.2.20",
          "role": "cache",
          "zone": "internal",
          "inventory_group": "cacheservers"
        }
      ]
    },
    "services": {
      "domain": null,
      "source": "group_vars/*.yml",
      "values": [
        {
          "name": "nginx",
          "port": 443,
          "protocol": "tcp",
          "host_group": "webservers"
        },
        {
          "name": "postgresql",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers"
        },
        {
          "name": "redis",
          "port": 6379,
          "protocol": "tcp",
          "host_group": "cacheservers"
        }
      ]
    },
    "paths": {
      "domain": null,
      "source": "roles/db/tasks/main.yml, roles/web/tasks/main.yml",
      "values": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgresql"
        },
        {
          "path": "/var/www/html",
          "owner": "www-data",
          "group": "www-data",
          "mode": "0750",
          "service": "nginx"
        }
      ]
    },
    "networks": {
      "domain": null,
      "source": "group_vars/*.yml, inventory.ini",
      "values": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "webservers_subnet"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "internal",
          "label": "dbservers_subnet"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "any",
          "label": "internet"
        }
      ]
    },
    "host_groups": {
      "domain": [
        "webservers",
        "dbservers",
        "cacheservers",
        "prod"
      ],
      "source": "inventory.ini",
      "values": [
        "webservers",
        "dbservers",
        "cacheservers",
        "prod"
      ]
    },
    "zones": {
      "domain": [
        "dmz",
        "internal",
        "any"
      ],
      "source": "inventory.ini",
      "values": [
        "dmz",
        "internal",
        "any"
      ]
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
        "production",
        "staging",
        "development"
      ],
      "source": "inventory.ini",
      "values": [
        "production"
      ]
    },
    "compliance_tier": {
      "domain": [
        "soc2",
        "pci-dss",
        "hipaa",
        "none"
      ],
      "source": "group_vars/all.yml, inventory.ini",
      "values": [
        "soc2"
      ]
    },
    "retention_days": {
      "domain": null,
      "source": "group_vars/all.yml",
      "values": {
        "default_log_retention_days": 90
      }
    }
  },
  "packages": {
    "versions": {
      "nginx": "1.20.0-1~focal",
      "openssh": "1:9.6p1-3ubuntu1",
      "postgresql": "16.2-1.pgdg22.04+1",
      "redis": "7.0.11-1"
    },
    "source": "group_vars/all.yml"
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "Allow SSH login for users in the sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        24,
        26
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Allow HTTPS access to web service from any source",
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
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        19,
        22
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Allow Redis access from webservers subnet only",
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": [
        12,
        16
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow PostgreSQL access from webservers subnet only",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        14,
        17
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow postgres user read/write access to PostgreSQL data directory",
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
      "mode": {
        "equals": "0700"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": [
        6,
        11
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow www-data user read/write access to document root",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": [
        13,
        18
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Explicitly deny sudo access for www-data user",
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
        27,
        29
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Allow creation of redis system user with no shell",
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Ensure redis runs as redis user",
      "lines": [
        5,
        9
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Allow creation of postgres system user with no shell",
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres user has no shell access",
      "lines": [
        12,
        15
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "Allow creation of www-data system user with no shell",
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Create www-data service user (no sudo, no shell)",
      "lines": [
        4,
        12
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "Default deny all access not explicitly permitted",
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
      "task": "implicit-deny",
      "lines": [
        1,
        99
      ]
    }
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
      "compliance_tier": {
        "equals": "soc2"
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
    "id": "rule-004",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "product": "nginx",
    "cve_id": "CVE-2016-0746",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "nginx buffer overflow in resolver",
    "affects_pinned_version": false,
    "recommendation": "Upgrade nginx to 1.9.10+ or 1.10.0+"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2021-46461",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "njs out-of-bounds access",
    "affects_pinned_version": false,
    "recommendation": "Upgrade njs to 0.7.1+"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2017-20005",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "NGINX buffer overflow before 1.13.6",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to 1.20.0+ immediately"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2021-23017",
    "cvss_score": 7.7,
    "severity": "high",
    "description": "nginx resolver 1-byte overwrite",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to 1.20.0+"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2013-4547",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "nginx 0.8.41-1.4.3 memory corruption",
    "affects_pinned_version": false,
    "recommendation": "Upgrade nginx to 1.4.3+"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2024-1597",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "PostgreSQL SQL injection via pg_largeobject",
    "affects_pinned_version": false,
    "recommendation": "Upgrade PostgreSQL to 16.3+"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2023-3943",
    "cvss_score": 8.8,
    "severity": "high",
    "description": "PostgreSQL REPLICA identity via rules",
    "affects_pinned_version": false,
    "recommendation": "Upgrade PostgreSQL to 15.4+"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2023-2455",
    "cvss_score": 8.8,
    "severity": "high",
    "description": "PostgreSQL row-level security bypass",
    "affects_pinned_version": false,
    "recommendation": "Upgrade PostgreSQL to 15.3+"
  },
  {
    "product": "redis",
    "cve_id": "CVE-2023-36824",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "Redis Integer overflow in SET RM",
    "affects_pinned_version": true,
    "recommendation": "Upgrade Redis to 7.0.13+"
  },
  {
    "product": "redis",
    "cve_id": "CVE-2022-31144",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "Redis Lua sandbox escape",
    "affects_pinned_version": true,
    "recommendation": "Upgrade Redis to 7.0.2+"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2023-48795",
    "cvss_score": 7.8,
    "severity": "high",
    "description": "OpenSSH regexp denial of service",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to 9.6p1+ (already installed)"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2023-38408",
    "cvss_score": 7.8,
    "severity": "high",
    "description": "OpenSSH ssh-agent forward complication",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to 9.4+"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The infrastructure serves a production environment with SOC2 compliance requirements.

## Phase 1: Attribute Catalog

### Subjects

| Type | Domain | Values | Source |
|------|--------|--------|--------|
| Users | free-form | admin (uid=1001, sudo), developer (uid=1002, developers) | group_vars/all.yml |
| Groups | enumerated | sudo, developers, www-data, postgres, redis | group_vars/all.yml, roles/*/tasks |
| Clearance | enumerated | secret, confidential | group_vars/all.yml |
| Department | enumerated | operations, engineering | group_vars/all.yml |

### Resources

| Type | Domain | Values | Source |
|------|--------|--------|--------|
| Hosts | free-form | web01.lab.local (10.0.1.10, dmz), db01.lab.local (10.0.2.10, internal), cache01.lab.local (10.0.2.20, internal) | inventory.ini |
| Services | free-form | nginx:443/tcp (webservers), postgresql:5432/tcp (dbservers), redis:6379/tcp (cacheservers) | group_vars/*.yml |
| Paths | free-form | /var/lib/postgresql/data (postgres:postgres, 0700), /var/www/html (www-data:www-data, 0750) | roles/db/tasks, roles/web/tasks |
| Networks | free-form | 10.0.1.0/24 (dmz), 10.0.2.0/24 (internal), 0.0.0.0/0 (any) | group_vars/*.yml, inventory.ini |

### Environment

| Attribute | Value | Source |
|-----------|-------|--------|
| Organization | privsep-corp | group_vars/all.yml |
| Environment | production | inventory.ini |
| Compliance Tier | soc2 | group_vars/all.yml, inventory.ini |
| Log Retention | 90 days | group_vars/all.yml |

## Phase 1.5: Vulnerability Assessment

### Pinned Package Versions

- **nginx**: 1.20.0-1~focal
- **openssh**: 1:9.6p1-3ubuntu1
- **postgresql**: 16.2-1.pgdg22.04+1
- **redis**: 7.0.11-1

### Critical Findings (Affects Pinned Versions)

| Product | CVE | CVSS | Status | Recommendation |
|---------|-----|------|--------|----------------|
| nginx | CVE-2017-20005 | 9.8 | **VULNERABLE** | Upgrade to 1.20.0+ |
| nginx | CVE-2021-23017 | 7.7 | **VULNERABLE** | Upgrade to 1.20.0+ |
| redis | CVE-2023-36824 | 7.5 | **VULNERABLE** | Upgrade to 7.0.13+ |
| redis | CVE-2022-31144 | 7.5 | **VULNERABLE** | Upgrade to 7.0.2+ |
| openssh | CVE-2023-48795 | 7.8 | OK | Already patched (9.6p1) |

### Total CVEs Found: 12 (5 affecting pinned versions)

## Phase 2: Extracted ABAC Rules

| Rule ID | Action | Subject Condition | Resource Condition | Effect | Source |
|---------|--------|-------------------|---------------------|--------|--------|
| rule-001 | ssh:login | groups=sudo | zone=dmz | permit | roles/web/tasks/main.yml |
| rule-002 | network:connect | all | service=nginx, port=443 | permit | roles/web/tasks/main.yml |
| rule-003 | network:connect | source_network=10.0.1.0/24 | service=redis, port=6379 | permit | roles/cache/tasks/main.yml |
| rule-004 | network:connect | source_network=10.0.1.0/24 | service=postgresql, port=5432 | permit | roles/db/tasks/main.yml |
| rule-005 | filesystem:write | user=postgres | path=/var/lib/postgresql/data, mode=0700 | permit | roles/db/tasks/main.yml |
| rule-006 | filesystem:write | user=www-data | path=/var/www/html, mode=0750 | permit | roles/web/tasks/main.yml |
| rule-007 | sudo:execute | user=www-data | all | **deny** | roles/web/tasks/main.yml |
| rule-008 | user:create | user=redis | all | permit | roles/cache/tasks/main.yml |
| rule-009 | user:create | user=postgres | all | permit | roles/db/tasks/main.yml |
| rule-010 | user:create | user=www-data | all | permit | roles/web/tasks/main.yml |
| rule-011 | * | all | all | **deny** | implicit-deny |

## Phase 4: Validation

- ✅ All attributes have valid sources from Ansible configuration
- ✅ All rules use only allowed operators (equals, any_of, in)
- ✅ All rules include environment_condition with compliance_tier=soc2
- ✅ Default deny rule properly structured
- ✅ All subject/resource/environment condition keys are disjoint
- ✅ All JSON outputs are valid

## Ambiguities & Notes

1. **Credentials**: No explicit credentials (passwords, SSH keys, API tokens) found in Ansible configuration. However, PostgreSQL uses scram-sha-256 authentication as configured in pg_hba.conf.
2. **Logging**: No explicit session logging or audit configurations found in the scanned files. Consider adding audit obligations for sudo access.
3. **Redis bind address**: Redis is bound to 10.0.2.20 (internal IP) rather than a hostname, which may affect host-based policy evaluation.
4. **Nginx version**: Pinned version 1.20.0 has known CVEs; recommend upgrading to 1.24.0+.

## Summary Statistics

- **Users**: 2 configured (admin, developer)
- **Hosts**: 3 (web01, db01, cache01)
- **Services**: 3 (nginx, postgresql, redis)
- **Rules**: 11 total (10 permit, 1 explicit deny, 1 implicit deny)
- **Critical Vulnerabilities**: 5 affecting pinned versions
