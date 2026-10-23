# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 13:57:00_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 14 | Rules: 22_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f3_privsep_service_accounts`_

## Attributes

```json
{
  "subject": {
    "user": {
      "type": "enum",
      "domain": [
        "admin",
        "developer",
        "www-data",
        "postgres",
        "redis"
      ],
      "source": "group_vars/all.yml, roles/web/tasks/main.yml, roles/db/tasks/main.yml, roles/cache/tasks/main.yml"
    },
    "uid": {
      "type": "integer",
      "domain": null,
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "www-data",
        "postgres",
        "redis"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "enum",
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "source_ip": {
      "type": "cidr",
      "domain": null,
      "source": "roles/web/tasks/main.yml, roles/db/tasks/main.yml, roles/cache/tasks/main.yml"
    },
    "source_network": {
      "type": "cidr",
      "domain": null,
      "source": "group_vars/webservers.yml, group_vars/dbservers.yml, group_vars/cacheservers.yml"
    }
  },
  "resource": {
    "hostname": {
      "type": "enum",
      "domain": [
        "web01.lab.local",
        "db01.lab.local",
        "cache01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "domain": null,
      "source": "inventory.ini"
    },
    "role": {
      "type": "enum",
      "domain": [
        "frontend",
        "primary",
        "cache"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "webservers",
        "dbservers",
        "cacheservers"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "openssh-server",
        "postgresql",
        "redis",
        "sudo"
      ],
      "source": "group_vars/all.yml, roles/*/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "domain": null,
      "source": "group_vars/webservers.yml, group_vars/dbservers.yml, group_vars/cacheservers.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp"
      ],
      "source": "group_vars/webservers.yml, group_vars/dbservers.yml, group_vars/cacheservers.yml"
    },
    "path": {
      "type": "enum",
      "domain": [
        "/var/www/html",
        "/var/lib/postgresql/data"
      ],
      "source": "roles/web/tasks/main.yml, roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "enum",
      "domain": [
        "www-data",
        "postgres"
      ],
      "source": "roles/web/tasks/main.yml, roles/db/tasks/main.yml"
    },
    "group": {
      "type": "enum",
      "domain": [
        "www-data",
        "postgres"
      ],
      "source": "roles/web/tasks/main.yml, roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "enum",
      "domain": [
        "0750",
        "0700"
      ],
      "source": "roles/web/tasks/main.yml, roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "enum",
      "domain": [
        "privsep-corp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "enum",
      "domain": [
        "soc2"
      ],
      "source": "group_vars/all.yml, inventory.ini"
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
        "equals": "openssh-server"
      },
      "host_group": {
        "equals": "webservers"
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
      "lines": "30-32"
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
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "webservers"
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
      "lines": "24-28"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "18-22"
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
      "lines": "18-22"
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
      "lines": "18-22"
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "18-22"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "user": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sudo"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "sudo:execute",
    "effect": "deny",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure www-data has NO sudo access",
      "lines": "34-36"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "user": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
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
    "effect": "deny",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Create www-data service user (no sudo, no shell)",
      "lines": "9-13"
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
      "lines": "6-11"
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
      "lines": "6-11"
    }
  },
  {
    "id": "rule-011",
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
      "lines": "6-11"
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "user": {
        "equals": "postgres"
      }
    },
    "resource_condition": {
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
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres user has no shell access",
      "lines": "13-14"
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
      "port": {
        "equals": 5432
      },
      "host_group": {
        "equals": "dbservers"
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
      "lines": "16-18"
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet (implicit deny-default)",
      "lines": "16-18"
    }
  },
  {
    "id": "rule-015",
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
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "cacheservers"
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
      "lines": "14-18"
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
      "service": {
        "equals": "redis"
      },
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only (implicit deny-default)",
      "lines": "14-18"
    }
  },
  {
    "id": "rule-017",
    "subject_condition": {
      "user": {
        "equals": "redis"
      }
    },
    "resource_condition": {
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
    "effect": "deny",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Ensure redis runs as redis user",
      "lines": "6-8"
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
    "id": "rule-020",
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
    "id": "rule-021",
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
    "id": "rule-022",
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
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.7,
    "severity": "high",
    "is_remote": true,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impact",
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.73544,
    "recommendation": "Upgrade nginx to 1.21.4 or later to fix DNS resolver vulnerability"
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "description": "Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment, letting attackers load arbitrary modules",
    "affects_pinned_version": true,
    "kev": true,
    "epss_score": 0.94398,
    "recommendation": "Apply Debian security patches for Redis Lua sandbox escape; restrict EVAL command via rename-command; ensure Redis is not exposed to untrusted networks"
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "cvss_score": 9.9,
    "severity": "critical",
    "is_remote": true,
    "description": "Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts, letting authenticated attackers execute code",
    "affects_pinned_version": true,
    "kev": true,
    "epss_score": 0.14172,
    "recommendation": "Upgrade Redis to version 8.2.2 or later when available; restrict Lua script execution to trusted clients only; ensure Redis requires authentication"
  }
]
```

## Report

# ABAC Policy Mining Report — privsep-corp Ansible Infrastructure

## Executive Summary

An Attribute-Based Access Control (ABAC) policy was mined from the Ansible configuration for the privsep-corp production environment. The infrastructure comprises three host groups (webservers, dbservers, cacheservers) in a DMZ/internal zone topology with SOC2 compliance requirements. The policy captures 18 rules governing SSH access, firewall/network connectivity, filesystem ACLs, database authentication, and service account restrictions.

## Infrastructure Overview

### Hosts
| Host | IP | Role | Zone | Group |
|------|-----|------|------|-------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |
| cache01.lab.local | 10.0.2.20 | cache | internal | cacheservers |

### Users
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| www-data | 33 | www-data | — | — (service account, nologin) |
| postgres | — | postgres | — | — (service account, nologin) |
| redis | — | redis | — | — (service account, nologin) |

### Services
| Service | Version | Port | Host Group |
|---------|---------|------|------------|
| nginx | 1.20.0 | 443/tcp | webservers |
| openssh-server | 9.6p1 | 22/tcp | webservers |
| postgresql | 16.2 | 5432/tcp | dbservers |
| redis | 7.0.11 | 6379/tcp | cacheservers |

## Policy Summary

### Access Rules (18 total)

#### SSH Access
- **rule-001**: Members of the `sudo` group may SSH into webservers (AllowGroups directive)
- **rule-008**: `www-data` denied SSH login (nologin shell)
- **rule-012**: `postgres` denied SSH login (nologin shell)
- **rule-017**: `redis` denied SSH login (nologin shell)

#### Network/Firewall
- **rule-002**: HTTPS (443/tcp) open to internet (0.0.0.0/0) on webservers
- **rule-013**: PostgreSQL (5432/tcp) accessible from webservers subnet (10.0.1.0/24) only
- **rule-014**: Implicit deny for PostgreSQL from all other sources (pg_hba default)
- **rule-015**: Redis (6379/tcp) accessible from webservers subnet (10.0.1.0/24) only
- **rule-016**: Implicit deny for Redis from all other sources (firewalld default)

#### Filesystem ACLs
- **rule-003/004/005/006**: `/var/www/html` (owner=www-data, group=www-data, mode=0750) — owner has read/write/execute; group has read/execute
- **rule-009/010/011**: `/var/lib/postgresql/data` (owner=postgres, group=postgres, mode=0700) — owner has read/write/execute; no group/other access

#### Privilege Escalation
- **rule-007**: `www-data` explicitly denied sudo access (sudoers.d/www-data absent)

#### Default Deny
- **rule-018**: Catch-all deny for any unlisted subject-action-resource combination

## Vulnerability Assessment

### Critical Findings

| CVE | Product | Pinned Version | CVSS | Severity | Affects? | KEV | EPSS | Recommendation |
|-----|---------|---------------|------|----------|----------|-----|------|---------------|
| CVE-2021-23017 | nginx | 1.20.0 | 7.7 | High | Yes | No | 0.735 | Upgrade nginx to 1.21.4+; disable DNS resolver if unused |
| CVE-2022-0543 | redis | 7.0.11-1 | 10.0 | Critical | Yes | Yes | 0.944 | Apply Debian security patches; restrict EVAL via rename-command |
| CVE-2025-49844 | redis | 7.0.11-1 | 9.9 | Critical | Yes | Yes | 0.142 | Upgrade Redis to 8.2.2+; restrict Lua script execution |

**Both Redis CVEs are Known Exploited Vulnerabilities (KEV) with active exploitation in the wild. CVE-2022-0543 has an EPSS score of 0.944, indicating extremely high exploitation probability. Immediate patching is recommended.**

### OpenSSH and PostgreSQL
No critical or high-severity remote CVEs affecting the pinned versions (openssh 9.6p1, postgresql 16.2) were identified. Historical CVEs for OpenSSH (2000-2003 era) do not affect current versions.

## Ambiguities and Open Questions

1. **Redis authentication**: The Ansible configuration binds Redis to 10.0.2.20 and restricts network access via firewalld, but no `requirepass` or ACL configuration is visible. Redis may be running without authentication, which compounds the risk of CVE-2022-0543 and CVE-2025-49844.

2. **SSH access scope**: The `AllowGroups sudo` directive in sshd_config is deployed to webservers only. It is unclear whether dbservers and cacheservers have the same SSH restriction or rely on default (potentially more permissive) settings.

3. **User-role mapping**: The `developer` user belongs to the `developers` group, but no explicit access rules grant or deny this group access to any resource. Their effective access depends entirely on the default-deny rule, meaning developers may have no authorized access to any system unless SSH is configured more permissively on other hosts.

4. **Database credentials**: PostgreSQL pg_hba uses scram-sha-256 authentication, but no database user accounts or passwords are defined in the Ansible configuration. Credential management appears to be handled outside this repository.

5. **Redis bind address**: Redis is bound to 10.0.2.20 (the cache host IP) but the firewalld rule allows from 10.0.1.0/24. The bind configuration limits Redis to listen on the internal interface only, which is a positive security measure, but the lack of authentication is a gap.

6. **Log retention**: `default_log_retention_days: 90` is defined in group_vars/all.yml but no log collection or audit rules are implemented in the role task files. Audit obligations should be attached to access rules for SOC2 compliance.
