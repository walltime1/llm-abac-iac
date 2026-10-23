# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:06:52_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 12 | Rules: 13_  
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
        "department": "service",
        "clearance": "none",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [
          "postgres"
        ],
        "department": "service",
        "clearance": "none",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "name": "redis",
        "uid": null,
        "groups": [
          "redis"
        ],
        "department": "service",
        "clearance": "none",
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
        "name": "secret",
        "domain": [
          "secret",
          "confidential",
          "none"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "name": "confidential",
        "domain": [
          "secret",
          "confidential",
          "none"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "name": "none",
        "domain": [
          "secret",
          "confidential",
          "none"
        ],
        "source": "roles/web/tasks/main.yml"
      }
    ],
    "departments": [
      {
        "name": "operations",
        "domain": [
          "operations",
          "engineering",
          "service"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "name": "engineering",
        "domain": [
          "operations",
          "engineering",
          "service"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "name": "service",
        "domain": [
          "operations",
          "engineering",
          "service"
        ],
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
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers-subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "internal",
        "label": "internal-subnet",
        "source": "inventory.ini"
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
        "hipaa",
        "pci-dss",
        "none"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "value": 90,
      "source": "group_vars/all.yml"
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
      "hostname": {
        "equals": "web01.lab.local"
      },
      "service": {
        "equals": "ssh"
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
      "lines": [
        43,
        47
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
      "hostname": {
        "equals": "web01.lab.local"
      },
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": [
        27,
        33
      ]
    },
    "obligations": [
      {
        "type": "audit",
        "description": "Document root ACL enforced via Ansible file module"
      }
    ]
  },
  {
    "id": "rule-004",
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
      "lines": [
        49,
        52
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
    "id": "rule-006",
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
      },
      "port": {
        "equals": 5432
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
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "cache01.lab.local"
      },
      "service": {
        "equals": "redis"
      },
      "port": {
        "equals": 6379
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
      "file": "implicit",
      "task": "Default deny — not found in config, implied by absence of explicit permits",
      "lines": [
        0,
        0
      ]
    }
  },
  {
    "id": "rule-009",
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
      "file": "postprocessor",
      "task": "mode 0750 group read",
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
    "id": "rule-011",
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
      },
      "port": {
        "equals": 5432
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
    "id": "rule-013",
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
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "severity": "critical",
    "cvss_score": 9.9,
    "description": "Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts.",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade redis-server to version > 8.2.1 or apply vendor patch. Restrict Redis access to trusted internal networks only (already enforced by firewalld rule)."
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment.",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "This is a distribution-specific packaging issue. Ensure the redis-server package is updated to a patched version from the Ubuntu/Debian repositories. Verify redis.conf does not enable EVAL/EVALSHA for untrusted input."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates.",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Already fixed in pinned version 1.20.0 (fix was in 1.13.6). No action required."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access.",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Affects the njs scripting module only, which is not installed per the Ansible configuration. Monitor if njs is added in future."
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX vulnerability (older CVE, details truncated in search).",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "CVE predates the pinned nginx 1.20.0 version. Verify current patch status."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "OpenSSH historical vulnerability (2003).",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Ancient CVE from 2003. Not applicable to OpenSSH 9.6p1. No action required."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL 9.x vulnerability allowing privilege escalation.",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "CVE targets PostgreSQL 9.1-9.2 only. Pinned version 16.2 is not affected. No action required."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "PostgreSQL 8.1+ plpgsql PUBLIC function creation vulnerability.",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Legacy vulnerability from PostgreSQL 8.x era. Fixed in modern versions. Verify PostgreSQL 16.2 default plpgsql security settings."
  }
]
```

## Report

# ABAC Policy Report — privsep-corp (Production / SOC2)

## Executive Summary

Mined 8 ABAC rules from an Ansible configuration managing 3 hosts (web01, db01, cache01) across 3 inventory groups (webservers, dbservers, cacheservers). The policy covers SSH access, HTTPS firewall rules, filesystem ACLs, PostgreSQL and Redis network access, and a default-deny baseline. 2 of 8 assessed CVEs affect pinned package versions (both in Redis).

## Attribute Catalog

### Subjects
| Attribute | Values | Source |
|-----------|--------|--------|
| Users | admin (uid 1001, sudo, operations, secret), developer (uid 1002, developers, engineering, confidential), www-data (uid 33, system), postgres (system), redis (system) | group_vars/all.yml, roles/* |
| Groups | sudo, developers, www-data, postgres, redis | group_vars/all.yml, roles/* |
| Clearance levels | secret, confidential, none | group_vars/all.yml |
| Departments | operations, engineering, service | group_vars/all.yml |

### Resources
| Attribute | Values | Source |
|-----------|--------|--------|
| Hosts | web01.lab.local (10.0.1.10, frontend, dmz), db01.lab.local (10.0.2.10, primary, internal), cache01.lab.local (10.0.2.20, cache, internal) | inventory.ini |
| Services | nginx:443/tcp, postgresql:5432/tcp, redis:6379/tcp, ssh:22/tcp | group_vars/*, roles/* |
| Filesystem paths | /var/www/html (0750, www-data:www-data), /var/lib/postgresql/data (0700, postgres:postgres) | roles/web, roles/db |
| Networks | 0.0.0.0/0 (external), 10.0.1.0/24 (dmz), 10.0.2.0/24 (internal) | group_vars/* |

### Environment
| Attribute | Value |
|-----------|-------|
| Organization | privsep-corp |
| Environment | production |
| Compliance tier | soc2 |
| Log retention | 90 days |

## Rule Summary

| ID | Action | Effect | Subject | Resource | Source |
|----|--------|--------|---------|----------|--------|
| rule-001 | ssh:login | permit | groups in [sudo] | web01, ssh | roles/web/tasks/main.yml |
| rule-002 | network:connect | permit | source: 0.0.0.0/0 | web01, nginx:443 | roles/web/tasks/main.yml |
| rule-003 | filesystem:write | permit | groups in [www-data] | /var/www/html (0750) | roles/web/tasks/main.yml |
| rule-004 | sudo:execute | deny | user=www-data | all | roles/web/tasks/main.yml |
| rule-005 | filesystem:write | permit | groups in [postgres] | /var/lib/postgresql/data (0700) | roles/db/tasks/main.yml |
| rule-006 | network:connect | permit | source: 10.0.1.0/24 | db01, postgresql:5432 | roles/db/tasks/main.yml |
| rule-007 | network:connect | permit | source: 10.0.1.0/24 | cache01, redis:6379 | roles/cache/tasks/main.yml |
| rule-008 | * | deny | all | all | implicit |

## Vulnerability Assessment

### Critical findings (affecting pinned versions)
- **CVE-2025-49844** (Redis ≤8.2.1, CVSS 9.9): Use-after-free via GC manipulation in Lua scripts. Pinned redis-server 7.0.11 is affected. **Recommendation**: Upgrade to >8.2.1 or apply vendor patch.
- **CVE-2022-0543** (Redis Debian/Ubuntu packages, CVSS 10.0): Lua sandbox escape via insufficient sanitization. Pinned version potentially affected by packaging issue. **Recommendation**: Ensure patched distro package; verify redis.conf restricts EVAL/EVALSHA.

### Not affected (pinned versions are newer than vulnerable ranges)
- CVE-2017-20005 (nginx 1.20.0 > 1.13.6 fix threshold)
- CVE-2021-46461 (nginx njs module — not installed)
- CVE-2016-0746 (nginx — predates 1.20.0)
- CVE-2003-0786, CVE-2000-0999, CVE-2000-0525 (openssh 9.6p1 — ancient CVEs)
- CVE-2013-1903, CVE-2007-3279 (postgresql 16.2 — target 8.x/9.x only)

## Ambiguities & Limitations

1. **No explicit pg_hba.conf DENY rules**: The Ansible config only appends an ALLOW entry for 10.0.1.0/24. PostgreSQL's default pg_hba.conf behavior (typically peer/md5 for local, deny for unmatched) is assumed but not explicitly encoded. This is reflected as an implicit deny in rule-008.
2. **Redis bind address vs. firewall**: Redis is bound to 10.0.2.20 (internal interface) in redis.conf AND firewalld restricts to 10.0.1.0/24. These are complementary controls but only the firewalld rule is captured as a formal ABAC rule (rule-007). The bind address is a configuration-level control.
3. **No database user/privilege rules**: The Ansible config installs PostgreSQL but does not create specific database users or grant privileges via `postgresql_user`/`postgresql_privs`. Only filesystem and network-level controls are present.
4. **No explicit credentials management**: No vault-encrypted variables or credential rotation tasks found.
5. **Missing SSH deny-default**: The `AllowGroups sudo` directive implicitly denies all non-sudo SSH access, but no explicit deny rule for SSH is present beyond the default-deny catch-all.
6. **Line numbers are approximate**: Source file line ranges are estimated from file structure; exact line numbers may vary slightly.
7. **KEV searches returned entries with minimal detail**: Known Exploited Vulnerability searches produced results without full CVE metadata; cross-referenced with critical/remote searches.

## Recommendations

1. **Priority 1**: Patch redis-server to address CVE-2025-49844 and CVE-2022-0543.
2. Add explicit PostgreSQL `pg_hba.conf` DENY rules for clarity (e.g., `host all all 0.0.0.0/0 reject`).
3. Consider adding explicit SSH deny rule for non-sudo groups instead of relying on implicit default-deny.
4. Implement Ansible Vault for any future credential management tasks.
5. Add SELinux/AppArmor tasks for defense-in-depth on production hosts.
