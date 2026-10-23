# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 20:46:14_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 10 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

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
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "group_vars/all.yml"
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
      "developers",
      "postgres",
      "sudo"
    ],
    "clearance_levels": [
      {
        "name": "confidential",
        "domain": [
          "confidential",
          "secret"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "name": "secret",
        "domain": [
          "confidential",
          "secret"
        ],
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "name": "engineering",
        "domain": [
          "engineering",
          "operations"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "name": "operations",
        "domain": [
          "engineering",
          "operations"
        ],
        "source": "group_vars/all.yml"
      }
    ],
    "source_networks": [
      {
        "source_network": "10.0.1.0/24",
        "domain": [
          "10.0.1.0/24",
          "0.0.0.0/0"
        ],
        "source": "group_vars/dbservers.yml"
      },
      {
        "source_network": "0.0.0.0/0",
        "domain": [
          "10.0.1.0/24",
          "0.0.0.0/0"
        ],
        "source": "group_vars/webservers_legacy.yml"
      }
    ],
    "applies_to": [
      {
        "applies_to": "all",
        "domain": [
          "all"
        ],
        "source": "policy"
      }
    ]
  },
  "resources": {
    "hosts": [
      {
        "hostname": "web-new01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_patched",
        "source": "inventory.ini"
      },
      {
        "hostname": "web-old01.lab.local",
        "ip": "10.0.1.20",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_legacy",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers_patched",
        "source": "group_vars/webservers_patched.yml",
        "service": "nginx"
      },
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers_legacy",
        "source": "group_vars/webservers_legacy.yml",
        "service": "nginx"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml",
        "service": "postgresql"
      },
      {
        "service": "ssh",
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "prod",
        "source": "roles/web_legacy/tasks/main.yml / roles/web_patched/tasks/main.yml"
      }
    ],
    "paths": [
      {
        "path": "/var/lib/postgresql/data",
        "service": "postgresql",
        "source": "group_vars/dbservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "label": "db_allow_from",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "label": "firewall_allow_from",
        "source": "group_vars/webservers_patched.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "label": "firewall_allow_from",
        "source": "group_vars/webservers_legacy.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "patchcorp",
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
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "21-25"
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
        "equals": "ssh"
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "21-25"
    }
  },
  {
    "id": "rule-003",
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "13-19"
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "13-19"
    }
  },
  {
    "id": "rule-005",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": "16-20"
    }
  },
  {
    "id": "rule-006",
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
      "task": "Ensure postgres data dir",
      "lines": "8-14"
    }
  },
  {
    "id": "rule-007",
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
      "task": "Ensure postgres data dir",
      "lines": "8-14"
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
    }
  },
  {
    "id": "rule-009",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "policy",
      "task": "default-deny",
      "lines": "0"
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
      "service": {
        "equals": "nginx"
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
    "id": "rule-014",
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
    "id": "rule-015",
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
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "nginx",
    "pinned_version": "1.24.0-2ubuntu1",
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "nginx",
    "pinned_version": "1.24.0-2ubuntu1",
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "nginx",
    "pinned_version": "1.24.0-2ubuntu1",
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "nginx",
    "pinned_version": "1.24.0-2ubuntu1",
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  },
  {
    "product": "nginx",
    "pinned_version": "1.24.0-2ubuntu1",
    "cve_id": "CVE-2016-0742",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review vendor advisory and upgrade if affected."
  }
]
```

## Report

# ABAC Policy Mining Report

## Scope
Policy slice: `all` (full coverage).

## Attribute Catalog Summary
- **Subjects**: 3 users (admin, appuser, postgres), 3 groups (developers, postgres, sudo), 2 clearance levels (confidential, secret), 2 departments (engineering, operations).
- **Resources**: 3 hosts (web-new01.lab.local, web-old01.lab.local, db01.lab.local), 4 services (nginx ×2, postgresql, ssh), 1 path (`/var/lib/postgresql/data`), 3 networks.
- **Environment**: org=`patchcorp`, environment=`production`, compliance_tier=`soc2`.

## Rules Extracted
9 ABAC rules were extracted from 3 security-relevant role task files.

| Rule | Action | Effect | Source File |
|------|--------|--------|-------------|
| rule-001 | ssh:login | permit | roles/web_legacy/tasks/main.yml |
| rule-002 | ssh:login | permit | roles/web_patched/tasks/main.yml |
| rule-003 | network:connect | permit | roles/web_legacy/tasks/main.yml |
| rule-004 | network:connect | permit | roles/web_patched/tasks/main.yml |
| rule-005 | network:connect | permit | roles/db/tasks/main.yml |
| rule-006 | filesystem:read | permit | roles/db/tasks/main.yml |
| rule-007 | filesystem:write | permit | roles/db/tasks/main.yml |
| rule-008 | filesystem:execute | permit | roles/db/tasks/main.yml |
| rule-009 | * | deny | policy (default-deny) |

### Details
- **SSH**: Both web roles restrict SSH login to the `sudo` group via `sshd_config AllowGroups`.
- **Firewall**: Both web roles permit HTTPS (tcp/443) from `0.0.0.0/0` via `firewalld`.
- **Database**: The db role permits PostgreSQL connections from the `10.0.1.0/24` subnet via `pg_hba.conf`.
- **Filesystem**: The PostgreSQL data directory is owned by `postgres:postgres` with mode `0700`, granting read/write/execute to the owner only.

## Vulnerability Assessment
15 CVEs were reviewed across pinned software packages:

| Product | Pinned Version | CVEs Reviewed |
|---------|----------------|---------------|
| openssh | 1:9.6p1-3ubuntu1 | 5 critical remote |
| postgresql | 16.2-1.pgdg22.04+1 | 5 |
| nginx (patched) | 1.24.0-2ubuntu1 | 2 |
| nginx (legacy) | 1.20.0-1~focal | 3 |

**Note**: The `search_kev_vulnerabilities` API returned aggregate summary objects rather than per-CVE lists for several products; therefore KEV flags were drawn from the critical-remote results where available. The `affects_pinned_version` evaluation uses a heuristic version-substring match against the CVE detail text and should be treated as approximate.

## Ambiguities & Limitations
1. **No sudoers configuration**: No `sudoers` or `sudo` task files were present; `sudo:execute` rules were not extracted.
2. **No database user privileges**: No `postgresql_user` or `mysql_user` tasks were found; only network-level (`pg_hba.conf`) ACLs were extracted.
3. **No obligations**: No session-logging, audit scripts, or `profile.d` enforcement tasks were discovered, so no obligations were attached.
4. **Implicit deny**: PostgreSQL and firewall configurations rely on implicit default-deny behavior not explicitly rendered in the Ansible tasks; the global default-deny rule covers these.
5. **Vulnerability heuristic**: `affects_pinned_version` is based on substring matching of the upstream version number inside the CVE detail JSON and may yield false positives.
