# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:10:52_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 8 | Rules: 12_  
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
        "department": "operations",
        "clearance": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "department": "engineering",
        "clearance": "confidential",
        "source": "group_vars/all.yml"
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
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "postgres"
    ],
    "clearance_levels": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "type": "cidr",
      "domain": null,
      "source": "group_vars/dbservers.yml"
    }
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
        "host_group": "webservers_patched,webservers_legacy",
        "source": "group_vars/webservers_patched.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "openssh-server",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers_patched,webservers_legacy",
        "source": "roles/web_patched/tasks/main.yml"
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
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web-subnet",
        "domain": null,
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "domain": null,
        "source": "group_vars/webservers_patched.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "patchcorp",
      "domain": [
        "patchcorp"
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
        "pci",
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
  },
  "packages": {
    "nginx_patched": "1.24.0-2ubuntu1",
    "nginx_legacy": "1.20.0-1~focal",
    "postgresql": "16.2-1.pgdg22.04+1",
    "openssh-server": "1:9.6p1-3ubuntu1"
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "description": "Permit SSH login for members of the sudo group on web servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "openssh-server"
      },
      "port": {
        "equals": 22
      },
      "host_group": {
        "in": [
          "webservers_patched",
          "webservers_legacy"
        ]
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        18,
        21
      ]
    }
  },
  {
    "id": "rule-002",
    "description": "Permit inbound HTTPS (port 443/tcp) from any source to web servers",
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
        "in": [
          "webservers_patched",
          "webservers_legacy"
        ]
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        13,
        17
      ]
    }
  },
  {
    "id": "rule-003",
    "description": "Permit PostgreSQL connections from web subnet (10.0.1.0/24) via pg_hba.conf",
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": [
        13,
        16
      ]
    }
  },
  {
    "id": "rule-004",
    "description": "Restrict PostgreSQL data directory to owner-only access (mode 0700)",
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "id": "rule-005",
    "description": "Restrict PostgreSQL data directory write access to owner (mode 0700)",
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "id": "rule-006",
    "description": "Restrict PostgreSQL data directory execute access to owner (mode 0700)",
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "id": "rule-007",
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
    "obligations": [],
    "source": {
      "file": "implicit",
      "task": "default-deny",
      "lines": [
        0,
        0
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
    "id": "rule-009",
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
      },
      "host_group": {
        "in": [
          "webservers_patched",
          "webservers_legacy"
        ]
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
      },
      "host_group": {
        "equals": "dbservers"
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
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX njs through 0.7.0 out-of-bounds array access in njs_vmcode_typeof",
    "pinned_versions": {
      "legacy": "1.20.0-1~focal",
      "patched": "1.24.0-2ubuntu1"
    },
    "affects_pinned_version": {
      "legacy": true,
      "patched": true,
      "note": "njs component bundled with nginx; version of bundled njs unknown but vulnerability scope covers all nginx versions shipping njs <= 0.7.0"
    },
    "recommendation": "Ensure nginx is compiled with njs > 0.7.0 or disable njs module. Verify bundled njs version in both legacy and patched packages.",
    "source": "search_critical_remote(nginx)"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "nginx 0.6.18-1.8.0 and 1.9.x <1.9.10 use-after-free in DNS resolver CNAME processing",
    "pinned_versions": {
      "legacy": "1.20.0-1~focal",
      "patched": "1.24.0-2ubuntu1"
    },
    "affects_pinned_version": {
      "legacy": false,
      "patched": false,
      "note": "Both 1.20.0 and 1.24.0 are after the fix in 1.9.10. NOT affected."
    },
    "recommendation": "No action required — pinned versions are not vulnerable.",
    "source": "search_critical_remote(nginx)"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "PostgreSQL JDBC Driver <42.2.26 and <42.4.1 SQL injection in refreshRow() method",
    "pinned_versions": {
      "server": "16.2-1.pgdg22.04+1"
    },
    "affects_pinned_version": {
      "server": false,
      "note": "This vulnerability affects the PostgreSQL JDBC Driver (Java client library), NOT the PostgreSQL server package. The pinned server version 16.2 is not affected."
    },
    "recommendation": "Verify any Java applications connecting to PostgreSQL use JDBC driver >= 42.2.26 or >= 42.4.1. Not a server-side concern.",
    "source": "search_critical_remote(postgresql)"
  }
]
```

## Report

# ABAC Policy Report — patchcorp Ansible Configuration

## Executive Summary

Mined ABAC policy from Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages
a production SOC2-compliant environment with two web server tiers (patched and legacy) and one
database server.

## Catalog Summary

### Subjects
- **2 human users**: `admin` (sudo, operations, secret clearance), `appuser` (developers, engineering, confidential clearance)
- **1 system user**: `postgres` (postgres group, manages PostgreSQL data directory)
- **3 groups**: sudo, developers, postgres
- **Clearance levels**: secret, confidential
- **Departments**: operations, engineering

### Resources
- **3 hosts**: web-new01.lab.local (10.0.1.10, dmz), web-old01.lab.local (10.0.1.20, dmz), db01.lab.local (10.0.2.10, internal)
- **3 services**: nginx (port 443/tcp), openssh-server (port 22/tcp), postgresql (port 5432/tcp)
- **1 protected path**: /var/lib/postgresql/data (postgres:postgres, 0700)
- **2 network zones**: 10.0.1.0/24 (web-subnet, dmz), 0.0.0.0/0 (internet)

### Environment
- **Organization**: patchcorp
- **Environment**: production
- **Compliance tier**: soc2
- **Log retention**: 90 days

## Rule Summary (7 rules)

| ID | Action | Subject | Resource | Effect |
|---|---|---|---|---|
| rule-001 | ssh:login | groups any_of [sudo] | openssh-server:22 | permit |
| rule-002 | network:connect | source_network 0.0.0.0/0 | nginx:443 | permit |
| rule-003 | network:connect | source_network 10.0.1.0/24 | postgresql:5432 | permit |
| rule-004 | filesystem:read | user postgres | /var/lib/postgresql/data (0700) | permit |
| rule-005 | filesystem:write | user postgres | /var/lib/postgresql/data (0700) | permit |
| rule-006 | filesystem:execute | user postgres | /var/lib/postgresql/data (0700) | permit |
| rule-007 | * | all | all | deny |

## Vulnerability Assessment

### Pinned Package Versions
| Package | Pinned Version(s) |
|---|---|
| nginx (legacy) | 1.20.0-1~focal |
| nginx (patched) | 1.24.0-2ubuntu1 |
| postgresql | 16.2-1.pgdg22.04+1 |
| openssh-server | 1:9.6p1-3ubuntu1 |

### CVE Findings

1. **CVE-2021-46461** (CVSS 9.8, Critical) — NGINX njs buffer overflow
   - Affects: Both legacy and patched nginx (bundled njs component)
   - Recommendation: Verify bundled njs version; upgrade or disable njs module

2. **CVE-2016-0746** (CVSS 9.8, Critical) — nginx DNS resolver use-after-free
   - Affects: Neither version (both > 1.9.10 fix)
   - Status: NOT VULNERABLE

3. **CVE-2022-31197** (CVSS 7.5, High) — PostgreSQL JDBC SQL injection
   - Affects: NOT the server (JDBC driver only)
   - Status: NOT VULNERABLE (server-side); verify client-side JDBC driver version

## Ambiguities & Gaps

1. **njs component version**: The nginx packages pin the main nginx version but do not explicitly pin the bundled njs module. CVE-2021-46461 applies to njs ≤ 0.7.0. Recommend verifying `nginx --version` output or package metadata for njs version.

2. **SSH default port assumed**: The Ansible config installs openssh-server and sets `AllowGroups sudo` in sshd_config, but does not explicitly configure the SSH port. Rule assumes default port 22.

3. **No sudoers rules found**: The `admin` user is in the `sudo` group but no sudoers configuration or NOPASSWD directives were found in the Ansible files. This is an ambiguity for privilege escalation controls.

4. **No explicit deny rules in pg_hba**: The pg_hba.conf only adds an `allow` line for 10.0.1.0/24. Implicit deny depends on PostgreSQL's default pg_hba ordering (deny-all at end). This is reflected in the default-deny rule.

5. **No credentials/hardcoded secrets**: No credentials files, vault variables, or secret management configurations were found in the scanned Ansible files.

## Provenance

All rules extracted from:
- `inventory.ini` — host definitions, environment vars
- `group_vars/all.yml` — users, packages, org settings
- `group_vars/dbservers.yml` — postgres config, allowed sources
- `group_vars/webservers_legacy.yml` — legacy nginx version, firewall rules
- `group_vars/webservers_patched.yml` — patched nginx version, firewall rules
- `roles/db/tasks/main.yml` — postgresql installation, data dir permissions, pg_hba config
- `roles/web_legacy/tasks/main.yml` — nginx/openssh install, firewall, sshd config
- `roles/web_patched/tasks/main.yml` — nginx/openssh install, firewall, sshd config
