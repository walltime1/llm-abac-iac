# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:14:07_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 15 | Rules: 15_  
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
        "source": "roles/db/tasks/main.yml",
        "note": "system account (postgresql package)"
      }
    ],
    "groups": [
      "sudo",
      "developers",
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
        "host_group": "webservers",
        "source": "group_vars/webservers_legacy.yml, group_vars/webservers_patched.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "sshd",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web_legacy/tasks/main.yml, roles/web_patched/tasks/main.yml"
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
        "label": "web_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "any",
        "label": "internet",
        "source": "group_vars/webservers_legacy.yml, group_vars/webservers_patched.yml"
      }
    ]
  },
  "environment": {
    "org": "patchcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "inventory.ini, group_vars/all.yml"
  },
  "subject_attributes": {
    "user": {
      "type": "string",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "postgres"
      ],
      "source": "group_vars/all.yml, roles/db/tasks/main.yml"
    },
    "clearance": {
      "type": "string",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "string",
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resource_attributes": {
    "hostname": {
      "type": "string",
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "source": "inventory.ini"
    },
    "zone": {
      "type": "string",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "type": "string",
      "domain": [
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "string",
      "domain": [
        "webservers_patched",
        "webservers_legacy",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "string",
      "domain": [
        "nginx",
        "postgresql",
        "sshd"
      ],
      "source": "group_vars/*.yml, roles/*"
    },
    "port": {
      "type": "number",
      "source": "group_vars/*.yml"
    },
    "path": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "source_ip": {
      "type": "string",
      "source": "group_vars/*.yml"
    },
    "source_network": {
      "type": "string",
      "source": "group_vars/dbservers.yml, group_vars/webservers_*.yml"
    },
    "source_zone": {
      "type": "string",
      "domain": [
        "dmz",
        "internal",
        "any"
      ],
      "source": "group_vars/*.yml"
    }
  },
  "environment_attributes": {
    "org": {
      "type": "string",
      "domain": [
        "patchcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "string",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "string",
      "domain": [
        "soc2"
      ],
      "source": "inventory.ini"
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
        "equals": "sshd"
      },
      "port": {
        "equals": 22
      },
      "host_group": {
        "in": [
          "webservers_legacy",
          "webservers_patched"
        ]
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        22,
        26
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
        "equals": "sshd"
      },
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "webservers_patched"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        22,
        26
      ]
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
      },
      "host_group": {
        "equals": "webservers_legacy"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        14,
        20
      ]
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
      },
      "host_group": {
        "equals": "webservers_patched"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        14,
        20
      ]
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
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": [
        17,
        21
      ]
    }
  },
  {
    "id": "rule-006",
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
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        9,
        15
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
    "action": "filesystem:write",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        9,
        15
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
    "action": "filesystem:execute",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        9,
        15
      ]
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
        "equals": "webservers_legacy"
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
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "webservers_patched"
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts.",
    "affected_version": "1.20.0-1~focal (legacy webservers)",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx on legacy webservers to 1.24.0 or later. Patched webservers already run 1.24.0-2ubuntu1 which is unaffected.",
    "source_file": "group_vars/webservers_legacy.yml"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 8.1,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling in the SIGALRM handler, letting unauthenticated remote attackers execute arbitrary code (regreSSHion).",
    "affected_version": "1:9.6p1-3ubuntu1 (all hosts)",
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh-server to 9.8p1 or later on all webservers. Apply vendor patches immediately.",
    "source_file": "group_vars/all.yml"
  }
]
```

## Report

# ABAC Policy Mining Report — patchcorp Ansible Configuration

## Executive Summary

Mined **9 ABAC rules** (8 permit, 1 default-deny) from the patchcorp Ansible
configuration. Identified **2 actively exploitable vulnerabilities** in pinned
package versions. Policy covers SSH access, network firewall rules, PostgreSQL
database access, and filesystem permissions.

## Policy Scope

- **Goal**: `all` (full coverage)
- **Files analyzed**: 8 (5 group_vars/inventory + 3 role task files)
- **Environment**: production, compliance_tier=soc2, org=patchcorp

## Attributes Catalog

### Subjects
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |
| postgres | — | postgres | — | — |

**Groups**: sudo, developers, postgres

### Resources
| Host | IP | Role | Zone | Group |
|------|-----|------|------|-------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| nginx | 443 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |
| sshd | 22 | tcp | webservers |

### Key Package Versions
| Package | Version | Host Group | Status |
|---------|---------|------------|--------|
| nginx | 1.24.0-2ubuntu1 | webservers_patched | ✅ Current |
| nginx | 1.20.0-1~focal | webservers_legacy | ⚠️ Vulnerable |
| openssh | 9.6p1-3ubuntu1 | all webservers | ⚠️ Vulnerable |
| postgresql | 16.2-1.pgdg22.04+1 | dbservers | ✅ Current |

## Extracted Rules

| ID | Action | Subject | Resource | Effect |
|----|--------|---------|----------|--------|
| rule-001 | ssh:login | groups ∈ [sudo] | sshd:22 (webservers) | permit |
| rule-002 | ssh:login | groups ∈ [sudo] | sshd:22 (webservers_patched) | permit |
| rule-003 | network:connect | source: 0.0.0.0/0 | nginx:443 (legacy) | permit |
| rule-004 | network:connect | source: 0.0.0.0/0 | nginx:443 (patched) | permit |
| rule-005 | network:connect | source: 10.0.1.0/24 | postgresql:5432 (dbservers) | permit |
| rule-006 | filesystem:read | groups ∈ [postgres] | /var/lib/postgresql/data (0700) | permit |
| rule-007 | filesystem:write | groups ∈ [postgres] | /var/lib/postgresql/data (0700) | permit |
| rule-008 | filesystem:execute | groups ∈ [postgres] | /var/lib/postgresql/data (0700) | permit |
| rule-009 | * | all | all | deny |

## Vulnerability Assessment

### Active Findings

1. **CVE-2024-6387 (regreSSHion)** — OpenSSH < 9.8p1
   - **Severity**: High (CVSS 8.1)
   - **Affected**: All webservers (openssh 9.6p1)
   - **Impact**: Remote unauthenticated RCE via signal handler race condition
   - **Recommendation**: Upgrade to openssh-server ≥ 9.8p1 immediately

2. **CVE-2021-23017** — nginx resolver memory overwrite
   - **Severity**: High (CVSS 7.7)
   - **Affected**: webservers_legacy only (nginx 1.20.0)
   - **Impact**: Worker process crash via forged DNS responses
   - **Recommendation**: Upgrade legacy nginx to ≥ 1.24.0

### Mitigated CVEs
- CVE-2023-38408 (openssh < 9.3p2): patched by 9.6p1
- CVE-2017-20005 (nginx < 1.13.6): patched by both 1.20.0 and 1.24.0
- CVE-2016-0746 (nginx < 1.9.10): patched by both versions

## Ambiguities & Notes

1. **Credential storage**: No explicit credential management (vault/secrets) found
   in the analyzed Ansible configuration. Database authentication uses
   `scram-sha-256` method per pg_hba.conf template, but password storage
   mechanism is not visible.

2. **SSH key management**: No `authorized_key` or SSH key distribution tasks
   found. SSH access control relies solely on `AllowGroups` directive.

3. **Default firewall policy**: Firewalld tasks only add allow rules; no
   explicit default-deny zone configuration is present in the Ansible tasks.
   The ABAC default-deny rule (rule-009) compensates for this at the policy
   level.

4. **PostgreSQL user management**: No `postgresql_user` tasks found — only
   network-level pg_hba.conf restrictions. Database-level user privileges
   are not defined in the analyzed configuration.

5. **No SELinux/AppArmor tasks**: No mandatory access control module
   configuration found in the role definitions.

6. **Divergent nginx versions**: Legacy webservers run nginx 1.20.0 (vulnerable)
   while patched webservers run 1.24.0. The firewall rules (rule-003/004)
   permit the same traffic to both, meaning the legacy servers are equally
   exposed to internet-facing attacks.

7. **Obligations**: No session logging or audit script tasks were found in
   the analyzed role files. SOC2 compliance tier may require these to be
   added separately.
