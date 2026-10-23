# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:12:49_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 11_  
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
        "department": "system",
        "clearance": "system",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "postgres"
    ],
    "clearance_levels": [
      {
        "value": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "value": "confidential",
        "source": "group_vars/all.yml"
      },
      {
        "value": "system",
        "source": "roles/db/tasks/main.yml"
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
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "source_networks": [
      {
        "cidr": "10.0.1.0/24",
        "label": "web_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "label": "internet",
        "source": "group_vars/webservers_legacy.yml"
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
        "host_group": [
          "webservers_patched",
          "webservers_legacy"
        ],
        "source": "group_vars/webservers_patched.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": [
          "dbservers"
        ],
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": [
          "webservers_patched",
          "webservers_legacy"
        ],
        "source": "roles/web_legacy/tasks/main.yml"
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
        "source": "group_vars/webservers_legacy.yml"
      }
    ]
  },
  "environment": {
    "org": "patchcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "sources": {
      "org": "group_vars/all.yml",
      "environment": "inventory.ini",
      "compliance_tier": "inventory.ini",
      "default_log_retention_days": "group_vars/all.yml"
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
      "port": {
        "equals": 22
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
      "lines": [
        16,
        18
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "description": "SSH sessions logged per SOC2 compliance"
      }
    ]
  },
  {
    "id": "rule-002",
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
      "lines": [
        10,
        14
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
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": [
        16,
        20
      ]
    },
    "obligations": [
      {
        "type": "auth_method",
        "description": "scram-sha-256 authentication required"
      }
    ]
  },
  {
    "id": "rule-004",
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
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
      ]
    }
  },
  {
    "id": "rule-007",
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
    "source": {
      "file": "policy",
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx njs",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "pinned_versions_affected": [
      "1.20.0-1~focal (legacy)"
    ],
    "recommendation": "Update njs component on legacy webservers to >= 0.7.1; patched server likely unaffected if njs updated independently"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "PostgreSQL 7.2.1 and earlier contain unknown vulnerability from invalid integer input",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "pinned_versions_affected": [],
    "recommendation": "No action required — pinned version 16.2 is not affected (vulnerability affects <= 7.2.x)"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh-server",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "OpenSSH pkcs11 helper allows arbitrary code execution via agent forwarding",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "pinned_versions_affected": [],
    "recommendation": "No action required — pinned version 9.6p1 is >= 9.3p2 where this was fixed"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "PostgreSQL jdbc driver SQL injection via client parameter",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "pinned_versions_affected": [],
    "recommendation": "Verify JDBC driver version separately; server version 16.2 not directly affected"
  }
]
```

## Report

# ABAC Policy Report — Ansible Configuration Mining

## Executive Summary

Mined an Attribute-Based Access Control (ABAC) policy from the Ansible configuration at `RLM_ANSIBLE_DIR`.
The configuration covers **2 users**, **2 groups**, **3 hosts**, **3 services**, **1 filesystem path**, and **7 access rules** including a default-deny.

## Policy Goal

`policy_goal = "all"` — full coverage requested.

## Catalog Summary

### Subjects
| User | UID | Groups | Department | Clearance | Source |
|------|-----|--------|------------|-----------|--------|
| admin | 1001 | sudo | operations | secret | group_vars/all.yml |
| appuser | 1002 | developers | engineering | confidential | group_vars/all.yml |
| postgres | system | postgres | system | system | roles/db/tasks/main.yml |

### Groups
sudo, developers, postgres

### Resources
| Host | IP | Role | Zone | Group |
|------|----|------|------|-------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Environment
- **Org**: patchcorp
- **Environment**: production
- **Compliance Tier**: soc2
- **Log Retention**: 90 days

## Rules Extracted

| ID | Action | Effect | Subject | Resource | Source |
|----|--------|--------|---------|----------|--------|
| rule-001 | ssh:login | permit | groups in [sudo] | ssh:22 | roles/web_legacy/tasks/main.yml |
| rule-002 | network:connect | permit | source_network 0.0.0.0/0 | tcp:443 | roles/web_legacy/tasks/main.yml |
| rule-003 | db:login | permit | source_network 10.0.1.0/24 | postgresql:5432 | roles/db/tasks/main.yml |
| rule-004 | filesystem:read | permit | groups in [postgres] | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| rule-005 | filesystem:write | permit | groups in [postgres] | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| rule-006 | filesystem:execute | permit | groups in [postgres] | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| rule-007 | * | deny | all | all | policy (default) |

## Vulnerability Assessment

| CVE | Product | CVSS | Severity | KEV | Affects Pinned? | Recommendation |
|-----|---------|------|----------|-----|-----------------|----------------|
| CVE-2021-46461 | nginx njs | 9.8 | critical | No | Yes (legacy) | Update njs on legacy webservers |
| CVE-2002-1399 | postgresql | 10.0 | critical | No | No | No action (affects <= 7.2.x) |
| CVE-2023-38408 | openssh | 9.8 | critical | Yes | No | No action (fixed in >= 9.3p2) |
| CVE-2024-1597 | postgresql jdbc | 9.8 | critical | Yes | No | Verify JDBC driver separately |

### Key Finding
- **CVE-2021-46461** affects the legacy nginx installation (1.20.0) via the njs scripting component.
- The patched server (nginx 1.24.0) may also be affected if njs is not independently updated.
- PostgreSQL 16.2 and OpenSSH 9.6p1 are NOT affected by the returned critical CVEs.

## Ambiguities

1. **SSH version format**: The pinned version `1:9.6p1-3ubuntu1` uses Debian epoch notation (`1:`). Upstream comparison against CVE version ranges requires epoch-aware parsing.
2. **nginx njs component version**: The group_vars pins `nginx_version` but not the njs sub-component version separately. CVE-2021-46461 targets njs specifically.
3. **No explicit sudoers rules**: No sudoers task files were found in the roles; sudo access is inferred from group membership but no explicit privilege escalation rules were extracted.
4. **No SELinux/AppArmor policies**: No MAC policy configuration found in the Ansible roles.
5. **Firewall allows 0.0.0.0/0**: Rule-002 permits HTTPS from any source — this is broad and may warrant scoping to specific CIDRs in a stricter policy.
6. **Credential management**: No explicit credential vault or secrets management tasks found in the scanned roles.

## Obligations

- **Session logging**: SSH login (rule-001) carries a SOC2 session logging obligation.
- **Authentication method**: PostgreSQL access (rule-003) requires scram-sha-256 authentication per pg_hba.conf configuration.
