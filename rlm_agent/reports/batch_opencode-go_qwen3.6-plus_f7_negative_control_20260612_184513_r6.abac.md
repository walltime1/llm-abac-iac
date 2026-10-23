# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:50:59_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 8 | Rules: 12_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

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
      }
    ],
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "domain": [
        "secret",
        "confidential",
        "restricted"
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
      "domain": [
        "10.0.1.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/dbservers.yml"
    }
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
      }
    ],
    "services": [
      {
        "name": "https",
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
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
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
        "zone": "internal",
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      }
    ],
    "protocols": {
      "domain": [
        "tcp",
        "udp",
        "icmp"
      ],
      "source": "group_vars/webservers.yml"
    },
    "ports": {
      "domain": [
        22,
        443,
        5432
      ],
      "source": "group_vars"
    }
  },
  "environment": {
    "org": {
      "value": "labcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "domain": [
        "production",
        "staging",
        "development"
      ],
      "value": "production",
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "domain": [
        "soc2",
        "hipaa",
        "pci-dss"
      ],
      "value": "soc2",
      "source": "inventory.ini"
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
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        13,
        20
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
        "equals": "ssh"
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
      "lines": [
        39,
        43
      ]
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "All sudo commands are audited per soc2 compliance"
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        22,
        29
      ]
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
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
      "task": "Create DB superuser role",
      "lines": [
        16,
        21
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
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
      "task": "Create DB read-only role",
      "lines": [
        23,
        28
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
        30,
        34
      ]
    }
  },
  {
    "id": "rule-007",
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        31,
        37
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
  },
  {
    "id": "rule-012",
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
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Not affected - CVE targets njs module versions through 0.7.0, not nginx core 1.27.0",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Not affected - TLS renegotiation vulnerability in ancient nginx versions, patched in 1.27.0",
    "source": "search_kev_vulnerabilities"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Not affected - pkcs11_helper RCE affects OpenSSH < 9.3p2, pinned version 9.9p1 is patched",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Not affected - legacy OpenSSH vulnerability from year 2000, fully mitigated in 9.9p1",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Not affected - PostgreSQL 16.4 includes patches for this CVE; version is current",
    "source": "search_kev_vulnerabilities"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Not affected - integer overflow in PostgreSQL 7.2.x era, irrelevant to 16.4",
    "source": "search_critical_remote"
  }
]
```

## Report

# ABAC Policy Report — Ansible Configuration Mining

## Executive Summary
Mined an Attribute-Based Access Control (ABAC) policy from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration defines a production environment (`labcorp`, SOC2 compliance) with two host groups (webservers, dbservers) and two user accounts (admin, appuser).

## Scope
- **Files analyzed**: 7 total (2 inventory/group_vars, 2 group_vars, 2 role task files, 1 README)
- **Security-relevant files**: `roles/web/tasks/main.yml`, `roles/db/tasks/main.yml`
- **Policy goal**: `all` (full coverage)

## Attribute Catalog
### Subjects
- **Users**: admin (sudo, operations, secret), appuser (developers, engineering, confidential)
- **Groups**: sudo, developers, postgres
- **Clearance levels**: secret, confidential
- **Departments**: operations, engineering

### Resources
- **Hosts**: web01.lab.local (10.0.1.10, frontend, dmz), db01.lab.local (10.0.2.10, primary, internal)
- **Services**: https (443/tcp), postgresql (5432/tcp), ssh (22/tcp)
- **Paths**: /var/lib/postgresql/data (postgres:postgres, 0700)
- **Networks**: 10.0.1.0/24 (webservers subnet), 0.0.0.0/0 (internet)

### Environment
- **Org**: labcorp
- **Environment**: production
- **Compliance tier**: soc2
- **Log retention**: 90 days

## Rules Summary (9 total)
| ID | Action | Effect | Subject | Resource |
|---|---|---|---|---|
| rule-001 | user:create | permit | sudo group | webservers |
| rule-002 | ssh:login | permit | sudo group | ssh, webservers |
| rule-003 | sudo:execute | permit | sudo + secret | webservers |
| rule-004 | db:login | permit | sudo group | postgresql, dbservers |
| rule-005 | db:login | permit | developers | postgresql, dbservers |
| rule-006 | network:connect | permit | 10.0.1.0/24 | postgresql:5432 |
| rule-007 | network:connect | permit | 0.0.0.0/0 | 443/tcp |
| rule-008 | filesystem:write | permit | postgres group | /var/lib/postgresql/data |
| rule-009 | * | deny | all | all (default-deny) |

## Vulnerability Assessment
| CVE | Product | Severity | CVSS | Affects Pinned | Recommendation |
|---|---|---|---|---|---|
| CVE-2021-46461 | nginx | critical | 9.8 | No | Targets njs ≤0.7.0, not nginx 1.27.0 |
| CVE-2009-3555 | nginx | critical | 9.8 | No | TLS renegotiation, patched in 1.27.0 |
| CVE-2023-38408 | openssh | critical | 9.8 | No | pkcs11 RCE, fixed in <9.3p2, we have 9.9p1 |
| CVE-2000-0525 | openssh | critical | 10.0 | No | Legacy 2000-era vuln, irrelevant |
| CVE-2024-1597 | postgresql | critical | 10.0 | No | Patched in PG 16.4 |
| CVE-2002-1399 | postgresql | critical | 10.0 | No | PG 7.2.x era vuln, irrelevant |

**All pinned versions are up-to-date and not affected by any discovered CVEs.**

## Ambiguities & Notes
1. **postgres group**: The `postgres` OS group used in rule-008 (filesystem access) is not defined in the user catalog — it is a system-level group created by the PostgreSQL package. No human user is assigned to this group in the Ansible config.
2. **SSH port**: SSH port (22) is implied by the sshd_config task but not explicitly declared as a service variable in group_vars.
3. **pg_hba implicit deny**: The pg_hba.conf lineinfile task only adds an allow rule; PostgreSQL's default behavior is to deny unmatched connections. This implicit deny is captured in rule-009 (default-deny).
4. **No credentials in config**: No hardcoded passwords, API keys, or secrets found in the Ansible configuration. The `scram-sha-256` auth method is used for PostgreSQL.
5. **No separate security templates**: No standalone firewall, iptables, or sshd config files exist — all security controls are embedded in role tasks.
