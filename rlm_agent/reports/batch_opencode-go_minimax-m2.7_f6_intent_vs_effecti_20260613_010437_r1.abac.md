# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:13:05_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

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
          "department": "operations"
        },
        {
          "name": "developer",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "clearance": "confidential",
          "department": "engineering"
        },
        {
          "name": "dba",
          "uid": 1003,
          "groups": [
            "dba"
          ],
          "clearance": "secret",
          "department": "data"
        }
      ]
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": {
      "domain": null,
      "source": "inventory.ini",
      "values": [
        {
          "hostname": "proxy01.lab.local",
          "ip": "10.0.1.10",
          "role": "reverse_proxy",
          "zone": "dmz",
          "inventory_group": "dmz"
        },
        {
          "hostname": "app01.lab.local",
          "ip": "10.0.2.10",
          "role": "application",
          "zone": "app",
          "inventory_group": "appservers"
        },
        {
          "hostname": "db01.lab.local",
          "ip": "10.0.3.10",
          "role": "primary",
          "zone": "data",
          "inventory_group": "dbservers"
        }
      ]
    },
    "services": {
      "domain": null,
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml",
      "values": [
        {
          "name": "app",
          "port": 8080,
          "protocol": "tcp",
          "host_group": "appservers"
        },
        {
          "name": "postgres",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers"
        },
        {
          "name": "https",
          "port": 443,
          "protocol": "tcp",
          "host_group": "dmz"
        },
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "all"
        }
      ]
    },
    "networks": {
      "domain": null,
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml",
      "values": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "DMZ subnet"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "app",
          "label": "appservers subnet"
        },
        {
          "cidr": "10.0.3.0/24",
          "zone": "data",
          "label": "dbservers subnet"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "any",
          "label": "internet"
        }
      ]
    },
    "paths": {
      "domain": null,
      "source": "roles/db/tasks/main.yml",
      "values": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700"
        }
      ]
    }
  },
  "environment": {
    "org": {
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "domain": [
        "pci"
      ],
      "source": "inventory.ini,group_vars/all.yml"
    },
    "retention_days": {
      "domain": null,
      "source": "group_vars/all.yml",
      "values": [
        365
      ]
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "SSH login to DMZ hosts restricted to sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dmz"
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        17,
        20
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "SSH login to app servers for sudo and developers groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      },
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        13,
        16
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "SSH login to database servers for sudo and dba groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        28,
        31
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "DBA users get PostgreSQL SUPERUSER privileges",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privilege_level": "SUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        12,
        16
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Developer users get PostgreSQL login only (no superuser)",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privilege_level": "NOSUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        18,
        22
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "DMZ subnet can connect to app servers on port 8080",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      },
      "source_zone": {
        "equals": "dmz"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      },
      "service": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        7,
        12
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Internet can connect to DMZ reverse proxy on HTTPS port 443",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      },
      "source_zone": {
        "equals": "any"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "port": {
        "equals": 443
      },
      "service": {
        "equals": "https"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        15,
        19
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "App servers subnet can connect to database on PostgreSQL port",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      },
      "source_zone": {
        "equals": "app"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "port": {
        "equals": 5432
      },
      "service": {
        "equals": "postgres"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        24,
        27
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "PostgreSQL data directory owned by postgres user with restrictive permissions",
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        13
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "Provision shell users for sudo and developers groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        3,
        8
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "Provision admin users for sudo group on DMZ",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        12,
        16
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "description": "Default deny for all unmatched access requests",
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
      "task": "default-deny",
      "lines": [
        1,
        17
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
      },
      "compliance_tier": {
        "equals": "pci"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 8080
      },
      "service": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
    "id": "rule-003",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "service": {
        "equals": "https"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
      "port": {
        "equals": 5432
      },
      "service": {
        "equals": "postgres"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
[]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The policy governs SSH access, database privileges, network connectivity, filesystem permissions, and user provisioning across the production environment.

## Phase 1: Attribute Catalog

### Subjects

| Attribute | Domain/Values | Source |
|-----------|---------------|--------|
| users | admin, developer, dba | group_vars/all.yml |
| groups | sudo, developers, dba | group_vars/all.yml |
| clearance | secret, confidential | group_vars/all.yml |
| department | operations, engineering, data | group_vars/all.yml |

### Resources

| Attribute | Domain/Values | Source |
|-----------|---------------|--------|
| hosts | proxy01.lab.local (dmz), app01.lab.local (app), db01.lab.local (data) | inventory.ini |
| services | ssh (22/tcp), app (8080/tcp), postgres (5432/tcp), https (443/tcp) | group_vars/*.yml |
| networks | 10.0.1.0/24 (dmz), 10.0.2.0/24 (app), 10.0.3.0/24 (data), 0.0.0.0/0 (internet) | group_vars/*.yml |
| paths | /var/lib/postgresql/data (postgres:postgres, 0700) | roles/db/tasks/main.yml |

### Environment

| Attribute | Value | Source |
|-----------|-------|--------|
| org | segcorp | group_vars/all.yml |
| environment | production | inventory.ini |
| compliance_tier | pci | inventory.ini, group_vars/all.yml |
| retention_days | 365 | group_vars/all.yml |

## Phase 1.5: Vulnerability Assessment

**Status:** Unable to complete - vulnerability search tools returned unexpected response formats.

**Pinned Software Versions:**
- nginx: 1.20.0-1~focal
- openssh: 1:9.1p1-1ubuntu1
- postgresql: 16.2-1.pgdg22.04+1

**Note:** Manual review recommended for these versions against known CVEs.

## Phase 2: Extracted Rules

| Rule ID | Action | Subject | Resource | Effect |
|---------|--------|---------|----------|--------|
| rule-001 | ssh:login | sudo | dmz hosts | permit |
| rule-002 | ssh:login | sudo, developers | appservers | permit |
| rule-003 | ssh:login | sudo, dba | dbservers | permit |
| rule-004 | db:login | dba | postgres (SUPERUSER) | permit |
| rule-005 | db:login | developers | postgres (NOSUPERUSER) | permit |
| rule-006 | network:connect | DMZ subnet → 10.0.1.0/24 | app:8080 | permit |
| rule-007 | network:connect | internet → 0.0.0.0/0 | dmz:443 | permit |
| rule-008 | network:connect | app subnet → 10.0.2.0/24 | db:5432 | permit |
| rule-009 | filesystem:write | all | /var/lib/postgresql/data (0700) | permit |
| rule-010 | user:create | sudo, developers | all zones | permit |
| rule-011 | user:create | sudo | dmz zone | permit |
| rule-012 | * | all | all | deny |

## Phase 3: Normalization

All attributes referenced in rules exist in the Phase 1 catalog. Rules use only the four allowed operators:
- `{"equals": <literal>}` for single-value matches
- `{"any_of": [<literal>, ...]}` for group membership
- `{"applies_to": {"equals": "all"}}` for catch-all rules

## Phase 4: Validation

- **Attributes:** Valid JSON with enumerated domains for enum-typed attributes
- **Rules:** Valid JSON with proper subject_condition/resource_condition/environment_condition structure
- **Effect values:** lowercase "permit" and "deny"
- **Source provenance:** All rules include file, task, and line references

## Security Observations

1. **SSH Hardening:** AllowGroups directives restrict SSH access by group per host zone
2. **Least Privilege:** Developers receive NOSUPERUSER database privileges
3. **Network Segmentation:** DMZ cannot directly reach database servers; only app servers can
4. **PCI-DSS Compliance:** Retention period set to 365 days per PCI requirements
5. **Filesystem Security:** PostgreSQL data directory has restrictive 0700 permissions

## Ambiguities

1. **Vulnerability Assessment:** Search tools returned non-standard response formats; manual CVE review recommended for:
   - nginx 1.20.0 (CVE-2021-23017, CVE-2022-41741)
   - openssh 9.1p1 (CVE-2023-38408, CVE-2023-28531)
   - postgresql 16.2 (check for recent CVEs)

2. **Credentials:** No explicit credential management found in Ansible config; external vault usage implied but not visible

3. **Audit Logging:** Session logging/audit scripts not explicitly defined in role tasks; may exist outside Ansible scope

4. **pg_hba.conf/my.cnf:** Database authentication configs referenced but not fully rendered; network:connect rules capture intent

## Conclusion

The mined ABAC policy captures 12 access control rules covering authentication, database access, network connectivity, and user provisioning. The policy implements defense-in-depth with zone-based segmentation and least-privilege principles appropriate for a PCI-compliant production environment.
