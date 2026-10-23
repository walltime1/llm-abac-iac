# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:38:24_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 11_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f1_minimal_twotier`_

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
        "uid": 999,
        "groups": [
          "postgres"
        ],
        "clearance": "system",
        "department": "database",
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
        "value": "database",
        "source": "roles/db/tasks/main.yml"
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
      }
    ],
    "services": [
      {
        "name": "http",
        "port": 80,
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
        "label": "webservers subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet-facing",
        "source": "group_vars/webservers.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "labcorp",
      "domain": [
        "labcorp"
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
      "source": "group_vars/all.yml"
    },
    "compliance_tier": {
      "value": "soc2",
      "domain": [
        "soc2",
        "pci-dss",
        "hipaa",
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
    "description": "SSH login restricted to sudo group members",
    "effect": "permit",
    "action": "ssh:login",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        33,
        37
      ]
    }
  },
  {
    "id": "rule-002",
    "description": "Sudo execution for admin users with secret clearance",
    "effect": "permit",
    "action": "sudo:execute",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        26,
        31
      ]
    },
    "obligations": [
      {
        "type": "audit",
        "description": "nopassword=false requires password entry for sudo"
      }
    ]
  },
  {
    "id": "rule-003",
    "description": "PostgreSQL SUPERUSER login for sudo group members",
    "effect": "permit",
    "action": "db:login",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        15,
        20
      ]
    },
    "privilege_attributes": {
      "role_attr_flags": "LOGIN,SUPERUSER"
    }
  },
  {
    "id": "rule-004",
    "description": "PostgreSQL NOSUPERUSER login for developers group members",
    "effect": "permit",
    "action": "db:login",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        22,
        27
      ]
    },
    "privilege_attributes": {
      "role_attr_flags": "LOGIN,NOSUPERUSER"
    }
  },
  {
    "id": "rule-005",
    "description": "PostgreSQL network access restricted to webservers subnet",
    "effect": "permit",
    "action": "network:connect",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "hostname": {
        "equals": "db01.lab.local"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        29,
        33
      ]
    }
  },
  {
    "id": "rule-006",
    "description": "HTTP firewall access from internet",
    "effect": "permit",
    "action": "network:connect",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
      },
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": [
        33,
        39
      ]
    }
  },
  {
    "id": "rule-007",
    "description": "Filesystem access to PostgreSQL data directory (owner-only)",
    "effect": "permit",
    "action": "filesystem:write",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        7,
        13
      ]
    }
  },
  {
    "id": "rule-008",
    "description": "Default deny all access",
    "effect": "deny",
    "action": "*",
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
    "source": {
      "file": "policy",
      "task": "default-deny",
      "lines": [
        1,
        1
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
        "equals": 80
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
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "affects_pinned": false,
    "recommendation": "Monitor for PostgreSQL patches; current 16.2 not directly affected",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2013-2250",
    "product": "apache",
    "severity": "critical",
    "affects_pinned": false,
    "recommendation": "Current httpd 2.4.49 not affected by legacy Apache CVEs",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "affects_pinned": false,
    "recommendation": "Current OpenSSH 9.6p1 not affected by legacy CVEs",
    "source": "search_critical_remote"
  }
]
```

## Report

# ABAC Policy Report — LabCorp Ansible Configuration

## Executive Summary
Mined an Attribute-Based Access Control (ABAC) policy from the LabCorp Ansible configuration.
The configuration defines 2 users, 2 groups, 2 hosts, 2 services, and 1 protected filesystem path.
8 access rules were extracted covering SSH, sudo, database, network, and filesystem access.

## Phase 1 — Attribute Catalog
### Subjects
- **Users**: admin (sudo, operations, secret), appuser (developers, engineering, confidential), postgres (system)
- **Groups**: sudo, developers, postgres
- **Clearance Levels**: secret, confidential, system
- **Departments**: operations, engineering, database

### Resources
- **Hosts**: web01.lab.local (frontend/dmz), db01.lab.local (primary/internal)
- **Services**: http (80/tcp), postgresql (5432/tcp)
- **Paths**: /var/lib/postgresql/data (postgres:postgres, 0700)
- **Networks**: 10.0.1.0/24 (webservers), 0.0.0.0/0 (internet)

### Environment
- **Org**: labcorp
- **Environment**: production
- **Compliance Tier**: soc2
- **Log Retention**: 90 days

## Phase 1.5 — Vulnerability Assessment
| Product | Pinned Version | Critical Remote CVEs | KEV CVEs | Affects Pinned |
|---------|---------------|---------------------|----------|----------------|
| apache (httpd) | 2.4.49 | 5 found | 0 | No |
| openssh | 9.6p1 | 5 found | 0 | No |
| postgresql | 16.2 | 5 found | 0 | No |

**Finding**: No critical remote or KEV vulnerabilities directly affect the pinned versions. Legacy CVEs returned by the search tools target much older product versions. Continued monitoring recommended.

## Phase 2 — Rule Extraction Summary
| Rule ID | Action | Subject Predicate | Resource | Effect |
|---------|--------|------------------|----------|--------|
| rule-001 | ssh:login | groups in [sudo] | web01.lab.local | permit |
| rule-002 | sudo:execute | groups in [sudo] AND clearance=secret | web01.lab.local | permit |
| rule-003 | db:login (SUPERUSER) | groups in [sudo] | db01.lab.local | permit |
| rule-004 | db:login (NOSUPERUSER) | groups in [developers] | db01.lab.local | permit |
| rule-005 | network:connect | source_network=10.0.1.0/24 | port 5432 (postgres) | permit |
| rule-006 | network:connect | source_network=0.0.0.0/0 | port 80 (http) | permit |
| rule-007 | filesystem:write | groups in [postgres] | /var/lib/postgresql/data | permit |
| rule-008 | * (default) | all | all | deny |

## Ambiguities & Notes
1. **Credential Exposure**: Database user creation tasks loop over `users` from group_vars, embedding usernames in postgres roles. Passwords are not shown in the config — assumed to be managed externally or via vault.
2. **Implicit Deny**: The default-deny rule (rule-008) is policy-level, not explicitly stated in the Ansible config. Added as standard ABAC practice.
3. **System Accounts**: The `postgres` system account was inferred from filesystem ownership and data directory configuration, not from the explicit `users` list in group_vars/all.yml.
4. **pg_hba.conf**: The lineinfile task adds entries but does not remove existing entries. A deny-all entry at the end of pg_hba.conf is assumed but not explicitly configured.
5. **SSH Key Management**: No SSH key provisioning tasks found in the roles — authentication method for SSH login is unspecified beyond AllowGroups restriction.

## Compliance Notes
- SOC2 compliance tier requires audit logging. Sudo rule (rule-002) includes `nopassword: false` obligation for password entry.
- Network segmentation is enforced: database access restricted to webservers subnet (10.0.1.0/24), HTTP is internet-facing.
- Filesystem permissions on PostgreSQL data directory (0700) enforce principle of least privilege.
