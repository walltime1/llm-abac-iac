# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:49:06_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 16 | Rules: 14_  
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
    "groups": [
      "sudo",
      "developers"
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
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "roles/db/tasks/main.yml"
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
      },
      {
        "path": "/etc/postgresql/pg_hba.conf",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "sshd",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "path": "/var/www/html",
        "owner": "root",
        "group": "root",
        "mode": "0755",
        "service": "nginx",
        "source": "group_vars/webservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "internal",
        "label": "webservers-subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      }
    ]
  },
  "environment": {
    "org": "labcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "effect": "permit",
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
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "obligations": [],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        42,
        45
      ]
    }
  },
  {
    "id": "rule-002",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
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
    "action": "sudo:execute",
    "obligations": [],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        34,
        40
      ]
    }
  },
  {
    "id": "rule-003",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
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
    "action": "user:create",
    "obligations": [],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        24,
        32
      ]
    }
  },
  {
    "id": "rule-004",
    "effect": "permit",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "obligations": [],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        47,
        53
      ]
    }
  },
  {
    "id": "rule-005",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
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
    "action": "db:login",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        15,
        20
      ]
    }
  },
  {
    "id": "rule-006",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
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
    "action": "db:login",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        22,
        27
      ]
    }
  },
  {
    "id": "rule-007",
    "effect": "permit",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "obligations": [],
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
    "id": "rule-008",
    "effect": "deny",
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
    "obligations": [],
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
    "id": "rule-009",
    "effect": "permit",
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
    "obligations": [],
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
    "id": "rule-010",
    "effect": "permit",
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
    "obligations": [],
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
    "id": "rule-011",
    "effect": "deny",
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
    "obligations": [],
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
        "equals": "webservers"
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
    "cve_id": "N/A",
    "product": "all",
    "pinned_version": "nginx 1.27.0, openssh 9.9p1, postgresql 16.4",
    "cvss_score": 0,
    "severity": "info",
    "affects_pinned_version": false,
    "source": "assessment",
    "recommendation": "All pinned package versions are current and not affected by known critical/remote or KEV vulnerabilities."
  }
]
```

## Report

# ABAC Policy Report — labcorp/production

## Overview
- **Organization**: labcorp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Policy Goal**: all (full coverage)

## Attribute Catalog

### Subjects
| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

**Groups**: sudo, developers  
**Clearance Levels**: secret, confidential  
**Departments**: operations, engineering

### Resources
| Host | IP | Role | Zone | Group |
|------|----|------|------|-------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| nginx | 443 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |

| Path | Owner | Group | Mode | Service |
|------|-------|-------|------|---------|
| /var/lib/postgresql/data | postgres | postgres | 0700 | postgresql |
| /etc/postgresql/pg_hba.conf | root | root | 0644 | postgresql |
| /etc/ssh/sshd_config | root | root | 0644 | sshd |
| /var/www/html | root | root | 0755 | nginx |

| Network CIDR | Zone | Label |
|--------------|------|-------|
| 10.0.1.0/24 | internal | webservers-subnet |
| 0.0.0.0/0 | external | internet |

## Rules Summary (11 rules)

| ID | Action | Effect | Subject | Resource | Source |
|----|--------|--------|---------|----------|--------|
| rule-001 | ssh:login | permit | groups in [sudo] | service=sshd, port=22 | roles/web/tasks/main.yml |
| rule-002 | sudo:execute | permit | groups in [sudo] AND clearance=secret | role=frontend | roles/web/tasks/main.yml |
| rule-003 | user:create | permit | groups in [sudo] | role=frontend | roles/web/tasks/main.yml |
| rule-004 | network:connect | permit | source_network=0.0.0.0/0 | service=nginx, port=443 | roles/web/tasks/main.yml |
| rule-005 | db:login | permit | groups in [sudo] | service=postgresql, port=5432 | roles/db/tasks/main.yml |
| rule-006 | db:login | permit | groups in [developers] | service=postgresql, port=5432 | roles/db/tasks/main.yml |
| rule-007 | network:connect | permit | source_network=10.0.1.0/24 | service=postgresql, port=5432 | roles/db/tasks/main.yml |
| rule-008 | network:connect | deny | all | service=postgresql, port=5432 | roles/db/tasks/main.yml |
| rule-009 | filesystem:read | permit | group=postgres | path=/var/lib/postgresql/data, mode=0700 | roles/db/tasks/main.yml |
| rule-010 | filesystem:write | permit | group=postgres | path=/var/lib/postgresql/data, mode=0700 | roles/db/tasks/main.yml |
| rule-011 | * | deny | all | all | policy (default) |

## Vulnerability Assessment

Pinned package versions:
- **nginx**: 1.27.0-1~noble
- **openssh**: 1:9.9p1-3ubuntu1
- **postgresql**: 16.4-1.pgdg24.04+1

**Result**: All pinned versions are current and not affected by any known critical/remote or KEV (Known Exploited Vulnerability) CVEs. 23 unique CVEs were evaluated across the three packages; all target older or unrelated product components.

## Ambiguities

1. **No explicit credential handling** detected in the Ansible configuration. Database passwords and SSH keys are not provisioned by these playbooks. Assume external credential management (e.g., Ansible Vault or secrets manager) is in use but not visible here.
2. **No session logging / audit obligations** found in the role task files. The `default_log_retention_days: 90` is defined in `group_vars/all.yml` but no concrete audit tasks were emitted.
3. **pg_hba.conf** is managed via `lineinfile` rather than a dedicated template. Implicit deny is assumed by PostgreSQL's default behavior (last match wins), but the exact `pg_hba.conf` contents are not fully declared in the playbook.
4. **Filesystem mode** for `/etc/ssh/sshd_config` and `/etc/postgresql/pg_hba.conf` are not explicitly set in the tasks; assumed defaults (0644) are inferred.
5. **PostgreSQL superuser role** is granted with `LOGIN,SUPERUSER` — this grants full database control. The read-only role uses `LOGIN,NOSUPERUSER` with no explicit privilege restrictions beyond NOSUPERUSER (e.g., no `NOCREATEDB`/`NOCREATEROLE` flags).
