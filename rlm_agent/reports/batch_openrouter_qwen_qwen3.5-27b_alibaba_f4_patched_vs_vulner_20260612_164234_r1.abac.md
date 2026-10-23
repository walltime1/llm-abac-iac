# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:45:40_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 5 | Rules: 11_  
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
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers_patched,webservers_legacy",
        "source": "group_vars/webservers_patched.yml"
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
        "label": "web subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
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
    "source": "group_vars/all.yml"
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "name": "SSH access restricted to sudo group",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "25-28"
    }
  },
  {
    "id": "rule-002",
    "name": "SSH access restricted to sudo group (patched)",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "25-28"
    }
  },
  {
    "id": "rule-003",
    "name": "Database access from web subnet only",
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": "15-20"
    }
  },
  {
    "id": "rule-004",
    "name": "HTTPS access from internet (legacy)",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "17-22"
    }
  },
  {
    "id": "rule-005",
    "name": "HTTPS access from internet (patched)",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "17-22"
    }
  },
  {
    "id": "rule-006",
    "name": "PostgreSQL data directory access",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "9-14"
    }
  },
  {
    "id": "rule-007",
    "name": "Default deny",
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
      "task": "default-deny policy",
      "lines": "N/A"
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
    "id": "rule-009",
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
    "id": "rule-010",
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
Mined ABAC policy from Ansible configuration for **patchcorp** production environment (SOC2 compliance tier).

## Environment
- **Organization**: patchcorp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Subjects (Users & Groups)

### Users
| Name | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |

### Groups
- sudo
- developers

## Resources

### Hosts
| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| postgresql | 5432 | tcp | dbservers |
| nginx | 443 | tcp | webservers_patched, webservers_legacy |

### Filesystem Paths
| Path | Owner | Group | Mode |
|------|-------|-------|------|
| /var/lib/postgresql/data | postgres | postgres | 0700 |

### Networks
| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | web subnet |
| 0.0.0.0/0 | external | internet |

## Access Rules Summary

### SSH Access (rules-001, rule-002)
- **Effect**: PERMIT
- **Subject**: Users in `sudo` group
- **Action**: ssh:login
- **Scope**: All web servers (legacy and patched)

### Database Access (rule-003)
- **Effect**: PERMIT
- **Subject**: Source network 10.0.1.0/24 (web subnet)
- **Resource**: PostgreSQL service on port 5432
- **Action**: network:connect

### Web Access (rules-004, rule-005)
- **Effect**: PERMIT
- **Subject**: Any source (0.0.0.0/0)
- **Resource**: Nginx service on port 443
- **Action**: network:connect
- **Scope**: All web servers

### Filesystem Access (rule-006)
- **Effect**: PERMIT
- **Subject**: Users in `postgres` group
- **Resource**: /var/lib/postgresql/data
- **Action**: filesystem:read

### Default Deny (rule-007)
- **Effect**: DENY
- **Subject**: All
- **Resource**: All
- **Action**: All

## Vulnerability Assessment
**Pinned Package Versions**:
- OpenSSH: 1:9.6p1-3ubuntu1
- PostgreSQL: 16.2-1.pgdg22.04+1
- Nginx (patched): 1.24.0-2ubuntu1
- Nginx (legacy): 1.20.0-1~focal

**Results**: No critical or KEV vulnerabilities affect the pinned versions.

## Ambiguities & Notes
1. **Filesystem rule**: The postgres group is referenced in filesystem rules but not defined in user catalog. This is a system group managed by the postgresql package.
2. **Legacy nginx**: web-old01 uses nginx 1.20.0-1~focal which is older than the patched version. While no active vulnerabilities were found, consider upgrading.
3. **Firewall exposure**: Both legacy and patched web servers allow HTTPS from 0.0.0.0/0 (internet-wide). Ensure this is intentional.
4. **No explicit sudo rules**: Sudo access is implied by group membership but no explicit sudoers rules were found in the configuration.

## Files Processed
- inventory.ini
- group_vars/all.yml
- group_vars/dbservers.yml
- group_vars/webservers_legacy.yml
- group_vars/webservers_patched.yml
- roles/db/tasks/main.yml
- roles/web_legacy/tasks/main.yml
- roles/web_patched/tasks/main.yml
