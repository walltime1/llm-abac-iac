# ABAC Policy Mining — goal: all
_Generated: 2026-04-25 12:39:19_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 8 | Rules: 10_  
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
      }
    ],
    "paths": [
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql",
        "source": "group_vars/dbservers.yml"
      },
      {
        "path": "/var/www/html",
        "owner": "www-data",
        "group": "www-data",
        "mode": "0755",
        "service": "nginx",
        "source": "group_vars/webservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers_subnet",
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
    "name": "DB superuser access for sudo group",
    "description": "Users in sudo group get SUPERUSER privileges on PostgreSQL",
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
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privilege": "SUPERUSER",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "10-15"
    }
  },
  {
    "id": "rule-002",
    "name": "DB read-only access for developers",
    "description": "Users in developers group get NOSUPERUSER privileges on PostgreSQL",
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
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privilege": "NOSUPERUSER",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "17-22"
    }
  },
  {
    "id": "rule-003",
    "name": "PostgreSQL network access from webservers",
    "description": "PostgreSQL accepts connections only from webservers subnet (10.0.1.0/24)",
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
      "zone": {
        "equals": "internal"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "24-29"
    }
  },
  {
    "id": "rule-004",
    "name": "Shell user creation for sudo group",
    "description": "Users in sudo group are provisioned with shell access",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "15-21"
    }
  },
  {
    "id": "rule-005",
    "name": "Sudo access for admin users",
    "description": "Users in sudo group with secret clearance get password-required sudo",
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
      "zone": {
        "equals": "dmz"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "privilege": "ALL",
    "nopassword": false,
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "23-29"
    }
  },
  {
    "id": "rule-006",
    "name": "Firewall HTTPS from internet",
    "description": "HTTPS (port 443) is open to all internet traffic on webservers",
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
      "zone": {
        "equals": "dmz"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "31-37"
    }
  },
  {
    "id": "rule-007",
    "name": "SSH access restricted to sudo group",
    "description": "SSH login is restricted to users in the sudo group",
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "39-43"
    }
  },
  {
    "id": "rule-008",
    "name": "Default deny",
    "description": "Default deny rule for all unspecified access",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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

This report documents the ABAC policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a two-tier infrastructure with web servers (DMZ) and database servers (internal zone).

## Infrastructure Overview

### Hosts
| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Environment
- **Organization**: labcorp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Subject Catalog

### Users
| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

### Groups
- `sudo` - Administrative group with elevated privileges
- `developers` - Application development group

## Resource Catalog

### Services
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| nginx | 443 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |

### Filesystem Paths
| Path | Owner | Group | Mode |
|------|-------|-------|------|
| /var/lib/postgresql/data | postgres | postgres | 0700 |
| /var/www/html | www-data | www-data | 0755 |

### Network Zones
| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | webservers_subnet |
| 0.0.0.0/0 | external | internet |

## Extracted ABAC Rules

### Rule 001: DB Superuser Access
- **Effect**: PERMIT
- **Subject**: Users in `sudo` group
- **Resource**: PostgreSQL service (port 5432)
- **Action**: db:login with SUPERUSER privilege
- **Source**: roles/db/tasks/main.yml (lines 10-15)

### Rule 002: DB Read-Only Access
- **Effect**: PERMIT
- **Subject**: Users in `developers` group
- **Resource**: PostgreSQL service (port 5432)
- **Action**: db:login with NOSUPERUSER privilege
- **Source**: roles/db/tasks/main.yml (lines 17-22)

### Rule 003: PostgreSQL Network Access
- **Effect**: PERMIT
- **Subject**: Source network 10.0.1.0/24 (webservers subnet)
- **Resource**: PostgreSQL on internal zone
- **Action**: network:connect
- **Source**: roles/db/tasks/main.yml (lines 24-29)

### Rule 004: Shell User Creation
- **Effect**: PERMIT
- **Subject**: Users in `sudo` group
- **Resource**: Frontend hosts in DMZ
- **Action**: user:create
- **Source**: roles/web/tasks/main.yml (lines 15-21)

### Rule 005: Sudo Access
- **Effect**: PERMIT
- **Subject**: Users in `sudo` group with `secret` clearance
- **Resource**: Frontend hosts in DMZ
- **Action**: sudo:execute (ALL commands, password required)
- **Source**: roles/web/tasks/main.yml (lines 23-29)

### Rule 006: Firewall HTTPS Access
- **Effect**: PERMIT
- **Subject**: Any source (0.0.0.0/0)
- **Resource**: Nginx service on port 443 in DMZ
- **Action**: network:connect
- **Source**: roles/web/tasks/main.yml (lines 31-37)

### Rule 007: SSH Access
- **Effect**: PERMIT
- **Subject**: Users in `sudo` group
- **Resource**: OpenSSH service (port 22)
- **Action**: ssh:login
- **Source**: roles/web/tasks/main.yml (lines 39-43)

### Rule 008: Default Deny
- **Effect**: DENY
- **Subject**: All
- **Resource**: All
- **Action**: *
- **Note**: Implicit default deny for all unspecified access

## Vulnerability Assessment

### Pinned Software Versions
- nginx: 1.27.0-1~noble (2024)
- openssh-server: 1:9.9p1-3ubuntu1 (2024)
- postgresql: 16.4-1.pgdg24.04+1 (2024)

### Findings
**No applicable vulnerabilities found.**

The configuration explicitly states "ALL PATCHED, no applicable CVEs." Vulnerability searches returned historical CVEs (2013-2016) affecting older versions, but the pinned versions (2024) are not affected by these vulnerabilities.

### Searched Products
| Product | Critical Remote CVEs | KEV Entries | Affects Pinned Version |
|---------|---------------------|-------------|----------------------|
| nginx | 5 found (2016) | 0 | No |
| openssh | 5 found (2013-2016) | 0 | No |
| postgresql | 5 found (2013) | 0 | No |

## Security Observations

1. **Defense in Depth**: Database server is in internal zone, only accessible from webservers subnet (10.0.1.0/24)
2. **Least Privilege**: Developers get read-only DB access; only sudo group gets superuser privileges
3. **Access Control**: SSH restricted to sudo group; sudo requires password
4. **Clearance-Based**: Sudo access requires both group membership AND secret clearance level
5. **Internet Exposure**: Only HTTPS (443) is exposed to internet; SSH and DB are internal-only

## Ambiguities

1. **Filesystem ACLs**: The document_root path (/var/www/html) has inferred ownership (www-data) but this is not explicitly defined in the Ansible configuration
2. **Credential Management**: No explicit credential rotation or secrets management policy found in configuration
3. **Audit Logging**: Log retention is set to 90 days, but no specific audit rules were extracted from the configuration

## Files Analyzed

| File | Purpose |
|------|---------|
| inventory.ini | Host definitions and environment variables |
| group_vars/all.yml | Organization-wide variables, users, software versions |
| group_vars/dbservers.yml | Database server configuration |
| group_vars/webservers.yml | Web server configuration |
| roles/db/tasks/main.yml | Database provisioning tasks |
| roles/web/tasks/main.yml | Web server provisioning tasks |

## Conclusion

The mined ABAC policy captures 8 access control rules across database, network, filesystem, and identity management domains. The configuration demonstrates good security practices with proper segmentation, least privilege, and defense in depth. No vulnerabilities were found affecting the pinned software versions.
