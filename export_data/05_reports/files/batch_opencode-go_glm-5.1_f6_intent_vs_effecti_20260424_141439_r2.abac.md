# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 14:44:09_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 18 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "description": "User account name",
      "type": "enum",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "description": "User ID number",
      "type": "integer",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "description": "System groups the user belongs to (set-valued)",
      "type": "enum",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "description": "Security clearance level of the user",
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "description": "Organizational department of the user",
      "type": "enum",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source_zone": {
      "description": "Source network zone for network-layer access rules",
      "type": "enum",
      "domain": [
        "internet",
        "dmz",
        "app",
        "data"
      ],
      "source": "group_vars/appservers.yml"
    },
    "source_network": {
      "description": "Source CIDR network for network-layer access rules",
      "type": "string",
      "source": "group_vars/appservers.yml"
    },
    "user_details": {
      "description": "Per-user attributes from users list",
      "type": "map",
      "entries": [
        {
          "name": "admin",
          "uid": 1001,
          "groups": [
            "sudo"
          ],
          "department": "operations",
          "clearance": "secret"
        },
        {
          "name": "developer",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "department": "engineering",
          "clearance": "confidential"
        },
        {
          "name": "dba",
          "uid": 1003,
          "groups": [
            "dba"
          ],
          "department": "data",
          "clearance": "secret"
        }
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hostname": {
      "description": "Host FQDN from inventory",
      "type": "enum",
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "description": "Network zone of the host",
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "description": "Functional role of the host",
      "type": "enum",
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "description": "Inventory group the host belongs to",
      "type": "enum",
      "domain": [
        "dmz",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "description": "Service name",
      "type": "enum",
      "domain": [
        "ssh",
        "nginx",
        "app",
        "postgresql"
      ],
      "source": "group_vars/dmz.yml"
    },
    "port": {
      "description": "Network port number",
      "type": "integer",
      "source": "group_vars/dmz.yml"
    },
    "path": {
      "description": "Filesystem path",
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "description": "File owner",
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "description": "File group",
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "description": "File permission mode (octal string)",
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "privilege": {
      "description": "Database role privilege level",
      "type": "enum",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "hosts": {
      "description": "Hosts defined in inventory",
      "type": "list",
      "entries": [
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
      ],
      "source": "inventory.ini"
    },
    "services": {
      "description": "Network services exposed by host groups",
      "type": "list",
      "entries": [
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": [
            "dmz",
            "appservers",
            "dbservers"
          ]
        },
        {
          "name": "nginx",
          "port": 443,
          "protocol": "tcp",
          "host_group": [
            "dmz"
          ]
        },
        {
          "name": "app",
          "port": 8080,
          "protocol": "tcp",
          "host_group": [
            "appservers"
          ]
        },
        {
          "name": "postgresql",
          "port": 5432,
          "protocol": "tcp",
          "host_group": [
            "dbservers"
          ]
        }
      ],
      "source": "group_vars/dmz.yml"
    },
    "networks": {
      "description": "Network segments referenced in firewall and pg_hba rules",
      "type": "list",
      "entries": [
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
          "cidr": "0.0.0.0/0",
          "zone": "internet",
          "label": "internet-facing"
        }
      ],
      "source": "group_vars/appservers.yml"
    }
  },
  "environment": {
    "org": {
      "description": "Organization name",
      "type": "enum",
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "description": "Deployment environment",
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "description": "Compliance classification",
      "type": "enum",
      "domain": [
        "pci"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "description": "Default log retention period in days",
      "type": "integer",
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
    "description": "SSH login permitted for sudo group members on DMZ hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "service": {
        "equals": "ssh"
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
      "lines": "24-27"
    }
  },
  {
    "id": "rule-002",
    "description": "SSH login permitted for sudo and developers group members on app hosts",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "service": {
        "equals": "ssh"
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
      "lines": "21-24"
    }
  },
  {
    "id": "rule-003",
    "description": "SSH login permitted for sudo and dba group members on db hosts",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "ssh"
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
      "lines": "32-35"
    }
  },
  {
    "id": "rule-004",
    "description": "Network connect to HTTPS on DMZ hosts permitted from internet",
    "subject_condition": {
      "source_zone": {
        "equals": "internet"
      },
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall - allow HTTPS from internet",
      "lines": "17-22"
    }
  },
  {
    "id": "rule-005",
    "description": "Network connect to app service on app hosts permitted from DMZ subnet",
    "subject_condition": {
      "source_zone": {
        "equals": "dmz"
      },
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
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
      "task": "Firewall - allow app port from DMZ only",
      "lines": "14-19"
    }
  },
  {
    "id": "rule-006",
    "description": "PostgreSQL network connect permitted from appservers subnet",
    "subject_condition": {
      "source_zone": {
        "equals": "app"
      },
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
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
      "lines": "27-30"
    }
  },
  {
    "id": "rule-007",
    "description": "PostgreSQL network connect denied from non-appservers sources (implicit deny-default)",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet (implicit deny)",
      "lines": "27-30"
    }
  },
  {
    "id": "rule-008",
    "description": "DBA group members permitted database login with SUPERUSER privileges",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "postgresql"
      },
      "privilege": {
        "equals": "SUPERUSER"
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "17-20"
    }
  },
  {
    "id": "rule-009",
    "description": "Developer group members permitted database login with NOSUPERUSER privileges",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "postgresql"
      },
      "privilege": {
        "equals": "NOSUPERUSER"
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "22-25"
    }
  },
  {
    "id": "rule-010",
    "description": "DBA group members can read postgres data directory",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "13-18"
    }
  },
  {
    "id": "rule-011",
    "description": "DBA group members can write postgres data directory",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      "lines": "13-18"
    }
  },
  {
    "id": "rule-012",
    "description": "User accounts provisioned for sudo and developers groups on app hosts",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "service": {
        "equals": "ssh"
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
    "action": "identity:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "8-12"
    }
  },
  {
    "id": "rule-013",
    "description": "User accounts provisioned for sudo group members on DMZ hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "service": {
        "equals": "ssh"
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
    "action": "identity:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "13-17"
    }
  },
  {
    "id": "rule-014",
    "description": "Default deny: all access not explicitly permitted is denied",
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
    "id": "rule-016",
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
    "id": "rule-017",
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
    "id": "rule-018",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
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
[
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": true,
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "epss_score": 0.73544,
    "epss_percentile": 0.98816,
    "description": "nginx resolver 1-byte memory overwrite via forged UDP packets from DNS server, allowing remote code execution",
    "recommendation": "Upgrade nginx to 1.21.0+ or apply vendor patch; configure trusted DNS resolvers only",
    "source": "roles/dmz/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx-njs",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "epss_score": null,
    "epss_percentile": null,
    "description": "NGINX njs versions through 0.7.0 out-of-bounds array access; only affects njs module, not base nginx",
    "recommendation": "If njs module is used, upgrade njs to 0.7.1+; otherwise this does not affect base nginx server",
    "source": "roles/dmz/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "pgjdbc",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "epss_score": null,
    "epss_percentile": null,
    "description": "pgjdbc PostgreSQL JDBC Driver SQL injection via preferQueryMode=SIMPLE; affects JDBC driver not server",
    "recommendation": "If JDBC connectivity is used, upgrade pgjdbc to 42.7.2+; PostgreSQL server itself is not affected",
    "source": "roles/db/tasks/main.yml"
  }
]
```

## Report

# ABAC Policy Mining Report — segcorp Ansible Configuration

## Executive Summary

An Attribute-Based Access Control (ABAC) policy was mined from the segcorp Ansible configuration covering **3 inventory hosts** across **3 network zones** (DMZ, App, Data), **3 user roles** (admin, developer, dba), and **4 network services** (nginx/HTTPS, app, PostgreSQL, SSH). The policy comprises **14 rules** including a default-deny catch-all, with **1 high-severity vulnerability** identified affecting the pinned nginx version.

---

## Infrastructure Overview

| Zone | Host | Role | Services |
|------|------|------|----------|
| DMZ | proxy01.lab.local (10.0.1.10) | reverse_proxy | nginx:443, SSH |
| App | app01.lab.local (10.0.2.10) | application | app:8080, SSH |
| Data | db01.lab.local (10.0.3.10) | primary | PostgreSQL:5432, SSH |

### Users

| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

---

## Access Control Rules

### SSH Access
- **DMZ**: Only `sudo` group members may SSH into DMZ hosts (rule-001)
- **App**: `sudo` and `developers` group members may SSH into app hosts (rule-002)
- **Data**: `sudo` and `dba` group members may SSH into db hosts (rule-003)

### Network/Firewall
- **DMZ HTTPS**: Internet (0.0.0.0/0) may connect to nginx:443 on DMZ hosts (rule-004)
- **App Port**: DMZ subnet (10.0.1.0/24) may connect to app:8080 on app hosts (rule-005)
- **DB PostgreSQL**: App subnet (10.0.2.0/24) may connect to PostgreSQL:5432 on db hosts (rule-006)
- **DB PostgreSQL DENY**: All other sources denied PostgreSQL access (rule-007, implicit deny-default)

### Database Authentication
- **DBA**: dba group members granted LOGIN+SUPERUSER on PostgreSQL (rule-008)
- **Developers**: developers group members granted LOGIN+NOSUPERUSER on PostgreSQL (rule-009)

### Filesystem
- **PostgreSQL data dir** (`/var/lib/postgresql/data`, mode 0700, owner postgres): dba group members may read/write (rules 010-011)

### Identity Management
- **App hosts**: Users in sudo or developers groups are provisioned shell accounts (rule-012)
- **DMZ hosts**: Only users in sudo group are provisioned shell accounts (rule-013)

### Default Deny
- All access not explicitly permitted is denied (rule-014)

---

## Vulnerability Assessment

### Pinned Software Versions
| Package | Version |
|---------|----------|
| nginx | 1.20.0-1~focal |
| openssh-server | 1:9.1p1-1ubuntu1 |
| postgresql-16 | 16.2-1.pgdg22.04+1 |

### Findings

| CVE | Product | Severity | CVSS | Affects Pinned? | Recommendation |
|-----|---------|----------|------|-----------------|----------------|
| CVE-2021-23017 | nginx | High | 7.7 | **Yes** (nginx <1.21.0) | Upgrade to nginx 1.21.0+ or apply vendor patch |
| CVE-2021-46461 | nginx-njs | Critical | 9.8 | No (njs module only) | Upgrade njs if module is used |
| CVE-2024-1597 | pgjdbc | Critical | 9.8 | No (JDBC driver only) | Upgrade pgjdbc if JDBC is used |

**Key Finding**: CVE-2021-23017 (EPSS 73.5%, 9 PoCs available) directly affects the pinned nginx 1.20.0 version. This DNS resolver vulnerability allows remote code execution via forged UDP packets. **Immediate remediation recommended**: upgrade nginx to 1.21.0 or later.

---

## Ambiguities and Gaps

1. **No explicit sudoers configuration**: The `sudo` group is referenced in SSH AllowGroups and user provisioning, but no sudoers file configuration was found. The actual sudo privileges (NOPASSWD vs password) are undefined.
2. **Database authorization granularity**: Developers receive LOGIN+NOSUPERUSER but no specific database/schema privileges are defined. It is unclear whether developers can access all schemas or only specific ones.
3. **pg_hba authentication method**: The pg_hba configuration uses `scram-sha-256` but no explicit DENY rules are defined; the deny rule (rule-007) is inferred from the deny-default semantics of pg_hba.
4. **Credentials management**: No vault or secret management configuration was found; database user passwords and SSH keys are not explicitly managed in the Ansible configuration.
5. **No monitoring/logging configuration**: No audit, logging, or session recording obligations were found in the Ansible configuration, which is notable given the PCI compliance tier.
6. **Network topology gaps**: The firewall rules do not explicitly address SSH network restrictions (only AllowGroups is configured); SSH is assumed reachable from any network that can reach the host.
7. **Developer DB access path**: Developers can SSH to app hosts (rule-002) and from app subnet connect to PostgreSQL (rule-006), but there is no explicit rule for developers connecting directly to the database host via SSH.

---

## Policy Completeness

- **Total rules**: 14 (13 explicit + 1 default-deny)
- **Permit rules**: 12
- **Deny rules**: 2 (1 explicit deny for pg_hba, 1 default-deny)
- **Obligations**: None found in configuration
- **Coverage**: SSH access, network/firewall, database authentication, filesystem ACL, identity provisioning
