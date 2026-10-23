# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 13:49:43_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 16 | Rules: 20_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f2_threetier_segmented`_

## Attributes

```json
{
  "subject": {
    "user": {
      "type": "enum",
      "domain": [
        "admin",
        "developer",
        "dba",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "domain": null,
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "enum",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source_ip": {
      "type": "string",
      "domain": null,
      "source": "group_vars/appservers.yml"
    },
    "source_network": {
      "type": "string",
      "domain": null,
      "source": "group_vars/appservers.yml"
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data",
        "internet"
      ],
      "source": "inventory.ini"
    }
  },
  "resource": {
    "hostname": {
      "type": "enum",
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "domain": null,
      "source": "inventory.ini"
    },
    "role": {
      "type": "enum",
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "ssh",
        "postgresql",
        "app"
      ],
      "source": "group_vars/all.yml"
    },
    "port": {
      "type": "integer",
      "domain": null,
      "source": "group_vars/appservers.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp",
        "udp",
        "icmp"
      ],
      "source": "group_vars/all.yml"
    },
    "path": {
      "type": "string",
      "domain": null,
      "source": "group_vars/dbservers.yml"
    },
    "owner": {
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "domain": null,
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "enum",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "enum",
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "enum",
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "integer",
      "domain": null,
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
    "description": "Users in sudo group can SSH to DMZ hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        26,
        29
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-002",
    "description": "Users in sudo or developers groups can SSH to app hosts",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        21,
        23
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-003",
    "description": "Users in sudo or dba groups can SSH to DB hosts",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        34,
        36
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-004",
    "description": "Allow HTTPS from internet to DMZ proxy",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      },
      "source_zone": {
        "equals": "internet"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall - allow HTTPS from internet",
      "lines": [
        18,
        23
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-005",
    "description": "Allow app port from DMZ subnet to app servers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      },
      "source_zone": {
        "equals": "dmz"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall - allow app port from DMZ only",
      "lines": [
        14,
        19
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-006",
    "description": "Allow PostgreSQL connections from appservers subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      },
      "source_zone": {
        "equals": "app"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        27,
        29
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-007",
    "description": "Deny PostgreSQL connections from non-appservers subnets (implicit pg_hba deny)",
    "subject_condition": {
      "source_zone": {
        "in": [
          "dmz",
          "data",
          "internet"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet (implicit deny)",
      "lines": [
        27,
        29
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-008",
    "description": "DBA users get SUPERUSER access to PostgreSQL",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        16,
        19
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-009",
    "description": "Developer users get NOSUPERUSER read-only access to PostgreSQL",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        21,
        24
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-010",
    "description": "Postgres user can read/write/execute the postgres data directory",
    "subject_condition": {
      "user": {
        "equals": "postgres"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
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
    "action": "filesystem:read",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        11,
        16
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-011",
    "description": "Postgres user can write the postgres data directory",
    "subject_condition": {
      "user": {
        "equals": "postgres"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
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
    "action": "filesystem:write",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        11,
        16
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-012",
    "description": "Postgres user can execute/traverse the postgres data directory",
    "subject_condition": {
      "user": {
        "equals": "postgres"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
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
    "action": "filesystem:execute",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        11,
        16
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-013",
    "description": "Users in sudo or developers groups can be created on app servers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        7,
        12
      ]
    }
  },
  {
    "id": "rule-014",
    "description": "Users in sudo group can be created on DMZ hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        12,
        17
      ]
    }
  },
  {
    "id": "rule-015",
    "description": "Default deny - all access not explicitly permitted is denied",
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
    "obligations": [],
    "source": {
      "file": "system",
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
      "host_group": {
        "equals": "dbservers"
      },
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
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
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
    "id": "rule-018",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
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
    "id": "rule-019",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
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
    "id": "rule-020",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
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
    "pinned_version": "1.20.0",
    "cvss_score": 7.7,
    "severity": "high",
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "nginx resolver 1-byte memory overwrite from forged DNS UDP packets, affects nginx 1.20.0",
    "recommendation": "Upgrade nginx from 1.20.0 to 1.20.1+ or 1.21.0+ which contain the patch for CVE-2021-23017"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "13.7",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL 8.1+ with plpgsql grants privileges to PUBLIC, potentially affects PG 13.7",
    "recommendation": "Review plpgsql language permissions and revoke excessive PUBLIC grants; consider upgrading to latest PostgreSQL 13.x patch release"
  }
]
```

## Report

# ABAC Policy Mining Report — Ansible Configuration

## Overview

This report presents an Attribute-Based Access Control (ABAC) policy mined from an Ansible configuration managing a three-tier infrastructure (DMZ, Application, Database) in a PCI-compliant production environment for **segcorp**.

## Attribute Catalog

### Subject Attributes
| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| user | enum | admin, developer, dba, postgres | group_vars/all.yml |
| uid | integer | — | group_vars/all.yml |
| groups | set | sudo, developers, dba | group_vars/all.yml |
| clearance | enum | secret, confidential | group_vars/all.yml |
| department | enum | operations, engineering, data | group_vars/all.yml |
| source_ip | string | — | group_vars/appservers.yml |
| source_network | string | — | group_vars/appservers.yml |
| source_zone | enum | dmz, app, data, internet | inventory.ini |

### Resource Attributes
| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| hostname | enum | proxy01.lab.local, app01.lab.local, db01.lab.local | inventory.ini |
| ip | string | — | inventory.ini |
| role | enum | reverse_proxy, application, primary | inventory.ini |
| zone | enum | dmz, app, data | inventory.ini |
| host_group | enum | dmz, appservers, dbservers, prod | inventory.ini |
| service | enum | nginx, ssh, postgresql, app | group_vars/all.yml |
| port | integer | — | group_vars/appservers.yml |
| protocol | enum | tcp, udp, icmp | group_vars/all.yml |
| path | string | — | group_vars/dbservers.yml |
| owner | enum | postgres | roles/db/tasks/main.yml |
| group | enum | postgres | roles/db/tasks/main.yml |
| mode | string | — | roles/db/tasks/main.yml |
| database | enum | all | roles/db/tasks/main.yml |

### Environment Attributes
| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| org | enum | segcorp | group_vars/all.yml |
| environment | enum | production | inventory.ini |
| compliance_tier | enum | pci | group_vars/all.yml |
| default_log_retention_days | integer | — | group_vars/all.yml |

## Extracted Rules

### User Account Provisioning
- **rule-013**: Users in `sudo` or `developers` groups → user:create on app servers
- **rule-014**: Users in `sudo` group → user:create on DMZ hosts

### SSH Access Control (AllowGroups)
- **rule-001**: Users in `sudo` group → SSH to DMZ hosts
- **rule-002**: Users in `sudo` or `developers` groups → SSH to app hosts
- **rule-003**: Users in `sudo` or `dba` groups → SSH to DB hosts

### Network Firewall Rules
- **rule-004**: Internet (0.0.0.0/0) → HTTPS (443/tcp) to DMZ proxy
- **rule-005**: DMZ subnet (10.0.1.0/24) → app port (8080/tcp) to app servers
- **rule-006**: App subnet (10.0.2.0/24) → PostgreSQL (5432/tcp) to DB servers
- **rule-007**: DENY non-app subnets → PostgreSQL (5432/tcp) to DB servers (implicit pg_hba deny)

### Database Access Control
- **rule-008**: DBA group → SUPERUSER login to PostgreSQL
- **rule-009**: Developers group → NOSUPERUSER login to PostgreSQL

### Filesystem Access Control
- **rule-010**: Postgres user → filesystem:read on /var/lib/postgresql/data (0700)
- **rule-011**: Postgres user → filesystem:write on /var/lib/postgresql/data (0700)
- **rule-012**: Postgres user → filesystem:execute on /var/lib/postgresql/data (0700)

### Default Deny
- **rule-015**: Default deny — all access not explicitly permitted is denied

## Vulnerability Assessment

### Pinned Package Versions
| Package | Pinned Version |
|---------|---------------|
| nginx | 1.20.0-1~focal |
| openssh-server | 1:9.6p1-3ubuntu1 |
| postgresql-13 | 13.7-1.pgdg20.04+1 |

### CVEs Affecting Pinned Versions

| CVE | Product | Pinned | CVSS | Severity | Remote | Description |
|-----|---------|--------|------|----------|--------|-------------|
| CVE-2021-23017 | nginx | 1.20.0 | 7.7 | high | Yes | DNS resolver 1-byte overwrite via forged UDP packets |
| CVE-2007-3279 | postgresql | 13.7 | 10.0 | critical | Yes | plpgsql grants excessive privileges to PUBLIC |

**CVE-2021-23017** (nginx): The DNS resolver in nginx 1.20.0 contains a 1-byte memory overwrite vulnerability exploitable via forged DNS UDP packets. Patched in nginx 1.20.1 and 1.21.0.

**CVE-2007-3279** (PostgreSQL): The plpgsql language grants privileges to PUBLIC by default in PostgreSQL 8.1+. While very old, the underlying pattern of excessive PUBLIC grants may persist in PostgreSQL 13.7 depending on configuration.

### Recommendations
1. Upgrade nginx from 1.20.0 to at least 1.20.1 to address CVE-2021-23017.
2. Review and restrict plpgsql PUBLIC grants in PostgreSQL; upgrade to latest 13.x patch release.
3. OpenSSH 9.6p1 and the older PostgreSQL CVEs do not affect the pinned versions but should be monitored.

## Ambiguities

1. **DBA OS account missing on dbservers**: AllowGroups on dbservers includes `dba`, but the Ansible roles do not provision OS accounts for dba-group users on any host. The dba user may not be able to SSH despite the AllowGroups configuration unless accounts are created by other means.
2. **Postgres system user**: The `postgres` OS user is implicitly created by the PostgreSQL package installation but is not defined in the Ansible `users` list. Filesystem rules for the data directory reference this system user.
3. **Firewall implicit deny**: The firewalld rules only define `enabled` entries; implicit deny for all other traffic is assumed but not explicitly stated in the configuration.
4. **pg_hba deny-default**: Only the app subnet (10.0.2.0/24) is explicitly allowed; all other sources are implicitly denied by pg_hba.conf's default behavior.
5. **Developer DB privilege scope**: The `NOSUPERUSER` role for developers allows login but does not explicitly define which tables/schemas they can access; the Ansible config only creates the user role without GRANT statements.
6. **No sudoers configuration**: While `sudo` is a defined group, there is no explicit sudoers file configuration in the Ansible roles. Sudo access is assumed from group membership.
7. **No credential/secrets management**: Database passwords and SSH keys are not managed by the Ansible configuration, which is a security gap for a PCI environment.
8. **Nginx njs module (CVE-2021-46461)**: The vulnerability affects the optional njs module; it is unclear whether njs is installed alongside nginx 1.20.0.
