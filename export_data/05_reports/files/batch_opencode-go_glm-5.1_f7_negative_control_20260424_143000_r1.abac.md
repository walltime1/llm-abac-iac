# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 14:45:15_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 9 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "type": "enum",
      "domain": [
        "admin",
        "appuser",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers"
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
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "source_ip": {
      "type": "cidr",
      "source": "group_vars/dbservers.yml"
    },
    "source_network": {
      "type": "cidr",
      "source": "group_vars/dbservers.yml"
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal",
        "internet",
        "internet"
      ],
      "source": "inventory.ini"
    }
  },
  "resources": {
    "hostname": {
      "type": "enum",
      "domain": [
        "web01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "ip",
      "source": "inventory.ini"
    },
    "role": {
      "type": "enum",
      "domain": [
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "webservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "openssh-server",
        "postgresql"
      ],
      "source": "group_vars/all.yml"
    },
    "port": {
      "type": "integer",
      "source": "group_vars/webservers.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp",
        "udp"
      ],
      "source": "group_vars/webservers.yml"
    },
    "path": {
      "type": "string",
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
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "enum",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "privilege_level": {
      "type": "enum",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "enum",
      "domain": [
        "labcorp"
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
        "soc2"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
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
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "openssh-server"
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
        28,
        30
      ]
    }
  },
  {
    "id": "rule-002",
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
        "description": "nopassword=false",
        "source": "roles/web/tasks/main.yml"
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        21,
        24
      ]
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "source_zone": {
        "equals": "internet"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      },
      "service": {
        "equals": "nginx"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall - allow HTTPS from internet",
      "lines": [
        26,
        31
      ]
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
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
        23,
        26
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        23,
        26
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "privilege_level": {
        "equals": "SUPERUSER"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        11,
        14
      ]
    }
  },
  {
    "id": "rule-007",
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
      "privilege_level": {
        "equals": "NOSUPERUSER"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        16,
        19
      ]
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "user": {
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
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        7,
        12
      ]
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "user": {
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        7,
        12
      ]
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "user": {
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        7,
        12
      ]
    }
  },
  {
    "id": "rule-011",
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
        17
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
    "action": "filesystem:read",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "mode 0700 non-owner deny",
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
    "action": "filesystem:read",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "mode 0700 non-owner deny",
      "lines": "N/A"
    }
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.27.0 is not affected; CVE from 2016, status=rejected"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.27.0 is not affected; CVE predates 1.27.0 release"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.27.0 is not affected; CVE from 2017"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "cvss_score": 7.7,
    "severity": "high",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.27.0 is not affected; CVE patched in earlier releases"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.9p1 is not affected; CVE from 2003"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.9p1 is not affected; CVE from 2000"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.4",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.4 is not affected; CVE from 2007"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.4",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.4 is not affected; CVE patched before 16.4 release"
  }
]
```

## Report

# ABAC Policy Mining Report — LabCorp Ansible Configuration

## 1. Executive Summary

An Attribute-Based Access Control (ABAC) policy was mined from an Ansible configuration comprising an inventory file, three group variable files, and two role task files (web and db). The policy captures **12 rules** governing SSH access, sudo privileges, firewall rules, database authentication, filesystem permissions, and user provisioning across a production environment segmented into DMZ (webservers) and internal (dbservers) zones.

## 2. Attribute Catalog

### 2.1 Subject Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| user | enum | admin, appuser, postgres | group_vars/all.yml |
| uid | integer | — | group_vars/all.yml |
| groups | set | sudo, developers | group_vars/all.yml |
| clearance | enum | secret, confidential | group_vars/all.yml |
| department | enum | operations, engineering | group_vars/all.yml |
| source_ip | cidr | — | group_vars/dbservers.yml |
| source_network | cidr | — | group_vars/dbservers.yml |
| source_zone | enum | dmz, internal, internet | inventory.ini |

### 2.2 Resource Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| hostname | enum | web01.lab.local, db01.lab.local | inventory.ini |
| ip | ip | — | inventory.ini |
| role | enum | frontend, primary | inventory.ini |
| zone | enum | dmz, internal | inventory.ini |
| host_group | enum | webservers, dbservers, prod | inventory.ini |
| service | enum | nginx, openssh-server, postgresql | group_vars/all.yml |
| port | integer | — | group_vars/webservers.yml |
| protocol | enum | tcp, udp | group_vars/webservers.yml |
| path | string | — | group_vars/dbservers.yml |
| owner | enum | postgres | roles/db/tasks/main.yml |
| group | enum | postgres | roles/db/tasks/main.yml |
| mode | string | — | roles/db/tasks/main.yml |
| database | enum | all | roles/db/tasks/main.yml |
| privilege_level | enum | SUPERUSER, NOSUPERUSER | roles/db/tasks/main.yml |

### 2.3 Environment Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| org | enum | labcorp | group_vars/all.yml |
| environment | enum | production | inventory.ini |
| compliance_tier | enum | soc2 | group_vars/all.yml |
| default_log_retention_days | integer | — | group_vars/all.yml |

## 3. Extracted Rules

| Rule ID | Effect | Action | Subject Condition | Resource Condition | Source |
|---------|--------|--------|-------------------|-------------------|--------|
| rule-001 | permit | ssh:login | groups any_of [sudo] | host_group=webservers, service=openssh-server | roles/web/tasks/main.yml |
| rule-002 | permit | sudo:execute | groups any_of [sudo], clearance=secret | host_group=webservers | roles/web/tasks/main.yml |
| rule-003 | permit | network:connect | source_zone=internet | host_group=webservers, port=443, service=nginx | roles/web/tasks/main.yml |
| rule-004 | permit | network:connect | source_network=10.0.1.0/24 | host_group=dbservers, service=postgresql, port=5432 | roles/db/tasks/main.yml |
| rule-005 | deny | network:connect | applies_to=all | host_group=dbservers, service=postgresql, port=5432 | roles/db/tasks/main.yml |
| rule-006 | permit | db:login | groups any_of [sudo] | host_group=dbservers, service=postgresql, privilege_level=SUPERUSER | roles/db/tasks/main.yml |
| rule-007 | permit | db:login | groups any_of [developers] | host_group=dbservers, service=postgresql, privilege_level=NOSUPERUSER | roles/db/tasks/main.yml |
| rule-008 | permit | filesystem:read | user=postgres | path=/var/lib/postgresql/data, mode=0700, host_group=dbservers | roles/db/tasks/main.yml |
| rule-009 | permit | filesystem:write | user=postgres | path=/var/lib/postgresql/data, mode=0700, host_group=dbservers | roles/db/tasks/main.yml |
| rule-010 | permit | filesystem:execute | user=postgres | path=/var/lib/postgresql/data, mode=0700, host_group=dbservers | roles/db/tasks/main.yml |
| rule-011 | permit | user:create | groups any_of [sudo] | host_group=webservers | roles/web/tasks/main.yml |
| rule-012 | deny | * | applies_to=all | applies_to=all | implicit |

**Obligations:** Rule-002 (sudo:execute) carries an obligation requiring `nopassword=false`, meaning password authentication is required for sudo usage.

## 4. Vulnerability Assessment

Pinned software versions in the configuration:
- **nginx** 1.27.0
- **openssh-server** 9.9p1
- **postgresql** 16.4

All three packages are recent, patched versions. The Ansible configuration explicitly states "ALL PATCHED, no applicable CVEs." Vulnerability scans confirmed that available critical/high remote CVEs (e.g., CVE-2016-0746, CVE-2003-0786, CVE-2007-3279) are from 2000–2016 and do not affect these pinned versions. **No applicable vulnerabilities were found.**

## 5. Security Observations

1. **SSH restricted to sudo group only** (AllowGroups sudo) — developers group is explicitly excluded from SSH login on webservers.
2. **PostgreSQL access is network-segmented** — only connections from the 10.0.1.0/24 subnet (webservers) are permitted (rule-004), with an explicit deny for all other sources (rule-005).
3. **Webservers are internet-facing** — firewall allows HTTPS from 0.0.0.0/0, appropriate for a DMZ frontend but note the broad source range.
4. **Mode 0700 on PostgreSQL data directory** restricts access to the postgres OS user only.
5. **Sudo requires password** (nopassword=false obligation on rule-002), which is a good security practice.

## 6. Ambiguities

1. **`postgres` user not in users list** — The filesystem rules reference `postgres` as the owner/user, but `postgres` is not defined in the `users` list in `group_vars/all.yml`. It is assumed to be a service account created by the PostgreSQL installation.
2. **`appuser` lacks SSH access** — The `appuser` is in the `developers` group but is never provisioned on webservers (the provisioning task filters for `sudo` group members only). This may be intentional or may indicate missing configuration.
3. **Firewall rule source 0.0.0.0/0** — The webservers firewall allows HTTPS from all IPs. If a more restrictive source range was intended, it should be specified in `group_vars/webservers.yml`.
4. **No DB access for developers** — Developers get NOSUPERUSER login to PostgreSQL (rule-007), but only from permitted networks (10.0.1.0/24). Since developers cannot SSH to webservers, they would need another path to reach the database, which is not defined in this configuration.
5. **No explicit SELinux or iptables rules** found in this configuration.
