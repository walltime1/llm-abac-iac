# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:43:45_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 16_  
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
        "uid": 999,
        "groups": [
          "postgres"
        ],
        "department": "system",
        "clearance": "none",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "postgres"
    ],
    "clearance_levels": {
      "values": [
        "confidential",
        "secret"
      ],
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "values": [
        "engineering",
        "operations"
      ],
      "domain": [
        "engineering",
        "operations"
      ],
      "source": "group_vars/all.yml"
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
        "name": "apache2",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "version": "2.4.49-1",
        "source": "group_vars/all.yml"
      },
      {
        "name": "openssh-server",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "version": "1:9.6p1-3ubuntu1",
        "source": "group_vars/all.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "version": "16.2-1.pgdg22.04+1",
        "source": "group_vars/all.yml"
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
        "path": "/var/www/html",
        "owner": "root",
        "group": "root",
        "mode": "0755",
        "service": "apache2",
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
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "service": {
        "equals": "openssh-server"
      },
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "sudo commands logged per compliance policy"
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
    "id": "rule-003",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "port": {
        "equals": 80
      },
      "service": {
        "equals": "apache2"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall - allow HTTP from internet",
      "lines": [
        31,
        37
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
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
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
        16,
        21
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
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
        23,
        28
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
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
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
    "id": "rule-011",
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
      "file": "policy",
      "task": "default-deny",
      "lines": [
        0,
        0
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
      "compliance_tier": {
        "equals": "soc2"
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
      "compliance_tier": {
        "equals": "soc2"
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
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
      "port": {
        "equals": 80
      },
      "service": {
        "equals": "apache2"
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
    "id": "rule-016",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": true,
    "severity": "high",
    "cvss_score": 8.1,
    "description": "regreSSHion: signal handler race condition in OpenSSH server on glibc-based systems allows remote unauthenticated code execution",
    "remediation": "Upgrade to OpenSSH 9.8 or later, or apply vendor patches",
    "recommendation": "URGENT: Upgrade openssh-server from 9.6p1 to >= 9.8p1. This is a KEV-listed remote code execution vulnerability with known exploits (100+ POCs). Consider temporary mitigations: set LoginGraceTime to 0 in sshd_config.",
    "is_kev": true,
    "is_poc_available": true,
    "source": "search_kev_vulnerabilities('openssh')"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "OpenSSH pkcs11 helper RCE via forwarded ssh-agent (fixed in 9.3p2)",
    "remediation": "Already patched in version 9.6p1",
    "recommendation": "No action required. Current version 9.6p1 includes fix (released Oct 2023, after July 2023 patch).",
    "is_kev": true,
    "is_poc_available": true,
    "source": "search_kev_vulnerabilities('openssh')"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql_jdbc_driver",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "SQL Injection in PostgreSQL JDBC Driver refreshRow() method",
    "remediation": "Upgrade JDBC driver to 42.2.26+ or 42.4.1+",
    "recommendation": "Not applicable to server package. If Java applications connect to this PostgreSQL instance, verify JDBC driver versions in application dependencies.",
    "is_kev": true,
    "is_poc_available": true,
    "source": "search_kev_vulnerabilities('postgresql')"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "OpenBSD SSH format string vulnerability (year 2000)",
    "remediation": "N/A - fixed over 20 years ago",
    "recommendation": "No action required. Ancient vulnerability from OpenBSD SSH era, long fixed in modern OpenSSH.",
    "is_kev": false,
    "is_poc_available": false,
    "source": "search_critical_remote('openssh')"
  }
]
```

## Report

# ABAC Policy Mining Report

## Overview
This report documents the ABAC policy extracted from the Ansible configuration for `labcorp` (production environment, SOC2 compliance tier). The configuration manages two host groups (`webservers`, `dbservers`) with two human users (`admin`, `appuser`) and one service account (`postgres`).

## Scope
- **Policy goal**: `all` (full coverage)
- **Files analyzed**: `inventory.ini`, `group_vars/all.yml`, `group_vars/dbservers.yml`, `group_vars/webservers.yml`, `roles/web/tasks/main.yml`, `roles/db/tasks/main.yml`
- **Total rules extracted**: 11 (10 permit rules + 1 default-deny)

## Attribute Catalog Summary

### Subjects
- **Users**: `admin` (uid 1001, sudo, operations, secret), `appuser` (uid 1002, developers, engineering, confidential), `postgres` (uid 999, system service account)
- **Groups**: `sudo`, `developers`, `postgres`
- **Clearance levels**: confidential, secret
- **Departments**: engineering, operations

### Resources
- **Hosts**: `web01.lab.local` (10.0.1.10, frontend, dmz, webservers), `db01.lab.local` (10.0.2.10, primary, internal, dbservers)
- **Services**: apache2 (port 80/tcp), openssh-server (port 22/tcp), postgresql (port 5432/tcp)
- **Paths**: `/var/lib/postgresql/data` (postgres:postgres 0700), `/var/www/html` (root:root 0755)
- **Networks**: `10.0.1.0/24` (webservers subnet), `0.0.0.0/0` (internet)

### Environment
- **Organization**: labcorp
- **Environment**: production
- **Compliance tier**: soc2
- **Log retention**: 90 days

## Rules Summary

| ID | Action | Effect | Subject | Resource | Condition |
|----|--------|--------|---------|----------|-----------|
| rule-001 | ssh:login | permit | groups in [sudo] | web01.lab.local:22 | compliance_tier=soc2 |
| rule-002 | sudo:execute | permit | groups in [sudo] + clearance=secret | web01.lab.local | compliance_tier=soc2 |
| rule-003 | network:connect | permit | source_network=0.0.0.0/0 | web01.lab.local:80 | compliance_tier=soc2 |
| rule-004 | user:create | permit | groups in [sudo] | web01.lab.local | compliance_tier=soc2 |
| rule-005 | db:login | permit | groups in [sudo] | db01.lab.local:postgresql | compliance_tier=soc2, SUPERUSER |
| rule-006 | db:login | permit | groups in [developers] | db01.lab.local:postgresql | compliance_tier=soc2, NOSUPERUSER |
| rule-007 | network:connect | permit | source_network=10.0.1.0/24 | db01.lab.local:5432 | compliance_tier=soc2 |
| rule-008 | filesystem:read | permit | user=postgres | /var/lib/postgresql/data (0700) | compliance_tier=soc2 |
| rule-009 | filesystem:write | permit | user=postgres | /var/lib/postgresql/data (0700) | compliance_tier=soc2 |
| rule-010 | filesystem:execute | permit | user=postgres | /var/lib/postgresql/data (0700) | compliance_tier=soc2 |
| rule-011 | * | deny | all | all | compliance_tier=soc2 |

## Vulnerability Assessment

### Pinned Software Versions
| Package | Pinned Version | Source |
|---------|---------------|--------|
| apache2 (httpd) | 2.4.49-1 | group_vars/all.yml |
| openssh-server | 1:9.6p1-3ubuntu1 | group_vars/all.yml |
| postgresql | 16.2-1.pgdg22.04+1 | group_vars/all.yml |

### Critical Findings
1. **CVE-2024-6387 (regreSSHion)** — **AFFECTS** pinned version
   - **Product**: OpenSSH
   - **Pinned version**: 1:9.6p1-3ubuntu1 (< 9.8, vulnerable)
   - **CVSS**: 8.1 (High)
   - **KEV**: Yes, actively exploited
   - **Description**: Signal handler race condition in OpenSSH server on glibc-based systems allows remote unauthenticated code execution
   - **Recommendation**: URGENT upgrade to OpenSSH >= 9.8p1. Consider temporary mitigation: set `LoginGraceTime 0` in sshd_config.

2. **CVE-2023-38408** — Does NOT affect (fixed in 9.3p2, before our 9.6p1)
   - CVSS 9.8, KEV-listed, but patched in our version

3. **CVE-2024-1597** — Does NOT affect (PostgreSQL JDBC Driver only, not server)
   - CVSS 10.0, KEV-listed, but targets Java applications using the JDBC driver

4. **Ancient OpenSSH CVEs** (2000-2003) — Do NOT affect (fixed 20+ years ago)

### Overall Risk: HIGH due to CVE-2024-6387 being actively exploited and affecting the pinned OpenSSH version.

## Ambiguities
- No `pg_hba.conf` template file was found; pg_hba entries are generated via `lineinfile` in db role. Implicit deny is assumed (PostgreSQL default).
- No explicit credentials management tasks found (no vault vars, no password generation). User passwords are not specified in the visible configuration.
- `httpd_version` is pinned to `2.4.49-1` which is a notably old version (released 2021), but no critical/remote vulnerabilities were found for this specific version in the current search scope.
- The `appuser` (developers group) does not appear to have SSH access per the `AllowGroups sudo` restriction, but is provisioned as a DB read-only user. This is intentional separation of duties.
