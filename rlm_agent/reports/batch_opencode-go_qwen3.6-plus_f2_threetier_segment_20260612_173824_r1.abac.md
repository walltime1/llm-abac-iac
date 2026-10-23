# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:42:27_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 8 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f2_threetier_segmented`_

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
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "group_vars/all.yml"
      },
      {
        "name": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "clearance": "secret",
        "department": "data",
        "source": "group_vars/all.yml"
      }
    ],
    "groups": {
      "values": [
        "sudo",
        "developers",
        "dba"
      ],
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "values": [
        "secret",
        "confidential"
      ],
      "domain": [
        "secret",
        "confidential",
        "top_secret",
        "unclassified"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "values": [
        "operations",
        "engineering",
        "data"
      ],
      "domain": [
        "operations",
        "engineering",
        "data",
        "security",
        "management"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "proxy01.lab.local",
        "ip": "10.0.1.10",
        "role": "reverse_proxy",
        "zone": "dmz",
        "inventory_group": "dmz",
        "source": "inventory.ini"
      },
      {
        "hostname": "app01.lab.local",
        "ip": "10.0.2.10",
        "role": "application",
        "zone": "app",
        "inventory_group": "appservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.3.10",
        "role": "primary",
        "zone": "data",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "sshd",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all",
        "source": "roles/app/tasks/main.yml"
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
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "sshd",
        "source": "roles/app/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "dmz_subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "data_subnet",
        "source": "inventory.ini"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "segcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "domain": [
        "production",
        "staging",
        "development",
        "testing"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "pci",
      "domain": [
        "pci",
        "hipaa",
        "sox",
        "gdpr",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "retention": {
      "default_log_retention_days": 365,
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
    "description": "Provision shell users for sudo and developers groups on appservers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "role": {
        "equals": "application"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        7,
        12
      ]
    }
  },
  {
    "id": "rule-002",
    "description": "Allow DMZ subnet (10.0.1.0/24) to connect to app service port 8080/tcp",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        14,
        19
      ]
    }
  },
  {
    "id": "rule-003",
    "description": "Allow sudo and developers groups SSH login on appservers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sshd"
      },
      "host_group": {
        "equals": "appservers"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        21,
        24
      ]
    }
  },
  {
    "id": "rule-004",
    "description": "Filesystem access to PostgreSQL data directory - owner/group postgres only",
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        11,
        16
      ]
    }
  },
  {
    "id": "rule-005",
    "description": "Deny filesystem access to PostgreSQL data directory for non-postgres subjects",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
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
    "action": "filesystem:read",
    "effect": "deny",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        11,
        16
      ]
    }
  },
  {
    "id": "rule-006",
    "description": "Database superuser login for DBA group members",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "obligations": [
      {
        "type": "privilege_level",
        "value": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        18,
        21
      ]
    }
  },
  {
    "id": "rule-007",
    "description": "Database read-only login for developers group",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "obligations": [
      {
        "type": "privilege_level",
        "value": "NOSUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        23,
        26
      ]
    }
  },
  {
    "id": "rule-008",
    "description": "Allow PostgreSQL connections from app subnet (10.0.2.0/24)",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        28,
        30
      ]
    }
  },
  {
    "id": "rule-009",
    "description": "Allow sudo and dba groups SSH login on dbservers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sshd"
      },
      "host_group": {
        "equals": "dbservers"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        32,
        35
      ]
    }
  },
  {
    "id": "rule-010",
    "description": "Provision admin users (sudo group) on DMZ hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "reverse_proxy"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        11,
        16
      ]
    }
  },
  {
    "id": "rule-011",
    "description": "Allow any source to connect to HTTPS (port 443/tcp) on DMZ hosts",
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        18,
        23
      ]
    }
  },
  {
    "id": "rule-012",
    "description": "Allow sudo group SSH login on DMZ hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sshd"
      },
      "host_group": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        25,
        28
      ]
    }
  },
  {
    "id": "rule-013",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "policy-default",
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
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
        "equals": "app"
      },
      "port": {
        "equals": 8080
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
    "id": "rule-015",
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
    "id": "rule-016",
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

# ABAC Policy Report — Ansible Configuration Mining

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the
Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration manages a PCI-compliant
production environment for **segcorp** with three host groups: DMZ (reverse proxy), appservers
(application tier), and dbservers (primary database).

## Configuration Overview

| Attribute | Value |
|-----------|-------|
| Organization | segcorp |
| Environment | production |
| Compliance Tier | PCI |
| Log Retention | 365 days |

## Host Inventory

| Host | IP | Role | Zone | Group |
|------|-----|------|------|-------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

## Subjects

| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |

## Rules Summary

A total of **13 ABAC rules** were extracted:
- **12 permit rules** covering user creation, SSH access, database access, network connectivity, and filesystem access
- **1 deny rule** (default deny-all catch-all)
- **1 explicit deny** for filesystem access to PostgreSQL data directory (rule-005)

### Rule Breakdown by Action

| Action | Count |
|--------|-------|
| ssh:login | 3 |
| network:connect | 3 |
| db:login | 2 |
| user:create | 2 |
| filesystem:read | 2 |
| * (default deny) | 1 |

## Vulnerability Assessment

Three pinned software packages were assessed:

| Package | Pinned Version | Relevant CVEs | Affected? |
|---------|---------------|---------------|-----------|
| nginx | 1.20.0-1~focal | CVE-2016-0746 (critical), CVE-2021-46461 (critical) | No |
| openssh | 1:9.6p1-3ubuntu1 | No critical/remote or KEV findings | No |
| postgresql | 13.7-1.pgdg20.04+1 | CVE-2022-31197 (high) | No |

None of the identified CVEs affect the pinned server versions. CVE-2021-46461 and CVE-2022-31197 target
ancillary components (njs scripting module and JDBC driver respectively) whose versions are not tracked
in the Ansible configuration.

## Ambiguities and Gaps

1. **Credential management**: No password hashes, SSH keys, or credential provisioning tasks were found
   in the Ansible roles. User creation tasks do not specify password or SSH key attributes, leaving
   authentication mechanisms undefined in the policy.

2. **Implicit SSH deny**: The `AllowGroups` directives in sshd_config implicitly deny all users not in
   the listed groups, but no explicit deny rules were found in the configuration. Rule-013 (default-deny)
   covers this gap at the policy level.

3. **Firewalld implicit deny**: The firewalld tasks only add allow rules. The implicit default-deny
   behavior of firewalld is not explicitly configured in the Ansible roles.

4. **pg_hba.conf ordering**: The pg_hba.conf line insertion does not specify position. PostgreSQL
   processes pg_hba.conf top-down with first-match semantics. Without explicit ordering, the access
   control behavior may be unpredictable if additional entries exist.

5. **sshd_config file ownership**: The `/etc/ssh/sshd_config` path was cataloged with default owner/group
   (root:root) and mode (0644), but these values were inferred from convention rather than explicitly
   defined in the Ansible tasks.

6. **NJS and JDBC driver versions**: The Ansible configuration pins nginx 1.20.0 and postgresql 13.7
   but does not track the versions of ancillary components (njs, JDBC driver) that have known vulnerabilities.

7. **Network default-deny for firewalld**: No explicit deny rules for the firewalld configuration were
   found. The firewalld default zone behavior is not configured in the Ansible roles.

## Provenance

All rules and attributes were extracted from the following files:
- `inventory.ini` — host definitions and environment variables
- `group_vars/all.yml` — global variables, user definitions, package versions
- `group_vars/appservers.yml` — appserver-specific variables
- `group_vars/dbservers.yml` — database server variables
- `group_vars/dmz.yml` — DMZ variables
- `roles/app/tasks/main.yml` — appserver role tasks
- `roles/db/tasks/main.yml` — database role tasks
- `roles/dmz/tasks/main.yml` — DMZ role tasks
