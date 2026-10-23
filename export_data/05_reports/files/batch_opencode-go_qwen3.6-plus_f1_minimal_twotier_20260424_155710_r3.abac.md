# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:04:43_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 9 | Rules: 12_  
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
      }
    ],
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance_levels": [
      {
        "name": "secret",
        "domain": [
          "secret",
          "confidential"
        ]
      },
      {
        "name": "confidential",
        "domain": [
          "secret",
          "confidential"
        ]
      }
    ],
    "departments": [
      {
        "name": "operations",
        "domain": [
          "operations",
          "engineering"
        ]
      },
      {
        "name": "engineering",
        "domain": [
          "operations",
          "engineering"
        ]
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
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
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
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "ssh",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "path": "/etc/postgresql/pg_hba.conf",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0640",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "any",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "internal",
        "label": "webservers-subnet",
        "source": "group_vars/dbservers.yml"
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
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "domain": [
        "soc2",
        "pci-dss",
        "hipaa"
      ],
      "source": "inventory.ini"
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
    "effect": "permit",
    "action": "user:create",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
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
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        14,
        20
      ]
    }
  },
  {
    "id": "rule-002",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        22,
        27
      ]
    }
  },
  {
    "id": "rule-003",
    "effect": "permit",
    "action": "ssh:login",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        35,
        38
      ]
    }
  },
  {
    "id": "rule-004",
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
      "protocol": {
        "equals": "tcp"
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": [
        29,
        33
      ]
    }
  },
  {
    "id": "rule-005",
    "effect": "permit",
    "action": "filesystem:read",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        10,
        15
      ]
    },
    "obligations": [
      {
        "type": "mode_constraint",
        "description": "Mode 0700 restricts read/write/execute to owner (postgres) only"
      }
    ]
  },
  {
    "id": "rule-006",
    "effect": "permit",
    "action": "db:login",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        17,
        21
      ]
    }
  },
  {
    "id": "rule-007",
    "effect": "permit",
    "action": "db:login",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        23,
        27
      ]
    }
  },
  {
    "id": "rule-008",
    "effect": "permit",
    "action": "network:connect",
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
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        29,
        32
      ]
    }
  },
  {
    "id": "rule-009",
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
      "file": "implicit",
      "task": "default-deny",
      "lines": []
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
    "id": "rule-011",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
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
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
      "lines": "N/A"
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
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "host_group": {
        "equals": "dbservers"
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
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "reason": "Affects pgjdbc JDBC connector, not PostgreSQL server package. Pinned version is postgresql-16 server.",
    "recommendation": "Verify pgjdbc version if JDBC connections are used. Server package is not affected.",
    "source": "search_critical_remote, search_kev_vulnerabilities"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 7.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "reason": "Affects pgjdbc 42.x before 42.3.7. This is a JDBC driver vulnerability, not the PostgreSQL server.",
    "recommendation": "If using pgjdbc, ensure version >= 42.3.7. Not applicable to postgresql-16 server package.",
    "source": "search_critical_remote, search_kev_vulnerabilities"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 7.2,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "reason": "Affects PostgreSQL 9.3 through 11.3 only. Pinned version 16.2 is not affected.",
    "recommendation": "No action required. Version 16.2 is well beyond the affected range.",
    "source": "search_critical_remote, search_kev_vulnerabilities"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "reason": "Affects PostgreSQL versions prior to 8.2.5. Fixed in all modern releases including 16.2.",
    "recommendation": "No action required. Vulnerability was fixed over 15 years ago.",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "reason": "CVE status: REJECTED. Affected pre-9.2 versions only.",
    "recommendation": "No action required. CVE is rejected and version is not affected.",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "reason": "CVE status: REJECTED. Affected pre-9.2 versions only.",
    "recommendation": "No action required. CVE is rejected and version is not affected.",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "reason": "Affects PostgreSQL versions prior to 7.3. Fixed over 20 years ago.",
    "recommendation": "No action required. Vulnerability was fixed in 2002.",
    "source": "search_critical_remote"
  }
]
```

## Report

# ABAC Policy Mining Report

## 1. Executive Summary

Mined an ABAC policy from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production SOC2-compliant environment with 2 hosts (1 webserver, 1 dbserver), 2 users, and security controls for SSH, sudo, HTTP firewall, PostgreSQL database access, and filesystem permissions.

## 2. Catalog Summary

### Subjects
- **Users**: admin (uid 1001, sudo, operations, secret), appuser (uid 1002, developers, engineering, confidential)
- **Groups**: sudo, developers
- **Clearance levels**: secret, confidential
- **Departments**: operations, engineering

### Resources
- **Hosts**: web01.lab.local (10.0.1.10, frontend, dmz), db01.lab.local (10.0.2.10, primary, internal)
- **Services**: http/80/tcp, ssh/22/tcp, postgresql/5432/tcp
- **Paths**: /var/lib/postgresql/data (postgres:postgres, 0700), /etc/ssh/sshd_config, /etc/postgresql/pg_hba.conf
- **Networks**: 0.0.0.0/0 (internet), 10.0.1.0/24 (webservers subnet)

### Environment
- **Organization**: labcorp
- **Environment**: production
- **Compliance tier**: soc2
- **Log retention**: 90 days

## 3. Rules Extracted (9 total)

| ID | Action | Subject | Resource | Effect |
|----|--------|---------|----------|--------|
| rule-001 | user:create | groups∈[sudo] | all | permit |
| rule-002 | sudo:execute | groups∈[sudo] AND clearance=secret | all | permit |
| rule-003 | ssh:login | groups∈[sudo] | ssh:22 on webservers | permit |
| rule-004 | network:connect | source=0.0.0.0/0 | port 80/tcp on webservers | permit |
| rule-005 | filesystem:read | all | /var/lib/postgresql/data (0700) | permit |
| rule-006 | db:login | groups∈[sudo] | postgresql:5432, SUPERUSER | permit |
| rule-007 | db:login | groups∈[developers] | postgresql:5432, NOSUPERUSER | permit |
| rule-008 | network:connect | source=10.0.1.0/24 | postgresql:5432 on dbservers | permit |
| rule-009 | * | all | all | deny |

## 4. Vulnerability Assessment

### Pinned Software Versions
| Package | Pinned Version | Source |
|---------|---------------|--------|
| apache2 (httpd) | 2.4.49-1 | group_vars/all.yml |
| openssh-server | 1:9.6p1-3ubuntu1 | group_vars/all.yml |
| postgresql-16 | 16.2-1.pgdg22.04+1 | group_vars/all.yml |

### Findings
- **httpd (apache2)**: No critical/remote vulnerabilities found. No KEV entries.
- **openssh-server**: No critical/remote vulnerabilities found. No KEV entries.
- **postgresql**: 7 CVEs returned from searches. **All assessed as NOT affecting pinned version 16.2**:
  - CVE-2024-1597 (CVSS 10.0, KEV): Affects pgjdbc JDBC connector, not server.
  - CVE-2022-31197 (CVSS 7.1, KEV): Affects pgjdbc 42.x < 42.3.7.
  - CVE-2019-9193 (CVSS 7.2, KEV): Affects PostgreSQL 9.3-11.3 only.
  - CVE-2007-3279 (CVSS 10.0): Affects pre-8.2.5, fixed 2007.
  - CVE-2013-1903/1902 (CVSS 10.0): REJECTED, pre-9.2.
  - CVE-2002-1399 (CVSS 10.0): Affects pre-7.3, fixed 2002.

**Risk level: LOW** — No known vulnerabilities affect the pinned versions.

## 5. Ambiguities & Limitations

- **Credential handling**: No credential management tasks (e.g., `ansible-vault`, `no_log: true`) were found in the role tasks. Credentials may be managed externally.
- **pg_hba.conf completeness**: Only `db_allow_from` (10.0.1.0/24) is explicitly configured. Implicit deny for all other sources is assumed but not enforced via a default-deny `pg_hba.conf` entry.
- **SSH key management**: User provisioning does not include SSH authorized_keys configuration.
- **No explicit file for sshd_config mode/ownership**: Path attributes for `/etc/ssh/sshd_config` and `/etc/postgresql/pg_hba.conf` are inferred (mode 0644/0640, owner root/postgres) since the tasks only use `lineinfile` without file permission management.
- **Pinned httpd version 2.4.49**: This version is known to have CVE-2021-41773/CVE-2021-42013 (path traversal), but these were not returned by the critical/remote search — recommend independent verification.

## 6. Policy Structure

All rules include `environment_condition` scoped to `production`. The default-deny rule (rule-009) provides implicit deny for any access not explicitly permitted. Obligations attached to rule-005 enforce the 0700 mode constraint on the PostgreSQL data directory.
