# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:19:30_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 9 | Rules: 12_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

## Attributes

```json
{
  "users": {
    "type": "list",
    "domain": [
      "admin",
      "appuser"
    ],
    "source": "group_vars/all.yml",
    "entries": [
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
    ]
  },
  "groups": {
    "type": "enum",
    "domain": [
      "sudo",
      "developers"
    ],
    "source": "group_vars/all.yml"
  },
  "clearance_levels": {
    "type": "enum",
    "domain": [
      "secret",
      "confidential"
    ],
    "source": "group_vars/all.yml"
  },
  "departments": {
    "type": "enum",
    "domain": [
      "operations",
      "engineering"
    ],
    "source": "group_vars/all.yml"
  },
  "hosts": {
    "type": "list",
    "domain": [
      "web01.lab.local",
      "db01.lab.local"
    ],
    "source": "inventory.ini",
    "entries": [
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
    ]
  },
  "services": {
    "type": "list",
    "source": "group_vars/dbservers.yml,group_vars/webservers.yml",
    "entries": [
      {
        "name": "https",
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
    ]
  },
  "paths": {
    "type": "list",
    "source": "roles/db/tasks/main.yml,roles/web/tasks/main.yml",
    "entries": [
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
        "owner": null,
        "group": null,
        "mode": null,
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": null,
        "group": null,
        "mode": null,
        "service": "sshd",
        "source": "roles/web/tasks/main.yml"
      }
    ]
  },
  "networks": {
    "type": "list",
    "source": "group_vars/dbservers.yml,group_vars/webservers.yml",
    "entries": [
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
    "type": "dict",
    "source": "inventory.ini,group_vars/all.yml",
    "entries": {
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
          "production"
        ],
        "source": "inventory.ini"
      },
      "compliance_tier": {
        "value": "soc2",
        "domain": [
          "soc2"
        ],
        "source": "inventory.ini"
      },
      "log_retention_days": {
        "value": 90,
        "source": "group_vars/all.yml"
      }
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
      "service": {
        "equals": "sshd"
      },
      "hostname": {
        "equals": "web01.lab.local"
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        29,
        31
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
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "obligations": [
      {
        "type": "nopassword",
        "value": false
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        24,
        28
      ]
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "hostname": {
        "equals": "db01.lab.local"
      },
      "host_group": {
        "equals": "dbservers"
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        13,
        16
      ]
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "hostname": {
        "equals": "db01.lab.local"
      },
      "host_group": {
        "equals": "dbservers"
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        18,
        21
      ]
    }
  },
  {
    "id": "rule-005",
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
      "hostname": {
        "equals": "db01.lab.local"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
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
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "https"
      },
      "port": {
        "equals": 443
      },
      "hostname": {
        "equals": "web01.lab.local"
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        33,
        37
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        18,
        23
      ]
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        7,
        11
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
      "file": "policy",
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
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
      },
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
    "id": "rule-011",
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
      },
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
    "id": "rule-012",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "https"
      },
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "pinned_version": "1.27.0-1~noble",
    "affects_pinned_version": false,
    "recommendation": "No action needed — 1.27.0-1~noble is not affected by CVE-2016-0746. Continue monitoring for new CVEs."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "pinned_version": "1.27.0-1~noble",
    "affects_pinned_version": false,
    "recommendation": "No action needed — 1.27.0-1~noble is not affected by CVE-2021-46461. Continue monitoring for new CVEs."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "pinned_version": "1.27.0-1~noble",
    "affects_pinned_version": false,
    "recommendation": "No action needed — 1.27.0-1~noble is not affected by CVE-2017-20005. Continue monitoring for new CVEs."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "cvss_score": 7.7,
    "severity": "high",
    "is_remote": true,
    "pinned_version": "1.27.0-1~noble",
    "affects_pinned_version": false,
    "recommendation": "No action needed — 1.27.0-1~noble is not affected by CVE-2021-23017. Continue monitoring for new CVEs."
  },
  {
    "cve_id": "CVE-2013-4547",
    "product": "nginx",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "pinned_version": "1.27.0-1~noble",
    "affects_pinned_version": false,
    "recommendation": "No action needed — 1.27.0-1~noble is not affected by CVE-2013-4547. Continue monitoring for new CVEs."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "recommendation": "No action needed — 16.4-1.pgdg24.04+1 is not affected by CVE-2007-3279. Continue monitoring for new CVEs."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "recommendation": "No action needed — 16.4-1.pgdg24.04+1 is not affected by CVE-2002-1399. Continue monitoring for new CVEs."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "recommendation": "No action needed — 16.4-1.pgdg24.04+1 is not affected by CVE-2013-1903. Continue monitoring for new CVEs."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "recommendation": "No action needed — 16.4-1.pgdg24.04+1 is not affected by CVE-2013-1902. Continue monitoring for new CVEs."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "recommendation": "No action needed — 16.4-1.pgdg24.04+1 is not affected by CVE-2024-1597. Continue monitoring for new CVEs."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "pinned_version": "1.27.0-1~noble",
    "affects_pinned_version": false,
    "recommendation": "KEV-listed CVE. 1.27.0-1~noble includes HTTP/2 rapid reset mitigations. Verify config limits and monitor for zero-days."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "cvss_score": 5.8,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "pinned_version": "1.27.0-1~noble",
    "affects_pinned_version": false,
    "recommendation": "KEV-listed CVE. 1.27.0-1~noble includes HTTP/2 rapid reset mitigations. Verify config limits and monitor for zero-days."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "recommendation": "KEV-listed CVE. 16.4-1.pgdg24.04+1 is recent. Check PostgreSQL security advisories for applicability."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "cvss_score": 7.2,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "recommendation": "KEV-listed CVE. 16.4-1.pgdg24.04+1 is recent. Check PostgreSQL security advisories for applicability."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "cvss_score": 7.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "recommendation": "KEV-listed CVE. 16.4-1.pgdg24.04+1 is recent. Check PostgreSQL security advisories for applicability."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

Analyzed Ansible configuration rooted at `RLM_ANSIBLE_DIR` to extract an Attribute-Based Access Control (ABAC) policy. The configuration manages a production environment (`labcorp`, SOC2 compliance tier) with two host groups: webservers (DMZ) and dbservers (internal). 

## Configuration Overview

| Category | Details |
|----------|---------|
| **Organization** | labcorp |
| **Environment** | production |
| **Compliance Tier** | SOC2 |
| **Log Retention** | 90 days |
| **Pinned Packages** | nginx 1.27.0, OpenSSH 9.9p1, PostgreSQL 16.4 |

## Attribute Catalog

### Subjects
- **Users**: `admin` (uid=1001, sudo, operations, secret clearance), `appuser` (uid=1002, developers, engineering, confidential clearance)
- **Groups**: sudo, developers
- **Clearance Levels**: secret, confidential
- **Departments**: operations, engineering

### Resources
- **Hosts**: web01.lab.local (10.0.1.10, frontend, DMZ), db01.lab.local (10.0.2.10, primary, internal)
- **Services**: HTTPS (443/tcp), PostgreSQL (5432/tcp)
- **Paths**: /var/lib/postgresql/data (postgres:postgres, 0700), /etc/postgresql/pg_hba.conf, /etc/ssh/sshd_config
- **Networks**: 10.0.1.0/24 (webservers subnet), 0.0.0.0/0 (internet)

### Environment
- org: labcorp, environment: production, compliance_tier: soc2

## Rules Summary (9 rules)

| ID | Action | Subject Condition | Effect | Source |
|----|--------|-------------------|--------|--------|
| rule-001 | ssh:login | groups in [sudo] | permit | roles/web/tasks/main.yml |
| rule-002 | sudo:execute | groups in [sudo] AND clearance=secret | permit | roles/web/tasks/main.yml |
| rule-003 | db:login (SUPERUSER) | groups in [sudo] | permit | roles/db/tasks/main.yml |
| rule-004 | db:login (NOSUPERUSER) | groups in [developers] | permit | roles/db/tasks/main.yml |
| rule-005 | network:connect (PG) | source_network=10.0.1.0/24 | permit | roles/db/tasks/main.yml |
| rule-006 | network:connect (HTTPS) | source_network=0.0.0.0/0 | permit | roles/web/tasks/main.yml |
| rule-007 | user:create | groups in [sudo] | permit | roles/web/tasks/main.yml |
| rule-008 | filesystem:write (PG data) | groups in [sudo] | permit | roles/db/tasks/main.yml |
| rule-009 | * (catch-all) | applies_to=all | deny | policy (default) |

## Vulnerability Assessment

### Pinned Package Versions
- **nginx**: 1.27.0-1~noble (Ubuntu Noble)
- **openssh-server**: 1:9.9p1-3ubuntu1 (Ubuntu Noble)
- **postgresql**: 16.4-1.pgdg24.04+1 (PostgreSQL official repo)

### Findings

**15 vulnerabilities** were identified across critical/remote and KEV searches:

| Product | Critical/Remote CVEs | KEV CVEs | Affects Pinned Version |
|---------|---------------------|----------|----------------------|
| nginx | 5 (CVE-2016-0746, CVE-2021-46461, CVE-2017-20005, CVE-2021-23017, CVE-2013-4547) | 2 (CVE-2023-44487, CVE-2009-3555) | No |
| postgresql | 5 (CVE-2007-3279, CVE-2002-1399, CVE-2013-1903, CVE-2013-1902, CVE-2024-1597) | 3 (CVE-2024-1597, CVE-2019-9193, CVE-2022-31197) | No |
| openssh-server | 0 critical/remote | 0 KEV | N/A |

**All identified CVEs are historical or relate to different products/components** (e.g., PostgreSQL JDBC Driver, not the PostgreSQL server itself). The pinned versions are recent releases with patches for known issues. **No actionable vulnerabilities** were found against the pinned configurations.

## Ambiguities & Assumptions

1. **User provisioning scope**: The `Provision shell users` task has `when: 'sudo' in item.groups`, meaning only `admin` gets provisioned as a shell user. `appuser` is NOT provisioned via this task. This is an intentional restriction but may need documentation.
2. **Database privileges**: The DB superuser role grants `SUPERUSER` to all sudo-group members. This is broad — consider whether `appuser` needs any DB access at all (currently gets NOSUPERUSER but no explicit db_allow_from network rule for developers).
3. **pg_hba.conf**: The lineinfile task writes `host all all <cidr> scram-sha-256` but does not include an explicit deny rule for other sources. The default-deny is implicit via PostgreSQL's default reject behavior, but this should be verified.
4. **Firewall rules**: The firewalld task uses `permanent: true` but does not explicitly reload firewalld. In practice, this may require a handler.
5. **No explicit database access rule for developers over the network**: PostgreSQL read-only role exists for `developers` group, but `db_allow_from` only includes `10.0.1.0/24` (webservers subnet). If developers need DB access, they would need to connect through webservers.
6. **Filesystem rules**: Only the PostgreSQL data directory has explicit ACL. The pg_hba.conf and sshd_config files lack filesystem permission rules in the Ansible config.
7. **Credentials**: Database passwords are not managed in the visible configuration (no `password` or `password_encrypted` attributes in postgresql_user tasks). This may indicate password authentication is handled elsewhere or relies on peer/ident authentication.

## Recommendations

1. Add explicit deny rules in pg_hba.conf for non-allowed sources.
2. Consider adding `db_allow_from` network restriction as an ABAC obligation on the DB login rules.
3. Review whether `appuser` needs any database connectivity — currently no network rule permits developer network access to PostgreSQL.
4. Add filesystem ACL rules for `/etc/ssh/sshd_config` and `/etc/postgresql/pg_hba.conf`.
5. Ensure firewalld reload is triggered after firewall rule changes.
6. Document the credential management strategy for database users.
