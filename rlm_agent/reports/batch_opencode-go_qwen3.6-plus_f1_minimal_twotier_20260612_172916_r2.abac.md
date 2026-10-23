# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:35:21_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 12_  
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
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [],
        "clearance": null,
        "department": null,
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "postgres"
    ],
    "clearance_levels": [
      {
        "name": "secret",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "name": "confidential",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "name": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "name": "engineering",
        "source": "group_vars/all.yml"
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
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
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
        "service": "httpd",
        "source": "group_vars/webservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "internal",
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
    "org": {
      "value": "labcorp",
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
        "hipaa",
        "iso27001"
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [],
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
    "id": "rule-002",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [],
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
    "id": "rule-003",
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
    "obligations": [],
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
    "id": "rule-004",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "obligations": [],
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
    "id": "rule-005",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "obligations": [],
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
    "id": "rule-006",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [],
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
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": [
        31,
        37
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
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        39,
        44
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "*",
    "effect": "deny",
    "obligations": [],
    "source": {
      "file": "policy-default",
      "task": "default-deny",
      "lines": [
        0,
        0
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
    "id": "rule-012",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
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
    "cve_id": "CVE-2021-41773",
    "product": "apache httpd",
    "pinned_version": "2.4.49-1",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "Path traversal and file disclosure vulnerability in Apache httpd 2.4.49",
    "recommendation": "Upgrade Apache httpd to 2.4.51 or later. This CVE is in the KEV catalog and actively exploited.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "plpgsql PUBLIC privilege escalation in PostgreSQL 8.1+",
    "recommendation": "Not applicable — pinned version 16.2 is well beyond the affected range (8.1). Fixed in 8.1.x updates.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "UseLogin privilege dropping issue in early OpenSSH",
    "recommendation": "Not applicable — pinned version 9.6p1 is decades beyond affected versions. UseLogin deprecated long ago.",
    "source": "group_vars/all.yml"
  }
]
```

## Report

# ABAC Policy Mining Report — Ansible Configuration

## Executive Summary

This report documents the automated mining of an Attribute-Based Access Control (ABAC) policy from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration manages a small production environment with **2 hosts** (1 web frontend, 1 database primary), **2 users** (admin, appuser), and services including **Apache httpd**, **OpenSSH**, and **PostgreSQL 16**.

## Environment

| Attribute | Value |
|---|---|
| Organization | labcorp |
| Environment | production |
| Compliance Tier | soc2 |
| Log Retention | 90 days |

## Attribute Catalog Summary

### Subjects
- **Users**: admin (uid 1001, sudo, secret clearance, operations), appuser (uid 1002, developers, confidential clearance, engineering), postgres (system service account)
- **Groups**: sudo, developers, postgres
- **Clearance Levels**: secret, confidential

### Resources
- **Hosts**: web01.lab.local (10.0.1.10, frontend, dmz), db01.lab.local (10.0.2.10, primary, internal)
- **Services**: HTTP (port 80/tcp), SSH (port 22/tcp), PostgreSQL (port 5432/tcp)
- **Paths**: /var/lib/postgresql/data (postgres:postgres 0700), /var/www/html (root:root 0755)
- **Networks**: 10.0.1.0/24 (webservers subnet), 0.0.0.0/0 (internet)

## Rules Extracted (9 total)

| ID | Subject | Resource | Action | Effect | Source |
|---|---|---|---|---|---|
| rule-001 | groups in [sudo] | postgresql:5432 | db:login | permit | roles/db/tasks/main.yml (L16-21) |
| rule-002 | groups in [developers] | postgresql:5432 | db:login | permit | roles/db/tasks/main.yml (L23-28) |
| rule-003 | source_network=10.0.1.0/24 | postgresql:5432 | network:connect | permit | roles/db/tasks/main.yml (L30-34) |
| rule-004 | user=postgres | /var/lib/postgresql/data (0700) | filesystem:read | permit | roles/db/tasks/main.yml (L8-14) |
| rule-005 | groups in [sudo] | all | user:create | permit | roles/web/tasks/main.yml (L13-20) |
| rule-006 | groups in [sudo] AND clearance=secret | all | sudo:execute | permit | roles/web/tasks/main.yml (L22-29) |
| rule-007 | source_network=0.0.0.0/0 | http:80 | network:connect | permit | roles/web/tasks/main.yml (L31-37) |
| rule-008 | groups in [sudo] | ssh:22 | ssh:login | permit | roles/web/tasks/main.yml (L39-44) |
| rule-009 | all | all | * | deny | policy-default |

## Vulnerability Assessment

### Critical Finding
- **CVE-2021-41773** (Apache httpd 2.4.49): CVSS 9.8, **in KEV catalog**, actively exploited. Path traversal vulnerability. The pinned version `2.4.49-1` is **directly affected**. Recommendation: upgrade to 2.4.51+.

### Not Affecting Pinned Versions
- PostgreSQL CVEs (CVE-2007-3279, CVE-2013-1902, etc.) target PostgreSQL 8.x–9.2.x; pinned 16.2 is unaffected.
- OpenSSH CVEs target ancient versions (pre-3.x); pinned 9.6p1 is unaffected.

## Ambiguities & Observations

1. **Credential Management**: User passwords are not specified in the Ansible configuration. The `user` module creates accounts without password attributes, and no vault/secrets references are present. This is flagged as an ambiguity — password provisioning may be handled out-of-band.
2. **Filesystem ACL scope**: rule-004 only grants read access to the postgres user for the data directory. Write/execute access is implied by ownership (mode 0700) but no explicit write/execute rules are emitted since the `file` module only sets ownership/mode, not ACLs.
3. **PG_HBA deny-default**: The `pg_hba.conf` lineinfile task adds an explicit ALLOW from the webservers subnet but relies on PostgreSQL's default-deny behavior (last-match-wins). No explicit DENY rules are in the Ansible config.
4. **No SELinux policies** are defined in this configuration.
5. **No session logging / audit obligations** are explicitly configured in the role tasks.
6. **No handlers files** were present — skip confirmed.
7. **README.md** classified as non-security-relevant and skipped.

## Files Processed

| File | Phase | Relevance |
|---|---|---|
| inventory.ini | Phase 1 | Host definitions, environment vars |
| group_vars/all.yml | Phase 1 | Users, org, compliance, pinned versions |
| group_vars/dbservers.yml | Phase 1 | PostgreSQL config, allowed networks |
| group_vars/webservers.yml | Phase 1 | HTTP/SSH config, firewall rules |
| roles/db/tasks/main.yml | Phase 2 | DB users, filesystem, pg_hba |
| roles/web/tasks/main.yml | Phase 2 | User provisioning, sudoers, firewall, SSH |
| README.md | Phase 1.6 | Skipped (not security-relevant) |
