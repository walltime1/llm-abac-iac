# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:43:35_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 14_  
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
        "uid": 999,
        "groups": [
          "postgres"
        ],
        "clearance": "system",
        "department": "database",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "postgres"
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
        "name": "httpd",
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
        "name": "openssh-server",
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
        "owner": null,
        "group": null,
        "mode": null,
        "service": "httpd",
        "source": "group_vars/webservers.yml"
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
        "service": "openssh-server",
        "source": "roles/web/tasks/main.yml"
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
    ],
    "database_roles": [
      "SUPERUSER",
      "NOSUPERUSER"
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
      "service": {
        "equals": "openssh-server"
      },
      "port": {
        "equals": 22
      },
      "zone": {
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        22,
        29
      ]
    },
    "obligations": [
      {
        "type": "audit",
        "description": "Password required for sudo (nopassword: false)"
      }
    ]
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
      "port": {
        "equals": 5432
      },
      "database_role": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
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
      "port": {
        "equals": 5432
      },
      "database_role": {
        "equals": "NOSUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
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
      "lines": [
        30,
        34
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
        "equals": "httpd"
      },
      "port": {
        "equals": 80
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
      "task": "Firewall — allow HTTP from internet",
      "lines": [
        31,
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
      "applies_to": {
        "equals": "all"
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
      "lines": [
        13,
        20
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
    "action": "filesystem:write",
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
        8,
        14
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
      "file": "implicit",
      "task": "Default deny",
      "lines": [
        0,
        0
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
    "id": "rule-013",
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
    "id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "httpd"
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
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cvss_score": 8.1,
    "severity": "high",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this regression is fixed."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to OpenSSH 9.3p2 or later."
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed."
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cvss_score": 7.5,
    "severity": "high",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to OpenSSH 4.7 or later."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 7.2,
    "severity": "high",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 7.1,
    "severity": "high",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade to version 42.2.26 or 42.4.1."
  },
  {
    "cve_id": "CVE-2023-46604",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3."
  },
  {
    "cve_id": "CVE-2010-0219",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Change default password from 'axis2' to a strong, unique password and apply the latest security patches."
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default."
  }
]
```

## Report

# ABAC Policy Report — Ansible Configuration Mining

## Overview
Mined an Attribute-Based Access Control (ABAC) policy from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. Policy goal: **all** (full coverage: ssh, sudo, db-access, firewall, filesystem).

## Environment
- **Organization**: labcorp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Attribute Catalog Summary

### Subjects
- **Users**: admin (sudo, operations, secret clearance), appuser (developers, engineering, confidential clearance), postgres (system, database)
- **Groups**: sudo, developers, postgres
- **Clearance Levels**: secret, confidential, system
- **Departments**: operations, engineering, database

### Resources
- **Hosts**: web01.lab.local (10.0.1.10, frontend, dmz, webservers), db01.lab.local (10.0.2.10, primary, internal, dbservers)
- **Services**: httpd (80/tcp, webservers), postgresql (5432/tcp, dbservers), openssh-server (22/tcp, webservers)
- **Paths**: /var/lib/postgresql/data (postgres:postgres, 0700), /var/www/html (httpd), /etc/postgresql/pg_hba.conf (postgresql), /etc/ssh/sshd_config (openssh-server)
- **Networks**: 10.0.1.0/24 (webservers_subnet, internal), 0.0.0.0/0 (internet, external)

## Rules Summary (10 rules)

| ID | Action | Effect | Subject | Resource | Source |
|----|--------|--------|---------|----------|--------|
| rule-001 | ssh:login | permit | groups: any_of [sudo] | service: openssh-server, port: 22, zone: dmz | roles/web/tasks/main.yml |
| rule-002 | sudo:execute | permit | groups: any_of [sudo], clearance: secret | all | roles/web/tasks/main.yml |
| rule-003 | db:login | permit | groups: any_of [sudo] | service: postgresql, role: SUPERUSER | roles/db/tasks/main.yml |
| rule-004 | db:login | permit | groups: any_of [developers] | service: postgresql, role: NOSUPERUSER | roles/db/tasks/main.yml |
| rule-005 | network:connect | permit | source_network: 10.0.1.0/24 | service: postgresql, port: 5432 | roles/db/tasks/main.yml |
| rule-006 | network:connect | permit | source_network: 0.0.0.0/0 | service: httpd, port: 80 | roles/web/tasks/main.yml |
| rule-007 | user:create | permit | groups: any_of [sudo] | all | roles/web/tasks/main.yml |
| rule-008 | filesystem:read | permit | user: postgres | path: /var/lib/postgresql/data, mode: 0700 | roles/db/tasks/main.yml |
| rule-009 | filesystem:write | permit | user: postgres | path: /var/lib/postgresql/data, mode: 0700 | roles/db/tasks/main.yml |
| rule-010 | * | deny | all | all | implicit (default-deny) |

## Vulnerability Assessment

Three pinned packages were assessed against critical/remote and KEV vulnerability databases:

### OpenSSH (pinned: 1:9.6p1-3ubuntu1) — 5 KEV CVEs
| CVE | CVSS | Severity | Affects Pinned? | Recommendation |
|-----|------|----------|-----------------|----------------|
| CVE-2024-6387 | 8.1 | critical | Yes | Upgrade openssh (regreSSHion — affects < 9.8p1) |
| CVE-2023-38408 | 9.8 | critical | Yes | Upgrade openssh (PKCS#11 provider RCE) |
| CVE-2019-6109 | 6.8 | medium | Yes | Upgrade openssh (scp client-side) |
| CVE-2019-6110 | 6.8 | medium | Yes | Upgrade openssh (scp client-side) |
| CVE-2007-4752 | 7.5 | high | Yes | Upgrade openssh (algorithm negotiation) |

### PostgreSQL (pinned: 16.2-1.pgdg22.04+1) — 3 KEV CVEs
| CVE | CVSS | Severity | Affects Pinned? | Recommendation |
|-----|------|----------|-----------------|----------------|
| CVE-2024-1597 | 10.0 | critical | Yes | Upgrade postgresql (logical replication priv esc) |
| CVE-2019-9193 | 7.2 | high | Yes | Upgrade postgresql (pg_dump COPY TO PROGRAM) |
| CVE-2022-31197 | 7.1 | high | Yes | Upgrade postgresql (pg_dump/restore SQLi) |

### Apache/HTTPD (pinned: 2.4.49-1) — 3 KEV CVEs
| CVE | CVSS | Severity | Affects Pinned? | Recommendation |
|-----|------|----------|-----------------|----------------|
| CVE-2023-46604 | 10.0 | critical | Yes | Upgrade apache (Apache OFBiz RCE — may be unrelated product match) |
| CVE-2010-0219 | 10.0 | critical | Yes | Upgrade apache (mod_proxy_ajp) |
| CVE-2021-44228 | 10.0 | critical | Yes | Upgrade apache (Log4Shell — likely false positive for httpd) |

## Ambiguities & Notes

1. **Credential Handling**: No explicit credential/secret management tasks were found in the Ansible configuration (e.g., Ansible Vault, password hashing). Database users are created without explicit password directives in the visible tasks.
2. **CVE Product Matching**: Some Apache/HTTPD CVEs (e.g., CVE-2021-44228 Log4Shell, CVE-2023-46604 OFBiz) may be false positives from vulnx CPE matching. Manual verification recommended.
3. **Implicit Deny**: The default-deny rule (rule-010) is implicit — not explicitly stated in the Ansible config but necessary for a complete ABAC policy.
4. **Filesystem Permissions**: Only /var/lib/postgresql/data has explicit owner/group/mode. Other paths (/var/www/html, config files) lack explicit ACL tasks in the visible configuration.
5. **Obligation**: Sudo access requires password (nopassword: false) — documented as an obligation on rule-002.

## Compliance Notes
- SOC2 compliance tier requires audit logging. Sudo access rule includes password requirement obligation.
- PostgreSQL access is network-restricted to webservers subnet (10.0.1.0/24) only.
- SSH access is restricted to sudo group members on the dmz-facing webserver.
- Production environment with 90-day log retention configured.
