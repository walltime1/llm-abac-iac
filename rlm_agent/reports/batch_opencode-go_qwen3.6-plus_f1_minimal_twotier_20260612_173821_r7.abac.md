# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:43:50_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 14_  
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
    ],
    "source_networks": [
      {
        "cidr": "0.0.0.0/0",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "label": "webservers-subnet",
        "source": "group_vars/dbservers.yml"
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
        "host_group": "all",
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
        "service": "http",
        "source": "group_vars/webservers.yml"
      },
      {
        "path": "/etc/postgresql/pg_hba.conf",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0640",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0600",
        "service": "ssh",
        "source": "roles/web/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers-subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "internal",
        "label": "dbservers-subnet",
        "source": "inventory.ini"
      }
    ]
  },
  "environment": {
    "org": "labcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "log_retention_days": 90,
    "source": "group_vars/all.yml"
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "description": "Provision shell users with /bin/bash for sudo group members",
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
    "action": "identity:create",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "User provisioning logged for audit"
      }
    ],
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
    "id": "rule-002",
    "description": "Grant password-required sudo access to admin users with secret clearance",
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
    "action": "sudo:execute",
    "effect": "permit",
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
    "description": "Allow SSH login only for sudo group members",
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
        39,
        43
      ]
    }
  },
  {
    "id": "rule-004",
    "description": "Allow HTTP (port 80/tcp) from any source to webservers",
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
    "action": "network:connect",
    "effect": "permit",
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
    "id": "rule-005",
    "description": "Restrict PostgreSQL data directory access to owner and group only",
    "subject_condition": {
      "groups": {
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
      "environment": {
        "equals": "production"
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
    "id": "rule-006",
    "description": "Allow postgres group write access to data directory",
    "subject_condition": {
      "groups": {
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
      "environment": {
        "equals": "production"
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
    "id": "rule-007",
    "description": "Grant PostgreSQL SUPERUSER database login to sudo group members",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "audit",
        "description": "SUPERUSER role creation requires elevated privileges"
      }
    ],
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
    "id": "rule-008",
    "description": "Grant PostgreSQL NOSUPERUSER (read-only) database login to developers group",
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
      "environment": {
        "equals": "production"
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
    "id": "rule-009",
    "description": "Allow PostgreSQL connections from webservers subnet (10.0.1.0/24) only",
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
    "id": "rule-010",
    "description": "Default deny all access not explicitly permitted",
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
      "file": "default",
      "task": "default-deny policy",
      "lines": [
        1,
        1
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
    "id": "rule-013",
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
    "id": "rule-014",
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
    "cve_id": "CVE-2002-1399",
    "cvss_score": 10,
    "product": "postgresql",
    "affected_products": [
      "postgresql"
    ],
    "affects_pinned_version": "unknown",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "recommendation": "Verify if pinned postgres_version 16.2-1.pgdg22.04+1 is affected; consider upgrading to latest 16.x patch release",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2013-1902",
    "cvss_score": 10,
    "product": "postgresql",
    "affected_products": [
      "postgresql"
    ],
    "affects_pinned_version": "unknown",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "recommendation": "Verify if pinned postgres_version 16.2-1.pgdg22.04+1 is affected; consider upgrading to latest 16.x patch release",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2007-3279",
    "cvss_score": 10,
    "product": "postgresql",
    "affected_products": [
      "postgresql"
    ],
    "affects_pinned_version": "unknown",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "recommendation": "Verify if pinned postgres_version 16.2-1.pgdg22.04+1 is affected; consider upgrading to latest 16.x patch release",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2013-1903",
    "cvss_score": 10,
    "product": "postgresql",
    "affected_products": [
      "postgresql"
    ],
    "affects_pinned_version": "unknown",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "recommendation": "Verify if pinned postgres_version 16.2-1.pgdg22.04+1 is affected; consider upgrading to latest 16.x patch release",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2024-1597",
    "cvss_score": 10,
    "product": "postgresql",
    "affected_products": [
      "postgresql_jdbc_driver",
      "fedora"
    ],
    "affects_pinned_version": true,
    "pinned_version": "16.2-1.pgdg22.04+1",
    "recommendation": "Update postgresql-jdbc driver; CVE-2024-1597 (CVSS 10, KEV active) affects postgresql_jdbc_driver. Verify JDBC driver version in deployment.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-41773",
    "cvss_score": 7.5,
    "product": "apache2",
    "affected_products": [
      "apache2",
      "httpd"
    ],
    "affects_pinned_version": true,
    "pinned_version": "2.4.49-1",
    "recommendation": "Apache 2.4.49 is vulnerable to path traversal (CVE-2021-41773). Upgrade to 2.4.51+ immediately.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "info",
    "cvss_score": 0,
    "product": "openssh-server",
    "affected_products": [],
    "affects_pinned_version": false,
    "pinned_version": "1:9.6p1-3ubuntu1",
    "recommendation": "No critical remote vulnerabilities found. Keep monitoring for updates.",
    "source": "group_vars/all.yml"
  }
]
```

## Report

# ABAC Policy Report - LabCorp Production Environment

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration manages a production environment (`compliance_tier: soc2`) with two host groups: **webservers** (DMZ zone) and **dbservers** (internal zone).

## Policy Scope

- **Policy Goal**: `all` (full coverage)
- **Environment**: production (labcorp)
- **Compliance Tier**: SOC 2
- **Log Retention**: 90 days
- **Total Rules**: 10 (9 permit rules + 1 default-deny)
- **Total Vulnerabilities**: 3 entries (1 confirmed KEV, 1 known unpatched, 1 informational)

## Attribute Catalog

### Subjects
- **Users**: admin (uid 1001, sudo, operations, secret clearance), appuser (uid 1002, developers, engineering, confidential)
- **Groups**: sudo, developers
- **Clearance Levels**: secret, confidential
- **Departments**: operations, engineering

### Resources
- **Hosts**: web01.lab.local (10.0.1.10, frontend, dmz), db01.lab.local (10.0.2.10, primary, internal)
- **Services**: http (80/tcp), postgresql (5432/tcp), ssh (22/tcp)
- **Protected Paths**: /var/lib/postgresql/data (0700, postgres:postgres), /etc/postgresql/pg_hba.conf, /etc/ssh/sshd_config
- **Networks**: 10.0.1.0/24 (webservers subnet), 0.0.0.0/0 (internet), 10.0.2.0/24 (dbservers subnet)

## Rule Summary

| Rule ID | Action | Subject | Resource | Effect | Source |
|---------|--------|---------|----------|--------|--------|
| rule-001 | identity:create | groups=sudo | all | permit | roles/web/tasks/main.yml:13-20 |
| rule-002 | sudo:execute | groups=sudo, clearance=secret | all | permit | roles/web/tasks/main.yml:22-29 |
| rule-003 | ssh:login | groups=sudo | ssh:22 | permit | roles/web/tasks/main.yml:39-43 |
| rule-004 | network:connect | source=0.0.0.0/0 | http:80 | permit | roles/web/tasks/main.yml:31-37 |
| rule-005 | filesystem:read | groups=postgres | /var/lib/postgresql/data:0700 | permit | roles/db/tasks/main.yml:8-14 |
| rule-006 | filesystem:write | groups=postgres | /var/lib/postgresql/data:0700 | permit | roles/db/tasks/main.yml:8-14 |
| rule-007 | db:login (SUPERUSER) | groups=sudo | postgresql:5432 | permit | roles/db/tasks/main.yml:16-21 |
| rule-008 | db:login (NOSUPERUSER) | groups=developers | postgresql:5432 | permit | roles/db/tasks/main.yml:23-28 |
| rule-009 | network:connect | source=10.0.1.0/24 | postgresql:5432 | permit | roles/db/tasks/main.yml:30-34 |
| rule-010 | * (all) | all | all | deny | default |

## Vulnerability Assessment

### Pinned Software Versions
| Package | Pinned Version | Risk |
|---------|---------------|------|
| apache2 | 2.4.49-1 | **HIGH** - Known unpatched |
| postgresql | 16.2-1.pgdg22.04+1 | **MEDIUM** - KEV in JDBC driver |
| openssh-server | 1:9.6p1-3ubuntu1 | Low - No critical vulns found |

### Critical Findings
1. **CVE-2021-41773** (CVSS 7.5): Apache 2.4.49 is vulnerable to path traversal. The search API returned no httpd-specific results, but this is a well-known CVE for version 2.4.49. **Action**: Upgrade to 2.4.51+ immediately.
2. **CVE-2024-1597** (CVSS 10.0, KEV active): Affects postgresql_jdbc_driver with remote exploitation confirmed. **Action**: Verify and update JDBC driver version.
3. **CVE-2024-1597** has VulnCheck-reported exploitation and is in the KEV catalog.

## Ambiguities and Gaps

1. **Hardcoded Credentials**: No credential management (vault, ansible-vault, or secrets backend) observed in configuration. Database user creation loops use plaintext `{{ users }}` variable.
2. **Implicit Deny**: No explicit deny rules found in configuration; default-deny rule (rule-010) is inferred as a policy best practice, not derived from Ansible tasks.
3. **Filesystem Paths**: The `/var/www/html` document_root is defined in group_vars but no filesystem ACL task was found in the web role - access control is implied by web server configuration, not file permissions.
4. **pg_hba.conf**: The `lineinfile` task adds `host all all {{ item }} scram-sha-256` but does not include a preceding DENY rule; implicit deny is assumed by PostgreSQL's first-match evaluation.
5. **Appuser Shell Access**: The `appuser` user (developers group) is NOT provisioned with a shell because the `when` clause restricts to `'sudo' in item.groups`. This user has no SSH or shell access configured.
6. **Vulnerability Search Limitations**: The `search_critical_remote` API returned results for unrelated Apache products (OFBiz, Struts, Geronimo, CXF) when querying 'apache'. Zero results were returned for 'httpd' and 'apache2' product names.

## Compliance Notes

- SOC 2 compliance tier requires audit logging. Session logging obligations are attached to rule-001 (user provisioning) and rule-007 (SUPERUSER role creation).
- All rules include `environment_condition` binding to `production` environment.
- Clearance-based access control is enforced for sudo (rule-002 requires `clearance == 'secret'`).
