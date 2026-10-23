# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:26:52_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 12_  
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
        "domain": {
          "clearance": [
            "secret",
            "confidential"
          ],
          "department": [
            "operations",
            "engineering"
          ]
        },
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
        "domain": {
          "clearance": [
            "secret",
            "confidential"
          ],
          "department": [
            "operations",
            "engineering"
          ]
        },
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
        "domain": {
          "role": [
            "frontend",
            "primary"
          ],
          "zone": [
            "dmz",
            "internal"
          ]
        },
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": "dbservers",
        "domain": {
          "role": [
            "frontend",
            "primary"
          ],
          "zone": [
            "dmz",
            "internal"
          ]
        },
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
      }
    ],
    "paths": [
      {
        "path": "/var/www/html",
        "owner": null,
        "group": null,
        "mode": null,
        "service": "httpd",
        "source": "group_vars/webservers.yml"
      },
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql",
        "source": "group_vars/dbservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet_facing",
        "source": "group_vars/webservers.yml"
      }
    ]
  },
  "environment": {
    "org": "labcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "inventory.ini,group_vars/all.yml"
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
        "equals": "ssh"
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
      "lines": "40-44"
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "audit",
        "description": "All sudo commands logged"
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "26-31"
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
      "service": {
        "equals": "httpd"
      },
      "port": {
        "equals": 80
      },
      "inventory_group": {
        "equals": "webservers"
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
      "task": "Firewall — allow HTTP from internet",
      "lines": "33-38"
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
      "applies_to": {
        "equals": "all"
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
      "lines": "16-22"
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
      "lines": "14-18"
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
      "lines": "20-24"
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
      "lines": "26-29"
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
      "lines": "7-12"
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
      "compliance_tier": {
        "equals": "soc2"
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
        "equals": "httpd"
      },
      "port": {
        "equals": 80
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
    "cve_id": "CVE-1999-0067",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade Apache HTTPD to latest patched version"
  },
  {
    "cve_id": "CVE-1999-0926",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade Apache HTTPD to latest patched version"
  },
  {
    "cve_id": "CVE-1999-1199",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade Apache HTTPD to latest patched version"
  },
  {
    "cve_id": "CVE-2013-2250",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade Apache HTTPD to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1777",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade Apache HTTPD to latest patched version"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to latest version"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to latest version"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to latest version"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to latest version"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to latest version"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to latest version"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to latest version"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to latest version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to latest version"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to latest version"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the Ansible configuration. The configuration manages a production environment with web servers and database servers under SOC2 compliance.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | labcorp |
| Environment | production |
| Compliance Tier | soc2 |
| Log Retention | 90 days |

## Subjects (Users & Groups)

### Users
| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

### Groups
- `sudo` - Administrative access group
- `developers` - Application development group

### Clearance Levels
- `secret` - Highest clearance (admin)
- `confidential` - Standard clearance (appuser)

## Resources

### Hosts
| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services
| Name | Port | Protocol | Host Group |
|------|------|----------|------------|
| httpd | 80 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |

### Filesystem Paths
| Path | Owner | Group | Mode | Service |
|------|-------|-------|------|---------|
| /var/www/html | - | - | - | httpd |
| /var/lib/postgresql/data | postgres | postgres | 0700 | postgresql |

### Networks
| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | webservers_subnet |
| 0.0.0.0/0 | internet | internet_facing |

## Extracted ABAC Rules

| Rule ID | Action | Effect | Subject | Resource |
|---------|--------|--------|---------|----------|
| rule-001 | ssh:login | permit | groups in [sudo] | ssh service |
| rule-002 | sudo:execute | permit | groups in [sudo], clearance=secret | all |
| rule-003 | network:connect | permit | source=0.0.0.0/0 | httpd:80 on webservers |
| rule-004 | user:create | permit | groups in [sudo] | all |
| rule-005 | db:login | permit | groups in [sudo] | postgresql SUPERUSER |
| rule-006 | db:login | permit | groups in [developers] | postgresql NOSUPERUSER |
| rule-007 | network:connect | permit | source=10.0.1.0/24 | postgresql:5432 |
| rule-008 | filesystem:read | permit | user=postgres | /var/lib/postgresql/data |
| rule-009 | * | deny | all | all |

## Vulnerability Assessment

### Pinned Software Versions
| Product | Version |
|---------|---------|
| Apache HTTPD | 2.4.49-1 |
| OpenSSH | 9.6p1-3ubuntu1 |
| PostgreSQL | 16.2-1.pgdg22.04+1 |

### Critical Vulnerabilities Found
- **CVE-1999-0067**: apache - critical (CVSS: 10)
- **CVE-1999-0926**: apache - critical (CVSS: 10)
- **CVE-1999-1199**: apache - critical (CVSS: 10)
- **CVE-2013-2250**: apache - critical (CVSS: 10)
- **CVE-2013-1777**: apache - critical (CVSS: 10)

... and 10 more vulnerabilities

## Ambiguities & Notes

1. **Credentials**: No explicit credentials defined in Ansible configuration - database passwords and SSH keys are not visible in the configuration files.

2. **File Permissions**: The httpd document root (/var/www/html) owner/group/mode are not explicitly defined in the configuration.

3. **Default Deny**: An implicit default-deny rule is applied to all actions not explicitly permitted.

4. **Session Logging**: The configuration references a 90-day log retention policy but does not specify the logging mechanism or audit obligations.

## Compliance Notes

- All rules are scoped to `compliance_tier: soc2` as defined in the inventory
- SSH access is restricted to the `sudo` group only
- Database access is segregated by privilege level (SUPERUSER vs NOSUPERUSER)
- Network access follows a zero-trust model with explicit allow rules

## Recommendations

1. Upgrade pinned software versions to address known vulnerabilities
2. Define explicit file permissions for /var/www/html
3. Implement centralized audit logging for SOC2 compliance
4. Consider implementing network segmentation between dmz and internal zones
