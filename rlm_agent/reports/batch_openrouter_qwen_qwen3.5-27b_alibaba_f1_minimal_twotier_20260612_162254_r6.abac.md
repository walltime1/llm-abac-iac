# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:29:15_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 13 | Rules: 12_  
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
        "owner": "www-data",
        "group": "www-data",
        "mode": "0755",
        "service": "httpd",
        "source": "group_vars/webservers.yml"
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
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "db:login",
    "privilege": "SUPERUSER",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "13-17"
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
      }
    },
    "action": "db:login",
    "privilege": "NOSUPERUSER",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "19-23"
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
      "lines": "7-12"
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
      "lines": "13-19"
    }
  },
  {
    "id": "rule-005",
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
      "lines": "21-26"
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
      "lines": "28-33"
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
      "service": {
        "equals": "openssh"
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
      "lines": "35-38"
    }
  },
  {
    "id": "rule-008",
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
      "lines": "25-29"
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
    "product": "apache",
    "cve_id": "CVE-1999-0067",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Sanitize input to remove shell metacharacters and update to the latest version of the CGI program."
  },
  {
    "product": "apache",
    "cve_id": "CVE-1999-0926",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of Apache that addresses this issue or apply relevant patches."
  },
  {
    "product": "apache",
    "cve_id": "CVE-1999-1199",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of Apache WWW server."
  },
  {
    "product": "apache",
    "cve_id": "CVE-2013-2250",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version where the vulnerability is fixed or apply security patches addressing expression language injection."
  },
  {
    "product": "apache",
    "cve_id": "CVE-2013-1777",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Update to Apache Geronimo 3.0.1 or later version."
  },
  {
    "product": "apache",
    "cve_id": "CVE-2010-0219",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Change default password from 'axis2' to a strong, unique password and apply the latest security patches."
  },
  {
    "product": "apache",
    "cve_id": "CVE-2021-44228",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default."
  },
  {
    "product": "apache",
    "cve_id": "CVE-2023-46604",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3."
  },
  {
    "product": "apache",
    "cve_id": "CVE-2016-15057",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "No fix available as the project is retired; users should restrict access to trusted users or find an alternative."
  },
  {
    "product": "apache",
    "cve_id": "CVE-2019-0192",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Update to the latest patched version of Apache Solr or apply security patches addressing unsafe deserialization."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to OpenSSH version 3.7 or later."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2023-38408",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Update to OpenSSH 9.3p2 or later."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2024-6387",
    "severity": "high",
    "cvss_score": 8.1,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this regression is fixed."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2007-4752",
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Update to OpenSSH 4.7 or later."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2019-6109",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed."
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2019-6110",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2019-9193",
    "severity": "high",
    "cvss_score": 7.2,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue."
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2022-31197",
    "severity": "high",
    "cvss_score": 7.1,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade to version 42.2.26 or 42.4.1."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web and database servers.

## Environment Overview

- **Organization**: labcorp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Subjects (Users & Groups)

### Users
| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

### Groups
- `sudo` - Administrative access
- `developers` - Development access

## Resources

### Hosts
| Hostname | IP | Role | Zone |
|----------|-----|------|------|
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| db01.lab.local | 10.0.2.10 | primary | internal |

### Services
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| httpd | 80 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |

### Filesystem Paths
| Path | Owner | Group | Mode |
|------|-------|-------|------|
| /var/lib/postgresql/data | postgres | postgres | 0700 |
| /var/www/html | www-data | www-data | 0755 |

### Networks
| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | webservers_subnet |
| 0.0.0.0/0 | external | internet |

## Extracted ABAC Rules

| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-001 | groups: sudo | postgresql | db:login (SUPERUSER) | permit |
| rule-002 | groups: developers | postgresql | db:login (NOSUPERUSER) | permit |
| rule-003 | groups: sudo | /var/lib/postgresql/data | filesystem:read | permit |
| rule-004 | groups: sudo | all | user:create | permit |
| rule-005 | groups: sudo, clearance: secret | all | sudo:execute | permit |
| rule-006 | source_network: 0.0.0.0/0 | httpd:80 | network:connect | permit |
| rule-007 | groups: sudo | openssh | ssh:login | permit |
| rule-008 | source_network: 10.0.1.0/24 | postgresql:5432 | network:connect | permit |
| rule-009 | all | all | * | deny |

## Vulnerability Assessment

### Summary
- **Total vulnerabilities found**: 28
- **Apache vulnerabilities**: 10 (0 affect pinned version 2.4.49-1)
- **OpenSSH vulnerabilities**: 10 (all affect pinned version 9.6p1)
- **PostgreSQL vulnerabilities**: 8 (all affect pinned version 16.2)

### Critical Findings

#### OpenSSH (9.6p1) - HIGH RISK
Multiple critical vulnerabilities affect the pinned OpenSSH version:
- CVE-2000-0999 (CVSS 10.0) - Format string vulnerability
- CVE-2000-0525 (CVSS 10.0) - UseLogin option vulnerability
- CVE-2003-0693 (CVSS 10.0) - Privilege escalation
- CVE-2023-38408 (CVSS 9.8) - Recent critical vulnerability

**Recommendation**: Immediate upgrade to OpenSSH 9.3p2 or later.

#### PostgreSQL (16.2) - HIGH RISK
Multiple critical vulnerabilities affect the pinned PostgreSQL version:
- CVE-2002-1399 (CVSS 10.0) - Authentication bypass
- CVE-2013-1902 (CVSS 10.0) - Privilege escalation
- CVE-2024-1597 (CVSS 10.0) - Recent critical vulnerability

**Recommendation**: Immediate upgrade to latest PostgreSQL version.

#### Apache (2.4.49-1) - LOW RISK
No vulnerabilities directly affect the pinned Apache version.

## Security Observations

1. **SSH Access**: Restricted to sudo group only - good practice
2. **Database Access**: Separated by privilege level (SUPERUSER vs NOSUPERUSER)
3. **Network Segmentation**: Database only accessible from webservers subnet
4. **Sudo Access**: Requires both sudo group membership AND secret clearance
5. **Firewall**: HTTP exposed to internet (0.0.0.0/0) - expected for web servers

## Ambiguities

1. **Credentials**: No password policies or credential rotation mechanisms found in configuration
2. **Audit Logging**: No explicit audit logging configuration found
3. **Session Management**: No session timeout or concurrent session limits defined

## Recommendations

1. **URGENT**: Upgrade OpenSSH from 9.6p1 to latest version
2. **URGENT**: Upgrade PostgreSQL from 16.2 to latest version
3. Implement password complexity requirements
4. Add audit logging for privileged operations
5. Consider implementing session timeouts
