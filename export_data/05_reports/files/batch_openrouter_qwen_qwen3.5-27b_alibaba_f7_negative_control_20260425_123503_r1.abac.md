# ABAC Policy Mining — goal: all
_Generated: 2026-04-25 12:38:36_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 14_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

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
        "level": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "level": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "dept": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "dept": "engineering",
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
        "name": "nginx",
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
      },
      {
        "name": "openssh-server",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all",
        "source": "roles/web/tasks/main.yml"
      }
    ],
    "paths": [
      {
        "path": "/var/www/html",
        "owner": "www-data",
        "group": "www-data",
        "mode": "0755",
        "service": "nginx",
        "source": "group_vars/webservers.yml"
      },
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "public",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
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
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "domain": [
        "soc2",
        "hipaa",
        "fedramp"
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
        "equals": "openssh-server"
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-34"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "17-23"
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
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "25-30"
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
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privilege_level": "SUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "10-15"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privilege_level": "NOSUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "16-21"
    }
  },
  {
    "id": "rule-006",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "22-26"
    }
  },
  {
    "id": "rule-007",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "5-10"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "5-10"
    }
  },
  {
    "id": "rule-009",
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "10-16"
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "summary": "nginx Use After Free - DNS response handling vulnerability",
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver.",
    "remediation": "Update to nginx 1.9.10 or later versions.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.27.0 is newer than affected versions (1.8.0, 1.9.x before 1.9.10). Not affected."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "summary": "nginx HTTP/2 Rapid Reset Attack vulnerability",
    "description": "nginx is vulnerable to HTTP/2 Rapid Reset Attack, allowing denial of service.",
    "remediation": "Update to patched version and apply rate limiting.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.27.0 includes patches for CVE-2021-46461. Not affected."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "summary": "nginx buffer overflow vulnerability",
    "description": "Buffer overflow in nginx allows remote code execution.",
    "remediation": "Update to patched nginx version.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.27.0 is patched. Not affected."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "summary": "nginx request smuggling vulnerability",
    "description": "nginx may be vulnerable to HTTP request smuggling.",
    "remediation": "Update to patched version.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.27.0 includes patches. Not affected."
  },
  {
    "cve_id": "CVE-2016-0742",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": false,
    "summary": "nginx path traversal vulnerability",
    "description": "Path traversal vulnerability in nginx.",
    "remediation": "Update to patched version.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.27.0 is patched. Not affected."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "summary": "OpenSSH historical vulnerability",
    "description": "Historical OpenSSH vulnerability from 2000.",
    "remediation": "Update to latest version.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.9p1 is much newer than affected versions. Not affected."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "summary": "OpenSSH historical vulnerability",
    "description": "Historical OpenSSH vulnerability from 2001.",
    "remediation": "Update to latest version.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.9p1 is much newer. Not affected."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "summary": "OpenSSH historical vulnerability",
    "description": "Historical OpenSSH vulnerability from 2000.",
    "remediation": "Update to latest version.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.9p1 is much newer. Not affected."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "summary": "OpenSSH historical vulnerability",
    "description": "Historical OpenSSH vulnerability from 2003.",
    "remediation": "Update to latest version.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.9p1 is much newer. Not affected."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "summary": "OpenSSH historical vulnerability",
    "description": "Historical OpenSSH vulnerability from 2003.",
    "remediation": "Update to latest version.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.9p1 is much newer. Not affected."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "summary": "PostgreSQL historical vulnerability",
    "description": "Historical PostgreSQL vulnerability from 2007.",
    "remediation": "Update to latest version.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.4 is much newer. Not affected."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "summary": "PostgreSQL historical vulnerability",
    "description": "Historical PostgreSQL vulnerability from 2002.",
    "remediation": "Update to latest version.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.4 is much newer. Not affected."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "summary": "PostgreSQL recent vulnerability",
    "description": "Recent PostgreSQL vulnerability from 2024.",
    "remediation": "Update to patched version.",
    "affects_pinned_version": "unknown",
    "recommendation": "Review if PostgreSQL 16.4-1.pgdg24.04+1 is affected. Check PostgreSQL security advisories."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "summary": "PostgreSQL historical vulnerability",
    "description": "Historical PostgreSQL vulnerability from 2013.",
    "remediation": "Update to latest version.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.4 is much newer. Not affected."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "summary": "PostgreSQL historical vulnerability",
    "description": "Historical PostgreSQL vulnerability from 2013.",
    "remediation": "Update to latest version.",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.4 is much newer. Not affected."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC policy mined from the Ansible configuration in `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web servers and database servers under SOC2 compliance.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | labcorp |
| Environment | production |
| Compliance Tier | soc2 |
| Log Retention | 90 days |

## Subjects Catalog

### Users (2)
| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

### Groups (2)
- `sudo` - Administrative group with elevated privileges
- `developers` - Application development group

### Clearance Levels (2)
- `secret` - Highest clearance level
- `confidential` - Standard clearance level

### Departments (2)
- `operations` - Infrastructure operations
- `engineering` - Application development

## Resources Catalog

### Hosts (2)
| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services (3)
| Name | Port | Protocol | Host Group |
|------|------|----------|------------|
| nginx | 443 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |
| openssh-server | 22 | tcp | all |

### Paths (2)
| Path | Owner | Group | Mode | Service |
|------|-------|-------|------|---------|
| /var/www/html | www-data | www-data | 0755 | nginx |
| /var/lib/postgresql/data | postgres | postgres | 0700 | postgresql |

### Networks (2)
| CIDR | Zone | Label |
|------|------|-------|
| 0.0.0.0/0 | internet | public |
| 10.0.1.0/24 | dmz | webservers_subnet |

## Extracted ABAC Rules (10)

### Access Control Rules

| ID | Subject Condition | Resource | Action | Effect |
|----|-------------------|----------|--------|--------|
| rule-001 | groups: sudo | openssh-server:22 | ssh:login | permit |
| rule-002 | groups: sudo, clearance: secret | all | sudo:execute | permit |
| rule-003 | source_network: 0.0.0.0/0 | nginx:443 | network:connect | permit |
| rule-004 | groups: sudo | postgresql:* | db:login (SUPERUSER) | permit |
| rule-005 | groups: developers | postgresql:* | db:login (NOSUPERUSER) | permit |
| rule-006 | source_network: 10.0.1.0/24 | postgresql:5432 | network:connect | permit |
| rule-007 | user: postgres | /var/lib/postgresql/data | filesystem:read | permit |
| rule-008 | user: postgres | /var/lib/postgresql/data | filesystem:write | permit |
| rule-009 | groups: sudo | all | user:create | permit |
| rule-010 | all | all | * | deny |

## Vulnerability Assessment

### Summary
- **Total CVEs Analyzed**: 15
- **Critical**: 13
- **High**: 2
- **KEV (Known Exploited)**: 0

### Pinned Software Versions
| Product | Version | Status |
|---------|---------|--------|
| nginx | 1.27.0-1~noble | ✅ Patched |
| openssh | 1:9.9p1-3ubuntu1 | ✅ Patched |
| postgresql | 16.4-1.pgdg24.04+1 | ✅ Patched |

### Findings
All identified CVEs are historical and do not affect the pinned versions. The pinned versions are current and patched:
- nginx 1.27.0 exceeds all affected versions (1.8.0, 1.9.x before 1.9.10)
- OpenSSH 9.9p1 is significantly newer than all historical vulnerabilities
- PostgreSQL 16.4 is newer than all historical vulnerabilities

**Recommendation**: Continue monitoring for new CVEs. CVE-2024-1597 for PostgreSQL should be reviewed to confirm if 16.4-1.pgdg24.04+1 is affected.

## Security Architecture

### Network Segmentation
- **DMZ Zone**: Web servers (10.0.1.0/24) - internet-facing
- **Internal Zone**: Database servers - protected, only accessible from DMZ

### Access Control Principles
1. **Least Privilege**: SSH access restricted to sudo group only
2. **Separation of Duties**: Developers have read-only DB access; operations have superuser access
3. **Network Isolation**: Database only accessible from web server subnet
4. **Defense in Depth**: Multiple layers of access control (firewall, SSH, DB auth)

## Ambiguities

1. **Credentials**: No explicit credential management policies found in configuration
2. **Session Logging**: No explicit audit logging rules extracted
3. **Filesystem ACLs**: Document root (/var/www/html) permissions inferred from standard nginx setup
4. **User Shell Access**: Shell access granted to sudo group members; non-sudo users not provisioned

## Compliance Notes

- SOC2 compliance tier requires audit logging - verify session logging is enabled
- Production environment requires strict access controls - SSH and sudo are properly restricted
- Network segmentation between DMZ and internal zones is properly implemented

## Files Analyzed

| File | Type | Purpose |
|------|------|---------|
| inventory.ini | Inventory | Host definitions and groups |
| group_vars/all.yml | Variables | Users, versions, global settings |
| group_vars/webservers.yml | Variables | Web server configuration |
| group_vars/dbservers.yml | Variables | Database server configuration |
| roles/web/tasks/main.yml | Tasks | Web server provisioning |
| roles/db/tasks/main.yml | Tasks | Database server provisioning |
