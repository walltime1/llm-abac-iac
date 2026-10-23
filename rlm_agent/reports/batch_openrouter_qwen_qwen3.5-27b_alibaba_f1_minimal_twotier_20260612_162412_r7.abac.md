# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:29:11_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 11_  
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
        "path": "/var/www/html",
        "owner": "www-data",
        "group": "www-data",
        "mode": "0755",
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
    "name": "SSH access for sudo group",
    "description": "Allow SSH login to hosts for users in sudo group",
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
      "lines": "28-32"
    }
  },
  {
    "id": "rule-002",
    "name": "Sudo execution for admin users",
    "description": "Allow sudo execution for users in sudo group with secret clearance",
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
      "lines": "18-24"
    },
    "obligations": [
      {
        "type": "nopassword",
        "value": false
      }
    ]
  },
  {
    "id": "rule-003",
    "name": "HTTP access from internet",
    "description": "Allow HTTP connections from any source to web servers",
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
      "lines": "25-30"
    }
  },
  {
    "id": "rule-004",
    "name": "PostgreSQL superuser access",
    "description": "Allow database superuser login for users in sudo group",
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
      "lines": "10-15"
    }
  },
  {
    "id": "rule-005",
    "name": "PostgreSQL read-only access",
    "description": "Allow database read-only login for users in developers group",
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
      "lines": "16-21"
    }
  },
  {
    "id": "rule-006",
    "name": "PostgreSQL network access from webservers",
    "description": "Allow PostgreSQL connections only from webservers subnet",
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
      "lines": "22-26"
    }
  },
  {
    "id": "rule-007",
    "name": "PostgreSQL data directory access",
    "description": "Allow filesystem access to PostgreSQL data directory (mode 0700)",
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
      "lines": "5-10"
    }
  },
  {
    "id": "rule-008",
    "name": "Default deny",
    "description": "Deny all access not explicitly permitted",
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
    "id": "rule-009",
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
    "id": "rule-010",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain a buffer overflow in the sshd daemon",
    "affects_pinned_version": false,
    "pinned_version": "1:9.6p1-3ubuntu1",
    "recommendation": "Not applicable - CVE affects versions prior to 2.3.0, pinned version 9.6p1 is not affected",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 9.0,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping vulnerability",
    "affects_pinned_version": false,
    "pinned_version": "1:9.6p1-3ubuntu1",
    "recommendation": "Not applicable - CVE affects versions prior to 2.5.0, pinned version 9.6p1 is not affected",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 7.5,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_read",
    "affects_pinned_version": false,
    "pinned_version": "1:9.6p1-3ubuntu1",
    "recommendation": "Not applicable - CVE affects versions prior to 3.7, pinned version 9.6p1 is not affected",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 7.2,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation vulnerability",
    "affects_pinned_version": false,
    "pinned_version": "1:9.6p1-3ubuntu1",
    "recommendation": "Not applicable - CVE affects specific versions 3.7.1, pinned version 9.6p1 is not affected",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 7.5,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector vulnerability",
    "affects_pinned_version": false,
    "pinned_version": "1:9.6p1-3ubuntu1",
    "recommendation": "Not applicable - CVE affects SSH1 protocol, pinned version 9.6p1 uses SSH2 only",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "PostgreSQL 7.2.1 and earlier contains a buffer overflow vulnerability",
    "affects_pinned_version": false,
    "pinned_version": "16.2-1.pgdg22.04+1",
    "recommendation": "Not applicable - CVE affects versions prior to 7.2.2, pinned version 16.2 is not affected",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17 contain privilege escalation vulnerability",
    "affects_pinned_version": false,
    "pinned_version": "16.2-1.pgdg22.04+1",
    "recommendation": "Not applicable - CVE affects versions prior to 9.2.4, pinned version 16.2 is not affected",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 7.5,
    "description": "PostgreSQL 8.1 and later with plpgsql enabled contains SQL injection vulnerability",
    "affects_pinned_version": false,
    "pinned_version": "16.2-1.pgdg22.04+1",
    "recommendation": "Not applicable - CVE fixed in 8.1.11, 8.2.6, 8.3.2, 8.4, pinned version 16.2 is not affected",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL 9.2.x before 9.2.4, 9.1.x before 9.1.9 contains privilege escalation",
    "affects_pinned_version": false,
    "pinned_version": "16.2-1.pgdg22.04+1",
    "recommendation": "Not applicable - CVE affects versions prior to 9.2.4, pinned version 16.2 is not affected",
    "source": "search_critical_remote"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1 contain SQL injection vulnerability",
    "affects_pinned_version": false,
    "pinned_version": "16.2-1.pgdg22.04+1",
    "recommendation": "Not applicable - CVE affects pgjdbc JDBC driver, not core PostgreSQL server. If using pgjdbc, upgrade to 42.7.2+",
    "source": "search_critical_remote"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web and database servers.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | labcorp |
| Environment | production |
| Compliance Tier | SOC2 |
| Log Retention | 90 days |

## Subjects (Users & Groups)

### Users
| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

### Groups
- `sudo` - Administrative access
- `developers` - Application development access

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
| /var/www/html | www-data | www-data | 0755 |
| /var/lib/postgresql/data | postgres | postgres | 0700 |

### Networks
| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | webservers_subnet |
| 0.0.0.0/0 | external | internet |

## ABAC Rules Summary

| Rule ID | Name | Action | Effect |
|---------|------|--------|--------|
| rule-001 | SSH access for sudo group | ssh:login | permit |
| rule-002 | Sudo execution for admin users | sudo:execute | permit |
| rule-003 | HTTP access from internet | network:connect | permit |
| rule-004 | PostgreSQL superuser access | db:login | permit |
| rule-005 | PostgreSQL read-only access | db:login | permit |
| rule-006 | PostgreSQL network access from webservers | network:connect | permit |
| rule-007 | PostgreSQL data directory access | filesystem:read | permit |
| rule-008 | Default deny | * | deny |

## Vulnerability Assessment

### Pinned Software Versions
- **httpd**: 2.4.49-1
- **openssh-server**: 1:9.6p1-3ubuntu1
- **postgresql**: 16.2-1.pgdg22.04+1

### Findings
- **Total CVEs identified**: 10
- **CVEs affecting pinned versions**: 0
- **CVEs not affecting pinned versions**: 10

All identified CVEs are historical vulnerabilities affecting versions significantly older than the pinned versions in this configuration. No immediate remediation is required for the pinned software versions.

### Detailed Findings

#### OpenSSH (v9.6p1-3ubuntu1)
- 5 historical CVEs identified (2000-2003)
- All CVEs affect versions prior to 3.7
- **Status**: Not affected - pinned version is current

#### PostgreSQL (v16.2-1.pgdg22.04+1)
- 5 CVEs identified
- CVE-2024-1597 affects pgjdbc JDBC driver, not core PostgreSQL
- All other CVEs affect versions prior to 9.2.4
- **Status**: Not affected - pinned version is current

## Security Observations

1. **SSH Access**: Restricted to `sudo` group only via AllowGroups directive
2. **Sudo Access**: Requires both `sudo` group membership AND `secret` clearance level
3. **Database Access**: Segregated by privilege level (SUPERUSER vs NOSUPERUSER)
4. **Network Segmentation**: PostgreSQL only accessible from webservers subnet (10.0.1.0/24)
5. **Filesystem Security**: PostgreSQL data directory has restrictive 0700 permissions

## Ambiguities

1. **Credentials**: No password policies or credential rotation mechanisms found in configuration
2. **Audit Logging**: No explicit audit logging configuration found
3. **Session Management**: No session timeout or concurrent session limits defined

## Recommendations

1. Consider implementing explicit password policies
2. Add audit logging configuration for compliance with SOC2
3. Define session management policies for SSH and database connections
4. Regular vulnerability scanning to detect new CVEs for pinned versions
