# ABAC Policy Mining — goal: all
_Generated: 2026-04-25 12:26:09_  
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
  },
  "package_versions": {
    "httpd": "2.4.49-1",
    "openssh": "1:9.6p1-3ubuntu1",
    "postgresql": "16.2-1.pgdg22.04+1",
    "source": "group_vars/all.yml"
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "name": "SSH login for sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "openssh"
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
      "lines": "35-39"
    }
  },
  {
    "id": "rule-002",
    "name": "Sudo execute for admin users",
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
    "obligations": [
      {
        "type": "nopassword",
        "value": false
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "27-32"
    }
  },
  {
    "id": "rule-003",
    "name": "PostgreSQL SUPERUSER access",
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
      "privilege_level": {
        "equals": "SUPERUSER"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "14-19"
    }
  },
  {
    "id": "rule-004",
    "name": "PostgreSQL read-only access",
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
      "privilege_level": {
        "equals": "NOSUPERUSER"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "21-26"
    }
  },
  {
    "id": "rule-005",
    "name": "PostgreSQL network access from webservers",
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
      "lines": "28-32"
    }
  },
  {
    "id": "rule-006",
    "name": "HTTP access from internet",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": "34-39"
    }
  },
  {
    "id": "rule-007",
    "name": "PostgreSQL data directory access",
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-13"
    }
  },
  {
    "id": "rule-008",
    "name": "Default deny all",
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
      "task": "default-deny policy",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": false,
    "reason": "CVE affects SSH1 protocol; pinned version 9.6p1 uses SSH2",
    "recommendation": "No action needed - version uses SSH2 protocol"
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": false,
    "reason": "CVE affects SSH1 CRC-32; pinned version 9.6p1 uses SSH2",
    "recommendation": "No action needed - version uses SSH2 protocol"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2022-31197",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "affects_pinned_version": false,
    "reason": "CVE affects PostgreSQL JDBC Driver (Java library), not PostgreSQL server",
    "recommendation": "No action needed for server - monitor JDBC driver versions if used"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the Ansible configuration repository for **labcorp** in the **production** environment with **SOC2** compliance tier.

### Configuration Sources Analyzed
- `inventory.ini` - Host inventory and environment variables
- `group_vars/all.yml` - Organization-wide settings and user definitions
- `group_vars/dbservers.yml` - Database server configuration
- `group_vars/webservers.yml` - Web server configuration
- `roles/db/tasks/main.yml` - PostgreSQL setup and access control
- `roles/web/tasks/main.yml` - Apache, SSH, and firewall configuration

## Attribute Catalog

### Subjects
| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

**Groups defined:** sudo, developers

### Resources

#### Hosts
| Hostname | IP | Role | Zone |
|----------|-----|------|------|
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| db01.lab.local | 10.0.2.10 | primary | internal |

#### Services
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| httpd | 80 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |

#### Filesystem Paths
| Path | Owner | Group | Mode |
|------|-------|-------|------|
| /var/www/html | www-data | www-data | 0755 |
| /var/lib/postgresql/data | postgres | postgres | 0700 |

#### Networks
| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | webservers_subnet |
| 0.0.0.0/0 | external | internet |

### Environment
- **Organization:** labcorp
- **Environment:** production
- **Compliance Tier:** soc2
- **Log Retention:** 90 days

## Policy Rules

### Authentication & Authorization

| Rule ID | Action | Subject Condition | Resource | Effect |
|---------|--------|-------------------|----------|--------|
| rule-001 | ssh:login | groups contains "sudo" | openssh:22 | permit |
| rule-002 | sudo:execute | groups contains "sudo" AND clearance="secret" | all | permit |
| rule-003 | db:login | groups contains "sudo" | postgresql:5432 (SUPERUSER) | permit |
| rule-004 | db:login | groups contains "developers" | postgresql:5432 (NOSUPERUSER) | permit |

### Network Access

| Rule ID | Action | Source | Destination | Effect |
|---------|--------|--------|-------------|--------|
| rule-005 | network:connect | 10.0.1.0/24 | postgresql:5432 | permit |
| rule-006 | network:connect | 0.0.0.0/0 | httpd:80 | permit |

### Filesystem

| Rule ID | Action | Path | Permissions | Effect |
|---------|--------|------|-------------|--------|
| rule-007 | filesystem:read | /var/lib/postgresql/data | 0700 (owner only) | permit |

### Default Policy

| Rule ID | Action | Effect |
|---------|--------|--------|
| rule-008 | * (all) | deny |

## Vulnerability Assessment

### Pinned Software Versions
| Product | Version |
|---------|---------|
| httpd | 2.4.49-1 |
| openssh | 1:9.6p1-3ubuntu1 |
| postgresql | 16.2-1.pgdg22.04+1 |

### Vulnerability Findings

#### OpenSSH
| CVE | Severity | CVSS | Affects Version | Recommendation |
|-----|----------|------|-----------------|----------------|
| CVE-2000-0999 | Critical | 10.0 | No (SSH1 only) | No action needed |
| CVE-2001-0144 | Critical | 10.0 | No (SSH1 only) | No action needed |

**Analysis:** The critical CVEs found for OpenSSH target SSH1 protocol. The pinned version (9.6p1) uses SSH2 protocol exclusively, so these vulnerabilities do not apply.

#### PostgreSQL
| CVE | Severity | CVSS | Affects Version | Recommendation |
|-----|----------|------|-----------------|----------------|
| CVE-2022-31197 | High | 7.1 | No (JDBC driver) | No action for server |

**Analysis:** CVE-2022-31197 affects the PostgreSQL JDBC Driver (Java library), not the PostgreSQL server itself. No action needed for the server unless JDBC drivers are in use.

#### HTTPD
No critical or high-severity remote vulnerabilities found for httpd 2.4.49-1.

## Ambiguities & Recommendations

### Ambiguities
1. **Web document root permissions:** The path `/var/www/html` is defined but explicit filesystem access rules for web content are not configured in the Ansible tasks.
2. **SSH key management:** No SSH key deployment tasks found - key distribution method is not defined.
3. **Password policy:** No password complexity or expiration policies defined in the configuration.
4. **Audit logging:** While log retention (90 days) is defined, specific audit logging configurations are not present.

### Security Recommendations
1. **Database access:** PostgreSQL allows connections only from the webserver subnet (10.0.1.0/24) - this is a good security practice.
2. **SSH restriction:** SSH access is properly restricted to the sudo group only.
3. **Sudo privileges:** Sudo access requires both group membership AND secret clearance level - good defense-in-depth.
4. **Default deny:** Implicit default-deny policy is in place for all other access.
5. **Consider adding:**
   - Explicit web content filesystem rules
   - SSH key management automation
   - Password policy enforcement
   - Audit logging configuration

## Compliance Notes (SOC2)
- Log retention of 90 days meets minimum SOC2 requirements
- Access controls are role-based with clearance levels
- Network segmentation between DMZ and internal zones is enforced
- Default-deny policy aligns with least-privilege principle
