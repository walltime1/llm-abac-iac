# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:28:16_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 5 | Rules: 12_  
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
        "source": "roles/web/tasks/main.yml"
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
      "task": "Configure SSH access",
      "lines": "1-7"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "user": {
        "equals": "admin"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sudo"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "metadata": {
      "nopassword": true
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Configure sudoers",
      "lines": "9-15"
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "user": {
        "equals": "appuser"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "production"
      },
      "privilege": {
        "equals": "ALL"
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
      "task": "Create PostgreSQL users",
      "lines": "1-14"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "user": {
        "equals": "admin"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "production"
      },
      "privilege": {
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
      "task": "Create PostgreSQL users",
      "lines": "1-14"
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
      "task": "Configure pg_hba.conf",
      "lines": "16-21"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "not_equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Configure pg_hba.conf",
      "lines": "16-21"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/www/html"
      },
      "owner": {
        "equals": "www-data"
      },
      "group": {
        "equals": "www-data"
      },
      "mode": {
        "equals": "0755"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Set filesystem permissions",
      "lines": "17-23"
    }
  },
  {
    "id": "rule-008",
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Configure firewall",
      "lines": "25-30"
    }
  },
  {
    "id": "rule-009",
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
      "task": "Configure firewall",
      "lines": "32-37"
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
    "cve_id": "CVE-2022-31197",
    "product": "postgresql_jdbc_driver",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "is_kev": true,
    "description": "PostgreSQL JDBC Driver SQL Injection",
    "affects_pinned_version": false,
    "recommendation": "Upgrade PostgreSQL JDBC Driver to version 42.2.26 or 42.4.1 if used"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
This report documents the ABAC policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web and database servers.

## Environment
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
- `developers` - Development team

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

## Extracted Rules

### Access Control Rules
1. **SSH Access (rule-001)**: Users in `sudo` group can SSH login
2. **Sudo Access (rule-002)**: User `admin` has NOPASSWD sudo access
3. **Database Access (rule-003)**: User `appuser` has ALL privileges on production database
4. **Database Admin (rule-004)**: User `admin` has SUPERUSER privileges on production database

### Network Policies
5. **PostgreSQL Network (rule-005)**: Only 10.0.1.0/24 (webservers) can connect to PostgreSQL
6. **PostgreSQL Deny (rule-006)**: All other networks denied from PostgreSQL
7. **HTTP Access (rule-008)**: HTTP service open to internet (0.0.0.0/0)
8. **HTTPS Access (rule-009)**: HTTPS service open to internet (0.0.0.0/0)

### Filesystem Rules
9. **Web Root (rule-007)**: www-data group has read access to /var/www/html

### Default Policy
10. **Default Deny (rule-010)**: All other access denied

## Vulnerability Assessment

### Pinned Software Versions
- httpd: 2.4.49-1
- openssh: 1:9.6p1-3ubuntu1
- postgresql: 16.2-1.pgdg22.04+1

### Findings
| CVE | Product | Severity | Remote | KEV | Affects Version |
|-----|---------|----------|--------|-----|-----------------|
| CVE-2022-31197 | postgresql_jdbc_driver | High | Yes | Yes | No |

**Note**: CVE-2022-31197 affects the PostgreSQL JDBC Driver, not the PostgreSQL server itself. The pinned version 16.2-1.pgdg22.04+1 is not affected.

## Ambiguities & Recommendations

### Ambiguities
1. **Password Management**: Database user passwords are set to "changeme" - should be managed via secrets
2. **Firewall HTTPS Rule**: The firewall rule for HTTPS has `network: 0.0.0.0/0` and `permanent: auth` which appears to be a typo (should be `yes`)
3. **Missing SSH on dbservers**: SSH access control is only configured on webservers, not dbservers

### Recommendations
1. Implement proper secrets management for database passwords
2. Review and correct the HTTPS firewall rule configuration
3. Consider adding SSH access controls to database servers
4. Implement network segmentation between DMZ and internal zones
5. Add audit logging obligations to sensitive access rules

## Compliance Notes
- SOC2 compliance tier requires audit logging - consider adding session logging obligations
- Database access should be logged for compliance
- Sudo access without password should be reviewed for compliance requirements
