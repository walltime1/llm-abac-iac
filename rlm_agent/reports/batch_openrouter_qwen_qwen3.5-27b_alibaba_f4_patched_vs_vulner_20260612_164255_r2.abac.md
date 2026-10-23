# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:49:25_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 13_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

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
        "hostname": "web-new01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_patched",
        "source": "inventory.ini"
      },
      {
        "hostname": "web-old01.lab.local",
        "ip": "10.0.1.20",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_legacy",
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
        "source": "group_vars/webservers_patched.yml"
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
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers_patched.yml"
      }
    ]
  },
  "environment": {
    "org": "patchcorp",
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
      "inventory_group": {
        "any_of": [
          "webservers_patched",
          "webservers_legacy"
        ]
      },
      "service": {
        "equals": "sshd"
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
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "20-24"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers_patched"
      },
      "service": {
        "equals": "sshd"
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "20-24"
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
      "inventory_group": {
        "any_of": [
          "webservers_patched",
          "webservers_legacy"
        ]
      },
      "service": {
        "equals": "nginx"
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
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "14-19"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers_patched"
      },
      "service": {
        "equals": "nginx"
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "14-19"
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
      "inventory_group": {
        "equals": "dbservers"
      },
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
      "task": "Allow postgres only from web subnet",
      "lines": "14-19"
    }
  },
  {
    "id": "rule-006",
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
      "lines": "7-12"
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
      "lines": "7-12"
    }
  },
  {
    "id": "rule-008",
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
    "id": "rule-012",
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
    "summary": "OpenSSH vulnerability",
    "recommendation": "Upgrade to latest OpenSSH version"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "summary": "OpenSSH vulnerability",
    "recommendation": "Upgrade to latest OpenSSH version"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "summary": "OpenSSH vulnerability",
    "recommendation": "Upgrade to latest OpenSSH version"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "summary": "OpenSSH vulnerability",
    "recommendation": "Upgrade to latest OpenSSH version"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "summary": "OpenSSH vulnerability",
    "recommendation": "Upgrade to latest OpenSSH version"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "summary": "PostgreSQL vulnerability",
    "recommendation": "Upgrade to latest PostgreSQL version"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "summary": "PostgreSQL vulnerability",
    "recommendation": "Upgrade to latest PostgreSQL version"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "summary": "PostgreSQL vulnerability",
    "recommendation": "Upgrade to latest PostgreSQL version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "summary": "PostgreSQL vulnerability",
    "recommendation": "Upgrade to latest PostgreSQL version"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "summary": "PostgreSQL vulnerability",
    "recommendation": "Upgrade to latest PostgreSQL version"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "nginx",
    "severity": "critical",
    "summary": "Nginx vulnerability",
    "recommendation": "Upgrade to nginx 1.24.0 or later"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "severity": "critical",
    "summary": "Nginx vulnerability",
    "recommendation": "Upgrade to nginx 1.24.0 or later"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "critical",
    "summary": "Nginx vulnerability",
    "recommendation": "Upgrade to nginx 1.24.0 or later"
  },
  {
    "cve_id": "CVE-2021-22946",
    "product": "nginx",
    "severity": "critical",
    "summary": "Nginx vulnerability",
    "recommendation": "Upgrade to nginx 1.24.0 or later"
  },
  {
    "cve_id": "CVE-2019-20372",
    "product": "nginx",
    "severity": "critical",
    "summary": "Nginx vulnerability",
    "recommendation": "Upgrade to nginx 1.24.0 or later"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web servers (patched and legacy) and database servers.

## Environment Overview

- **Organization**: patchcorp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Subjects

### Users
| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

### Groups
- sudo
- developers

## Resources

### Hosts
| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services
- nginx (port 443/tcp) on webservers
- postgresql (port 5432/tcp) on dbservers

### Filesystem Paths
- `/var/lib/postgresql/data` (owner: postgres, mode: 0700)

### Networks
- 10.0.1.0/24 (dmz zone) - web subnet
- 0.0.0.0/0 (external) - internet

## Access Rules Summary

| Rule ID | Action | Effect | Subject | Resource |
|---------|--------|--------|---------|----------|
| rule-001 | ssh:login | permit | groups: sudo | webservers (sshd) |
| rule-002 | ssh:login | permit | groups: sudo | webservers_patched (sshd) |
| rule-003 | network:connect | permit | source: 0.0.0.0/0 | webservers (nginx:443) |
| rule-004 | network:connect | permit | source: 0.0.0.0/0 | webservers_patched (nginx:443) |
| rule-005 | network:connect | permit | source: 10.0.1.0/24 | dbservers (postgresql:5432) |
| rule-006 | filesystem:read | permit | user: postgres | /var/lib/postgresql/data |
| rule-007 | filesystem:write | permit | user: postgres | /var/lib/postgresql/data |
| rule-008 | * | deny | all | all |

## Vulnerability Assessment

### Critical Vulnerabilities Found: 15

#### OpenSSH (5 critical)
- CVE-2000-0999, CVE-2000-0525, CVE-2003-0693, CVE-2003-0786, CVE-2001-0144
- **Recommendation**: Upgrade to latest OpenSSH version

#### PostgreSQL (5 critical)
- CVE-2002-1399, CVE-2013-1902, CVE-2007-3279, CVE-2013-1903, CVE-2024-1597
- **Recommendation**: Upgrade to latest PostgreSQL version

#### Nginx (5 critical)
- CVE-2024-1597, CVE-2023-44487, CVE-2021-23017, CVE-2021-22946, CVE-2019-20372
- **Recommendation**: Upgrade to nginx 1.24.0 or later (already applied on webservers_patched)

## Security Observations

1. **SSH Access**: Restricted to sudo group only on web servers
2. **Database Access**: PostgreSQL only accepts connections from web subnet (10.0.1.0/24)
3. **Firewall**: HTTPS (443) open to internet on web servers
4. **Filesystem**: PostgreSQL data directory has restrictive permissions (0700)

## Ambiguities

1. No explicit sudoers configuration found in Ansible tasks
2. No explicit database user credentials defined
3. No SELinux policies defined
4. No audit logging configuration found

## Recommendations

1. Upgrade legacy nginx (1.20.0) to patched version (1.24.0)
2. Review and update OpenSSH version (1:9.6p1-3ubuntu1)
3. Implement explicit audit logging for compliance
4. Define explicit sudoers rules in Ansible
