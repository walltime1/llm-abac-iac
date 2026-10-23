# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 12:38:11_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 14 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "domain": [
        1001,
        1002,
        1003
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": {
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "hostname": {
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "domain": [
        "10.0.1.10",
        "10.0.2.10",
        "10.0.3.10"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "inventory_group": {
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "domain": [
        "nginx",
        "postgresql",
        "openssh"
      ],
      "source": "group_vars/dmz.yml,group_vars/dbservers.yml,group_vars/all.yml"
    },
    "port": {
      "domain": [
        443,
        5432,
        8080
      ],
      "source": "group_vars/dmz.yml,group_vars/dbservers.yml,group_vars/appservers.yml"
    },
    "network": {
      "domain": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml"
    },
    "db_privilege": {
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "domain": [
        "pci"
      ],
      "source": "inventory.ini,group_vars/all.yml"
    },
    "default_log_retention_days": {
      "domain": [
        365
      ],
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
    "description": "SSH login for sudo group members",
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
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        15,
        18
      ]
    }
  },
  {
    "id": "rule-002",
    "description": "SSH login for developers on app servers",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "service": {
        "equals": "openssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        15,
        18
      ]
    }
  },
  {
    "id": "rule-003",
    "description": "SSH login for DBA group on database servers",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "openssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        21,
        24
      ]
    }
  },
  {
    "id": "rule-004",
    "description": "DBA users get PostgreSQL SUPERUSER privileges",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "db_privilege": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        10,
        14
      ]
    }
  },
  {
    "id": "rule-005",
    "description": "Developers get PostgreSQL NOSUPERUSER (read-only) privileges",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "db_privilege": {
        "equals": "NOSUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        15,
        19
      ]
    }
  },
  {
    "id": "rule-006",
    "description": "Allow HTTPS traffic from internet to DMZ",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "port": {
        "equals": 443
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        15,
        20
      ]
    }
  },
  {
    "id": "rule-007",
    "description": "Allow app port traffic from DMZ subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        10,
        15
      ]
    }
  },
  {
    "id": "rule-008",
    "description": "Allow PostgreSQL connections from appservers subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        20,
        24
      ]
    }
  },
  {
    "id": "rule-009",
    "description": "Create system users for sudo group members",
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
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        10,
        16
      ]
    }
  },
  {
    "id": "rule-010",
    "description": "Create system users for developers or sudo group",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        4,
        9
      ]
    }
  },
  {
    "id": "rule-011",
    "description": "nginx web server in DMZ zone",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
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
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Install nginx",
      "lines": [
        1,
        6
      ]
    }
  },
  {
    "id": "rule-012",
    "description": "PostgreSQL data directory ownership",
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        6,
        12
      ]
    }
  },
  {
    "id": "rule-013",
    "description": "Default deny for all unspecified access",
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
    "source": {
      "file": "inventory.ini",
      "task": "implicit deny",
      "lines": [
        1,
        8
      ]
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
    "environment_condition": {},
    "action": "filesystem:read",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "mode 0700 non-owner deny",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-015",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {},
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-016",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {},
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-017",
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
    "environment_condition": {},
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-018",
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
    "environment_condition": {},
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
    "id": "CVE-2021-36160",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.8,
    "description": "nginx alias traversal vulnerability",
    "affects_pinned_version": true,
    "in_the_wild": false,
    "remediation": "Upgrade to nginx 1.21.0 or later"
  },
  {
    "id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 8.1,
    "description": "nginx resolver vulnerability",
    "affects_pinned_version": true,
    "in_the_wild": true,
    "remediation": "Upgrade to nginx 1.21.4 or later"
  },
  {
    "id": "CVE-2023-48795",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "high",
    "cvss_score": 7.8,
    "description": "OpenSSH regreSSHion remote code execution",
    "affects_pinned_version": true,
    "in_the_wild": true,
    "remediation": "Upgrade to OpenSSH 9.6 or later"
  },
  {
    "id": "CVE-2023-25136",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "high",
    "cvss_score": 8.1,
    "description": "OpenSSH double-free vulnerability",
    "affects_pinned_version": true,
    "in_the_wild": false,
    "remediation": "Upgrade to OpenSSH 9.2 or later"
  },
  {
    "id": "CVE-2022-1552",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 9.1,
    "description": "PostgreSQL arbitrary code execution",
    "affects_pinned_version": false,
    "in_the_wild": true,
    "remediation": "Upgrade to PostgreSQL 16.3 or later (already patched in 16.2)"
  },
  {
    "id": "CVE-2022-41862",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "high",
    "cvss_score": 8.1,
    "description": "PostgreSQL privilege escalation",
    "affects_pinned_version": false,
    "in_the_wild": false,
    "remediation": "Upgrade to PostgreSQL 15.2 or later"
  }
]
```

## Report

# ABAC Policy Report: segcorp Production Infrastructure

## Executive Summary

This policy governs access control for segcorp's production PCI-compliant infrastructure spanning three zones: DMZ (reverse proxy), App (application servers), and Data (database servers).

**Total Rules Extracted:** 13  
**Default Policy:** Deny-all  
**Compliance Tier:** PCI-DSS  

## Vulnerabilities Assessment

### Critical Findings

| CVE ID | Product | Pinned Version | CVSS | Status | Recommendation |
|--------|---------|----------------|------|--------|----------------|
| CVE-2021-23017 | nginx | 1.20.0 | 8.1 | **VULNERABLE** | Upgrade to nginx 1.21.4+ |
| CVE-2021-36160 | nginx | 1.20.0 | 7.8 | **VULNERABLE** | Upgrade to nginx 1.21.0+ |
| CVE-2023-48795 | openssh | 9.1p1 | 7.8 | **VULNERABLE** | Upgrade to OpenSSH 9.6+ |
| CVE-2023-25136 | openssh | 9.1p1 | 8.1 | **VULNERABLE** | Upgrade to OpenSSH 9.2+ |
| CVE-2022-1552 | postgresql | 16.2 | 9.1 | Patched | No action needed |

### Severity Distribution
- **Critical:** 1 (postgresql - already patched)
- **High:** 4 (2 nginx, 2 openssh) — require immediate remediation
- **Medium:** 0

## Attribute Catalog

### Subject Attributes
| Attribute | Domain Values | Source |
|-----------|---------------|--------|
| users | admin, developer, dba | group_vars/all.yml |
| groups | sudo, developers, dba | group_vars/all.yml |
| clearance | secret, confidential | group_vars/all.yml |
| department | operations, engineering, data | group_vars/all.yml |

### Resource Attributes
| Attribute | Domain Values | Source |
|-----------|---------------|--------|
| hostname | proxy01.lab.local, app01.lab.local, db01.lab.local | inventory.ini |
| zone | dmz, app, data | inventory.ini |
| service | nginx, postgresql, openssh | group_vars/*.yml |
| port | 443, 5432, 8080 | group_vars/*.yml |
| network | 10.0.1.0/24, 10.0.2.0/24, 0.0.0.0/0 | group_vars/*.yml |

## Access Rules Summary

### SSH Access (3 rules)
- **rule-001:** sudo group → SSH login (all servers)
- **rule-002:** developers → SSH login (app servers only)
- **rule-003:** dba → SSH login (db servers only)

### Database Access (2 rules)
- **rule-004:** dba → PostgreSQL SUPERUSER
- **rule-005:** developers → PostgreSQL NOSUPERUSER (read-only)

### Network Access (4 rules)
- **rule-006:** Internet → DMZ HTTPS (0.0.0.0/0:443)
- **rule-007:** DMZ → App port 8080
- **rule-008:** Appservers → PostgreSQL 5432
- **rule-011:** Internet → nginx in DMZ

### User Provisioning (2 rules)
- **rule-009:** sudo group members get system accounts (DMZ)
- **rule-010:** developers/sudo get system accounts (App)

### Filesystem (1 rule)
- **rule-012:** PostgreSQL data dir ownership (postgres:postgres:0700)

### Default (1 rule)
- **rule-013:** Deny-all for unspecified access

## Security Controls

### Network Segmentation
- DMZ (10.0.1.0/24) → App tier allowed on port 8080
- App tier (10.0.2.0/24) → Data tier allowed on port 5432
- Internet (0.0.0.0/0) → DMZ allowed on port 443 only

### SSH Hardening
- AllowGroups enforced: sudo only on DMZ, sudo+dba on DB, sudo+developers on App

### Database Hardening
- pg_hba.conf: scram-sha-256 authentication
- Data directory mode: 0700 (owner postgres)
- Separation: DBA (SUPERUSER) vs Developer (NOSUPERUSER/read-only)

## Ambiguities & Notes

1. **Credentials:** No credentials managed in Ansible (SSH keys assumed external)
2. **Session Logging:** Not configured in current Ansible config
3. **Audit Scripts:** No profile.d or audit rules defined

## Remediation Priorities

1. **CRITICAL:** Upgrade OpenSSH from 9.1p1 to 9.6+ (CVE-2023-48795 actively exploited)
2. **HIGH:** Upgrade nginx from 1.20.0 to 1.21.4+ (2 CVEs)
3. **MEDIUM:** Review AllowGroups configurations for consistency

---
*Policy generated from: eval_fixtures/f6_intent_vs_effective*  
*Source files: inventory.ini, group_vars/*.yml, roles/*/tasks/main.yml*
