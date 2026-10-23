# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:30:26_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 10 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "domain": null,
      "type": "string",
      "description": "Username",
      "source": "group_vars/all.yml"
    },
    "uid": {
      "domain": null,
      "type": "integer",
      "description": "User ID",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "type": "set",
      "description": "Unix groups",
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "domain": [
        "secret",
        "confidential"
      ],
      "type": "string",
      "description": "Security clearance level",
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "type": "string",
      "description": "Department",
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hostname": {
      "domain": null,
      "type": "string",
      "description": "FQDN",
      "source": "inventory.ini"
    },
    "ip": {
      "domain": null,
      "type": "string",
      "description": "IP address",
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "type": "string",
      "description": "Network zone",
      "source": "inventory.ini"
    },
    "role": {
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "type": "string",
      "description": "Host role",
      "source": "inventory.ini"
    },
    "inventory_group": {
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "type": "string",
      "description": "Ansible inventory group",
      "source": "inventory.ini"
    },
    "port": {
      "domain": null,
      "type": "integer",
      "description": "TCP/UDP port",
      "source": "group_vars/*.yml"
    },
    "protocol": {
      "domain": [
        "tcp",
        "udp"
      ],
      "type": "string",
      "description": "Network protocol",
      "source": "group_vars/*.yml"
    },
    "source_network": {
      "domain": [
        "0.0.0.0/0",
        "10.0.1.0/24",
        "10.0.2.0/24"
      ],
      "type": "string",
      "description": "Source CIDR network",
      "source": "group_vars/*.yml"
    },
    "path": {
      "domain": null,
      "type": "string",
      "description": "Filesystem path",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "domain": [
        "postgres",
        "root"
      ],
      "type": "string",
      "description": "File owner",
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "domain": [
        "postgres",
        "root"
      ],
      "type": "string",
      "description": "File group",
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "domain": [
        "0700",
        "0755"
      ],
      "type": "string",
      "description": "Octal file mode",
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "segcorp"
      ],
      "type": "string",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "type": "string",
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "domain": [
        "pci"
      ],
      "type": "string",
      "source": "group_vars/all.yml"
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "SSH login to DMZ hosts (proxy01) allowed for sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        15,
        18
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "SSH login to app servers (app01) allowed for sudo and developers groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        12,
        15
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "SSH login to DB servers (db01) allowed for sudo and dba groups only",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        22,
        25
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "description": "All DB server SSH sessions must be logged"
      }
    ]
  },
  {
    "rule_id": "rule-004",
    "description": "Sudo group members get passwordless sudo on all hosts",
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
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "group_vars/all.yml",
      "task": "sudo group definition",
      "lines": [
        1,
        99
      ]
    },
    "obligations": [
      {
        "type": "audit_command",
        "description": "All sudo commands logged to /var/log/secure"
      }
    ]
  },
  {
    "rule_id": "rule-005",
    "description": "DBA group members get SUPERUSER access to PostgreSQL",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "role": {
        "equals": "primary"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
    },
    "obligations": [
      {
        "type": "data_classification",
        "description": "PCI-DSS logging required for all DB modifications"
      }
    ]
  },
  {
    "rule_id": "rule-006",
    "description": "Developers get LOGIN but NOSUPERUSER access to PostgreSQL",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "role": {
        "equals": "primary"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        16,
        20
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "PostgreSQL accepts connections only from appservers subnet (10.0.2.0/24)",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        22,
        25
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "PostgreSQL denies connections from non-appserver subnets",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
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
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "pg_hba.conf implicit deny",
      "lines": [
        0,
        0
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "DMZ hosts accept HTTPS traffic from any source (internet-facing)",
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall - allow HTTPS from internet",
      "lines": [
        12,
        17
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "App servers accept traffic on app_port from DMZ subnet only",
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall - allow app port from DMZ only",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "Users with sudo group provisioned on DMZ hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "description": "Users with developers or sudo group provisioned on app servers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        5,
        10
      ]
    }
  },
  {
    "rule_id": "rule-013",
    "description": "PostgreSQL data directory owned by postgres:postgres with mode 0700",
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        13
      ]
    }
  },
  {
    "rule_id": "rule-999",
    "description": "Default deny - no access allowed unless explicitly permitted above",
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
      "file": "implicit",
      "task": "default-deny policy",
      "lines": [
        0,
        0
      ]
    }
  },
  {
    "id": "rule-001",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "installed_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.1,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "nginx 1.20.x remote code execution",
    "recommendation": "Upgrade nginx to 1.22.0+"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "installed_version": "1.20.0",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "nginx resolver off-by-one",
    "recommendation": "Upgrade nginx to 1.20.2+"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "installed_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "nginx HTTP/2 vulnerability",
    "recommendation": "Upgrade nginx to latest"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "installed_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "nginx resolver DNS manipulation",
    "recommendation": "Upgrade nginx"
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "installed_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "TLS renegotiation vulnerability",
    "recommendation": "Upgrade nginx"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "installed_version": "16.2",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL SQL injection via pg_largeobject",
    "recommendation": "URGENT: Upgrade PostgreSQL to 16.3+"
  },
  {
    "cve_id": "CVE-2023-47108",
    "product": "postgresql",
    "installed_version": "16.2",
    "severity": "high",
    "cvss_score": 8.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL bufferoverread",
    "recommendation": "Upgrade PostgreSQL"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "installed_version": "16.2",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL privilege escalation",
    "recommendation": "Upgrade PostgreSQL"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "installed_version": "16.2",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL format string bug",
    "recommendation": "Upgrade PostgreSQL"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "installed_version": "16.2",
    "severity": "high",
    "cvss_score": 8.5,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL buffer overflow",
    "recommendation": "Upgrade PostgreSQL"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report presents an Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration rooted at `$RLM_ANSIBLE_DIR`. The policy governs SSH access, sudo permissions, database authentication, and network connectivity for the SegCorp production environment.

**Organization:** segcorp  
**Environment:** production  
**Compliance Tier:** PCI-DSS  

## Phase 1: Attribute Catalog

### Subjects

| Attribute | Domain | Type | Source |
|-----------|--------|------|--------|
| user | (admin, developer, dba) | string | group_vars/all.yml |
| uid | (1001, 1002, 1003) | integer | group_vars/all.yml |
| groups | (sudo, developers, dba) | set | group_vars/all.yml |
| clearance | (secret, confidential) | string | group_vars/all.yml |
| department | (operations, engineering, data) | string | group_vars/all.yml |

### Resources

| Attribute | Domain | Type | Source |
|-----------|--------|------|--------|
| hostname | (proxy01, app01, db01).lab.local | string | inventory.ini |
| ip | (10.0.1.10, 10.0.2.10, 10.0.3.10) | string | inventory.ini |
| zone | (dmz, app, data) | string | inventory.ini |
| role | (reverse_proxy, application, primary) | string | inventory.ini |
| port | (443, 5432, 8080) | integer | group_vars/*.yml |
| source_network | (0.0.0.0/0, 10.0.1.0/24, 10.0.2.0/24) | string | group_vars/*.yml |
| path | /var/lib/postgresql/data | string | roles/db/tasks/main.yml |

### Environment

| Attribute | Domain | Source |
|-----------|--------|--------|
| org | segcorp | group_vars/all.yml |
| environment | production | inventory.ini |
| compliance_tier | pci | group_vars/all.yml |

## Phase 1.5: Vulnerability Assessment

### Pinned Software Versions

| Package | Installed Version | Source |
|---------|-------------------|--------|
| nginx | 1.20.0-1~focal | group_vars/all.yml |
| openssh-server | 1:9.1p1-1ubuntu1 | group_vars/all.yml |
| postgresql-16 | 16.2-1.pgdg22.04+1 | group_vars/all.yml |

### Critical Vulnerabilities Found

| CVE ID | Product | Severity | CVSS | Recommendation |
|--------|---------|----------|------|----------------|
| CVE-2021-46461 | nginx | CRITICAL | 9.1 | Upgrade nginx to 1.22.0+ |
| CVE-2016-0746 | nginx | CRITICAL | 10.0 | Upgrade nginx |
| CVE-2024-1597 | postgresql | CRITICAL | 10.0 | URGENT: Upgrade PostgreSQL to 16.3+ |
| CVE-2002-1399 | postgresql | CRITICAL | 10.0 | Upgrade PostgreSQL |

**Total vulnerabilities identified:** 10 (5 nginx, 5 postgresql)

## Phase 2: ABAC Rules Summary

| Rule ID | Subject | Action | Resource | Effect |
|---------|---------|--------|----------|--------|
| rule-001 | sudo group | ssh:login | dmz zone | permit |
| rule-002 | sudo, developers | ssh:login | app zone | permit |
| rule-003 | sudo, dba | ssh:login | data zone | permit |
| rule-004 | sudo group | sudo:execute | all hosts | permit |
| rule-005 | dba group | db:login | PostgreSQL (SUPERUSER) | permit |
| rule-006 | developers | db:login | PostgreSQL (NOSUPERUSER) | permit |
| rule-007 | 10.0.2.0/24 | network:connect | PostgreSQL:5432 | permit |
| rule-008 | (all others) | network:connect | PostgreSQL:5432 | deny |
| rule-009 | 0.0.0.0/0 | network:connect | dmz:443 | permit |
| rule-010 | 10.0.1.0/24 | network:connect | app:8080 | permit |
| rule-011 | sudo group | user:create | dmz hosts | permit |
| rule-012 | sudo, developers | user:create | app hosts | permit |
| rule-013 | (system) | filesystem:read | /var/lib/postgresql/data | permit |
| rule-999 | (all) | * | (all) | deny |

**Total rules:** 14 (13 permit, 1 deny)

## Phase 3: Obligations

The following obligations are attached to access rules:

1. **Session logging** (rule-003): All DB server SSH sessions must be logged
2. **Audit command logging** (rule-004): All sudo commands logged to /var/log/secure
3. **PCI-DSS compliance** (rule-005): All DB modifications require audit logging

## Phase 4: Validation

- All subject attributes defined in catalog
- All resource attributes defined in catalog
- All environment attributes defined in catalog
- All rules use valid operators (equals, any_of, applies_to)
- Default deny rule present (rule-999)
- Each rule includes source provenance (file, task, lines)

## Ambiguities

1. **SSH credentials:** No explicit SSH key management found in Ansible config. Manual key distribution assumed.
2. **Sudo password:** Configuration implies passwordless sudo for sudo group members, but this is implicit in group membership, not explicitly configured.
3. **PostgreSQL passwords:** DB user passwords not specified in config; authentication relies on pg_hba.conf network restrictions.

## Recommendations

1. **URGENT:** Upgrade PostgreSQL from 16.2 to 16.3+ to address CVE-2024-1597 (CVSS 10.0)
2. Upgrade nginx to 1.22.0+ to address CVE-2021-46461 (CVSS 9.1)
3. Implement explicit sudo password policy documentation
4. Add SSH key management to Ansible configuration
5. Document PostgreSQL authentication mechanism in security runbook
