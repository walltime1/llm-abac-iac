# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:23:48_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "description": "Human and service principals subject to ABAC policy",
    "attributes": {
      "name": {
        "type": "string",
        "description": "User account name",
        "domain": null,
        "source": "group_vars/all.yml"
      },
      "uid": {
        "type": "integer",
        "description": "Numeric user identifier",
        "domain": null,
        "source": "group_vars/all.yml"
      },
      "groups": {
        "type": "set",
        "description": "Unix groups the user belongs to",
        "domain": [
          "sudo",
          "developers",
          "dba"
        ],
        "source": "group_vars/all.yml"
      },
      "clearance": {
        "type": "string",
        "description": "Security clearance level",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      },
      "department": {
        "type": "string",
        "description": "Organizational department",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      }
    }
  },
  "groups": {
    "description": "Unix groups used for access control",
    "attributes": {
      "name": {
        "type": "string",
        "description": "Group name",
        "domain": [
          "sudo",
          "developers",
          "dba"
        ],
        "source": "group_vars/all.yml"
      }
    }
  },
  "clearance_levels": {
    "description": "Security clearance hierarchy",
    "attributes": {
      "level": {
        "type": "string",
        "description": "Clearance level",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      }
    }
  },
  "departments": {
    "description": "Organizational departments",
    "attributes": {
      "name": {
        "type": "string",
        "description": "Department name",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      }
    }
  },
  "hosts": {
    "description": "Managed inventory hosts",
    "attributes": {
      "hostname": {
        "type": "string",
        "description": "Inventory hostname",
        "domain": [
          "proxy01.lab.local",
          "app01.lab.local",
          "db01.lab.local"
        ],
        "source": "inventory.ini"
      },
      "ip": {
        "type": "string",
        "description": "IPv4 address",
        "domain": null,
        "source": "inventory.ini"
      },
      "role": {
        "type": "string",
        "description": "Host functional role",
        "domain": [
          "reverse_proxy",
          "application",
          "primary"
        ],
        "source": "inventory.ini"
      },
      "zone": {
        "type": "string",
        "description": "Network zone",
        "domain": [
          "dmz",
          "app",
          "data"
        ],
        "source": "inventory.ini"
      },
      "inventory_group": {
        "type": "string",
        "description": "Ansible inventory group membership",
        "domain": [
          "dmz",
          "appservers",
          "dbservers",
          "prod"
        ],
        "source": "inventory.ini"
      }
    }
  },
  "services": {
    "description": "Network-exposed services",
    "attributes": {
      "name": {
        "type": "string",
        "description": "Service name",
        "domain": [
          "nginx",
          "postgresql",
          "ssh",
          "app"
        ],
        "source": "group_vars/dmz.yml, group_vars/appservers.yml, group_vars/dbservers.yml"
      },
      "port": {
        "type": "integer",
        "description": "TCP port number",
        "domain": [
          443,
          5432,
          22,
          8080
        ],
        "source": "group_vars/dmz.yml, group_vars/appservers.yml, group_vars/dbservers.yml"
      },
      "protocol": {
        "type": "string",
        "description": "Network protocol",
        "domain": [
          "tcp"
        ],
        "source": "roles/*/tasks/main.yml"
      },
      "host_group": {
        "type": "string",
        "description": "Ansible host group serving this service",
        "domain": [
          "dmz",
          "appservers",
          "dbservers"
        ],
        "source": "inventory.ini"
      }
    }
  },
  "paths": {
    "description": "Sensitive filesystem paths",
    "attributes": {
      "path": {
        "type": "string",
        "description": "Absolute path",
        "domain": [
          "/var/lib/postgresql/data"
        ],
        "source": "group_vars/dbservers.yml"
      },
      "owner": {
        "type": "string",
        "description": "Unix owner",
        "domain": [
          "postgres"
        ],
        "source": "roles/db/tasks/main.yml"
      },
      "group": {
        "type": "string",
        "description": "Unix group",
        "domain": [
          "postgres"
        ],
        "source": "roles/db/tasks/main.yml"
      },
      "mode": {
        "type": "string",
        "description": "Octal permission mode",
        "domain": [
          "0700"
        ],
        "source": "roles/db/tasks/main.yml"
      }
    }
  },
  "networks": {
    "description": "Network CIDR scopes referenced in firewall rules",
    "attributes": {
      "cidr": {
        "type": "string",
        "description": "IPv4 CIDR notation",
        "domain": [
          "10.0.1.0/24",
          "10.0.2.0/24",
          "0.0.0.0/0"
        ],
        "source": "group_vars/appservers.yml, group_vars/dmz.yml, group_vars/dbservers.yml"
      },
      "zone": {
        "type": "string",
        "description": "Zone the CIDR belongs to",
        "domain": [
          "dmz",
          "app",
          "internet"
        ],
        "source": "group_vars/appservers.yml, group_vars/dmz.yml"
      },
      "label": {
        "type": "string",
        "description": "Human-readable label",
        "domain": [
          "DMZ subnet",
          "appservers subnet",
          "internet"
        ],
        "source": "group_vars/appservers.yml, group_vars/dmz.yml"
      }
    }
  },
  "environment": {
    "description": "Global environment and compliance context",
    "attributes": {
      "org": {
        "type": "string",
        "description": "Organization name",
        "domain": [
          "segcorp"
        ],
        "source": "group_vars/all.yml"
      },
      "environment": {
        "type": "string",
        "description": "Deployment environment",
        "domain": [
          "production"
        ],
        "source": "inventory.ini"
      },
      "compliance_tier": {
        "type": "string",
        "description": "Compliance framework tier",
        "domain": [
          "pci"
        ],
        "source": "group_vars/all.yml, inventory.ini"
      },
      "default_log_retention_days": {
        "type": "integer",
        "description": "Default session log retention in days",
        "domain": null,
        "source": "group_vars/all.yml"
      }
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "Allow sudo group SSH login to DMZ reverse-proxy hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "environment": {
        "equals": "production"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "inventory_group": {
        "equals": "dmz"
      },
      "role": {
        "equals": "reverse_proxy"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "Enable sshd LoginGraceTime and SyslogFacility AUTH",
        "source": {
          "file": "roles/dmz/tasks/main.yml",
          "task": "Restrict SSH to sudo group",
          "lines": [
            20,
            24
          ]
        }
      }
    ],
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        20,
        24
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Allow sudo and developers groups SSH login to app servers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      },
      "environment": {
        "equals": "production"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "inventory_group": {
        "equals": "appservers"
      },
      "role": {
        "equals": "application"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "SyslogFacility AUTH for SSH session logging",
        "source": {
          "file": "roles/app/tasks/main.yml",
          "task": "Restrict SSH to approved groups",
          "lines": [
            16,
            20
          ]
        }
      }
    ],
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        16,
        20
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Allow sudo and dba groups SSH login to database servers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      },
      "environment": {
        "equals": "production"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "inventory_group": {
        "equals": "dbservers"
      },
      "role": {
        "equals": "primary"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "SyslogFacility AUTH for SSH session logging",
        "source": {
          "file": "roles/db/tasks/main.yml",
          "task": "Restrict SSH to sudo group",
          "lines": [
            27,
            31
          ]
        }
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        27,
        31
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow DBA users SUPERUSER PostgreSQL login from appservers subnet",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      },
      "environment": {
        "equals": "production"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "database": {
        "equals": "all"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "description": "SUPERUSER role attribute flags: LOGIN,SUPERUSER",
        "source": {
          "file": "roles/db/tasks/main.yml",
          "task": "Create DB superuser role for DBAs",
          "lines": [
            14,
            18
          ]
        }
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        14,
        18
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow developer users NOSUPERUSER PostgreSQL login from appservers subnet",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      },
      "environment": {
        "equals": "production"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "database": {
        "equals": "all"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "description": "NOSUPERUSER role attribute flags: LOGIN,NOSUPERUSER — SELECT-only access",
        "source": {
          "file": "roles/db/tasks/main.yml",
          "task": "Create DB read-only role for developers",
          "lines": [
            20,
            24
          ]
        }
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        20,
        24
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow HTTPS traffic from internet to DMZ reverse-proxy",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      },
      "environment": {
        "equals": "production"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "dmz"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        14,
        19
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow app-port traffic from DMZ subnet to application servers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      },
      "environment": {
        "equals": "production"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      },
      "host_group": {
        "equals": "appservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        10,
        16
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Allow PostgreSQL traffic from appservers subnet to database servers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      },
      "environment": {
        "equals": "production"
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        25,
        30
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Allow postgres user full access to PostgreSQL data directory",
    "subject_condition": {
      "name": {
        "equals": "postgres"
      },
      "environment": {
        "equals": "production"
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
        9,
        15
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "Allow creation of shell user accounts for developers and sudo group members on app servers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      },
      "environment": {
        "equals": "production"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      },
      "role": {
        "equals": "application"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "obligations": [
      {
        "type": "account_config",
        "description": "shell=/bin/bash; groups set per user; uid per user definition",
        "source": {
          "file": "roles/app/tasks/main.yml",
          "task": "Provision shell users",
          "lines": [
            4,
            9
          ]
        }
      }
    ],
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
    "rule_id": "rule-011",
    "description": "Allow creation of admin user accounts for sudo group members on DMZ hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "environment": {
        "equals": "production"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dmz"
      },
      "role": {
        "equals": "reverse_proxy"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "obligations": [
      {
        "type": "account_config",
        "description": "shell=/bin/bash; uid per user definition; groups set per user",
        "source": {
          "file": "roles/dmz/tasks/main.yml",
          "task": "Provision admin users",
          "lines": [
            12,
            18
          ]
        }
      }
    ],
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        12,
        18
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "description": "Default-deny: block all access not explicitly permitted above",
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
      "task": "default-deny",
      "lines": [
        1,
        13
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
    "id": "rule-002",
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
      },
      "host_group": {
        "equals": "dmz"
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
    "id": "rule-003",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      },
      "host_group": {
        "equals": "appservers"
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
    "id": "rule-004",
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
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": "unlikely_or_mitigated",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "TLS renegotiation vulnerability",
    "recommendation": "Upgrade nginx to latest patched version; verify if CVE-2009-3555 affects 1.20.0 by consulting vendor advisory"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": "unlikely_or_mitigated",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "DNS resolver vulnerability",
    "recommendation": "Upgrade nginx to latest patched version; verify if CVE-2016-0746 affects 1.20.0 by consulting vendor advisory"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": "likely_affected",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "Memory corruption in ngx_http_ssi_filter",
    "recommendation": "Upgrade nginx to latest patched version; verify if CVE-2021-46461 affects 1.20.0 by consulting vendor advisory"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": "likely_affected",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "HTTP request smuggling vulnerability",
    "recommendation": "Upgrade nginx to latest patched version; verify if CVE-2017-20005 affects 1.20.0 by consulting vendor advisory"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": "likely_affected",
    "cvss_score": 7.7,
    "severity": "high",
    "title": "Off-by-one error in resolver",
    "recommendation": "Upgrade nginx to latest patched version; verify if CVE-2021-23017 affects 1.20.0 by consulting vendor advisory"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": "unlikely_or_mitigated",
    "cvss_score": 10.0,
    "severity": "critical",
    "title": "PostgreSQL buffer overflow",
    "recommendation": "Upgrade postgresql to latest patched version; verify if CVE-2002-1399 affects 16.2 by consulting vendor advisory"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": "unlikely_or_mitigated",
    "cvss_score": 10.0,
    "severity": "critical",
    "title": "PostgreSQL privilege escalation",
    "recommendation": "Upgrade postgresql to latest patched version; verify if CVE-2007-3279 affects 16.2 by consulting vendor advisory"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": "likely_affected",
    "cvss_score": 10.0,
    "severity": "critical",
    "title": "SQL injection via pg_cancel_backend",
    "recommendation": "Upgrade postgresql to latest patched version; verify if CVE-2024-1597 affects 16.2 by consulting vendor advisory"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": "unlikely_or_mitigated",
    "cvss_score": 10.0,
    "severity": "critical",
    "title": "PostgreSQL CREATE LANGUAGE vulnerability",
    "recommendation": "Upgrade postgresql to latest patched version; verify if CVE-2013-1903 affects 16.2 by consulting vendor advisory"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": "unlikely_or_mitigated",
    "cvss_score": 10.0,
    "severity": "critical",
    "title": "PostgreSQL SECURITY DEFINER function vulnerability",
    "recommendation": "Upgrade postgresql to latest patched version; verify if CVE-2013-1902 affects 16.2 by consulting vendor advisory"
  }
]
```

## Report

# ABAC Policy Report — segcorp Production Infrastructure

## Organisation & Environment

| Attribute | Value | Source |
|---|---|---|
| Organisation | segcorp | `group_vars/all.yml` |
| Environment | production | `inventory.ini` |
| Compliance Tier | PCI-DSS | `inventory.ini`, `group_vars/all.yml` |
| Log Retention | 365 days | `group_vars/all.yml` |

---

## Subjects

| User | UID | Groups | Clearance | Department | Source |
|---|---|---|---|---|---|
| admin | 1001 | sudo | secret | operations | `group_vars/all.yml` |
| developer | 1002 | developers | confidential | engineering | `group_vars/all.yml` |
| dba | 1003 | dba | secret | data | `group_vars/all.yml` |

### Enumerated Domains
- **Groups**: `sudo`, `developers`, `dba`
- **Clearance levels**: `secret`, `confidential`
- **Departments**: `operations`, `engineering`, `data`

---

## Resources

### Hosts

| Hostname | IP | Role | Zone | Inventory Group | Source |
|---|---|---|---|---|---|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz | `inventory.ini` |
| app01.lab.local | 10.0.2.10 | application | app | appservers | `inventory.ini` |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers | `inventory.ini` |

### Services

| Service | Port | Protocol | Host Group | Source |
|---|---|---|---|---|
| nginx | 443 | tcp | dmz | `group_vars/dmz.yml` |
| app | 8080 | tcp | appservers | `group_vars/appservers.yml` |
| postgresql | 5432 | tcp | dbservers | `group_vars/dbservers.yml` |
| ssh | 22 | tcp | all | `roles/*/tasks/main.yml` |

### Networks

| CIDR | Zone | Label | Source |
|---|---|---|---|
| 10.0.1.0/24 | dmz | DMZ subnet | `group_vars/dmz.yml` |
| 10.0.2.0/24 | app | appservers subnet | `group_vars/appservers.yml` |
| 0.0.0.0/0 | internet | internet | `group_vars/dmz.yml` |

### Paths

| Path | Owner | Group | Mode | Source |
|---|---|---|---|---|
| /var/lib/postgresql/data | postgres | postgres | 0700 | `group_vars/dbservers.yml` |

---

## Vulnerability Assessment

Three pinned software packages were assessed:

| Package | Pinned Version | Critical CVEs | KEV Matches | Notes |
|---|---|---|---|---|
| nginx | 1.20.0 | 4 | 0 | CVE-2017-20005, CVE-2021-46461, CVE-2021-23017 may affect 1.20.x |
| openssh-server | 9.1p1 | 0 | 0 | No known critical/KEV CVEs for this version |
| postgresql | 16.2 | 1 | 0 | CVE-2024-1597 (SQL injection) should be verified |

### Critical Findings

**nginx 1.20.0 — 5 CVEs (4 critical, 1 high)**

| CVE ID | CVSS | Severity | Affects Pinned? | Recommendation |
|---|---|---|---|---|
| CVE-2009-3555 | 9.8 | critical | unlikely_or_mitigated | TLS renegotiation flaw predates 1.20.0; verify backport |
| CVE-2016-0746 | 9.8 | critical | unlikely_or_mitigated | DNS resolver issue predates 1.20.0; verify backport |
| CVE-2021-46461 | 9.8 | critical | **likely_affected** | ngx_http_ssi_filter memory corruption — upgrade to 1.25.x |
| CVE-2017-20005 | 9.8 | critical | **likely_affected** | HTTP request smuggling — upgrade to 1.21.x+ |
| CVE-2021-23017 | 7.7 | high | **likely_affected** | Off-by-one in resolver — upgrade to 1.23.x+ |

**postgresql 16.2 — 5 CVEs (all critical)**

| CVE ID | CVSS | Severity | Affects Pinned? | Recommendation |
|---|---|---|---|---|
| CVE-2002-1399 | 10.0 | critical | unlikely_or_mitigated | Pre-dates PG 16; unlikely |
| CVE-2007-3279 | 10.0 | critical | unlikely_or_mitigated | Pre-dates PG 16; unlikely |
| CVE-2024-1597 | 10.0 | critical | **likely_affected** | SQL injection via pg_cancel_backend — **upgrade to PG 16.3+** |
| CVE-2013-1903 | 10.0 | critical | unlikely_or_mitigated | Pre-dates PG 16; unlikely |
| CVE-2013-1902 | 10.0 | critical | unlikely_or_mitigated | Pre-dates PG 16; unlikely |

**openssh-server 9.1p1 — No matching CVEs found**

---

## Extracted ABAC Rules

### Summary

| Rule ID | Subject | Resource | Action | Effect |
|---|---|---|---|---|
| rule-001 | sudo → production | proxy01.lab.local (dmz) | ssh:login | permit |
| rule-002 | sudo,developers → production | app01.lab.local (appservers) | ssh:login | permit |
| rule-003 | sudo,dba → production | db01.lab.local (dbservers) | ssh:login | permit |
| rule-004 | dba → production | postgresql:5432 (dbservers) | db:login (SUPERUSER) | permit |
| rule-005 | developers → production | postgresql:5432 (dbservers) | db:login (NOSUPERUSER) | permit |
| rule-006 | internet → production | nginx:443 (dmz) | network:connect | permit |
| rule-007 | dmz subnet → production | app:8080 (appservers) | network:connect | permit |
| rule-008 | appservers subnet → production | postgresql:5432 (dbservers) | network:connect | permit |
| rule-009 | postgres → production | /var/lib/postgresql/data (0700) | filesystem:execute | permit |
| rule-010 | developers,sudo → production | app01.lab.local (appservers) | user:create | permit |
| rule-011 | sudo → production | proxy01.lab.local (dmz) | user:create | permit |
| rule-012 | **all** | **all** | * | **deny** |

### Obligations

| Rule | Obligation Type | Detail |
|---|---|---|
| rule-001 | session_logging | SyslogFacility AUTH on sshd |
| rule-002 | session_logging | SyslogFacility AUTH on sshd |
| rule-003 | session_logging | SyslogFacility AUTH on sshd |
| rule-004 | privilege_level | SUPERUSER (LOGIN,SUPERUSER flags) |
| rule-005 | privilege_level | NOSUPERUSER (LOGIN,NOSUPERUSER flags) |
| rule-010 | account_config | shell=/bin/bash; uid and groups per user |
| rule-011 | account_config | shell=/bin/bash; uid and groups per user |

---

## Ambiguities & Gaps

1. **Credentials in plaintext**: No Ansible vault or external secrets manager is referenced in the configuration. All `lineinfile` tasks that write to `sshd_config` and `pg_hba.conf` use inline values. **Credentials should be externalised to a vault or secrets manager.**

2. **Sudo password not configured**: The SSH `AllowGroups` rules do not configure `RequirePassword` or `PasswordAuthentication`. Whether sudo requires a password depends on the OS default (`/etc/sudoers` not present in this config). This creates ambiguity around whether `ssh:login` implies `sudo:execute`.

3. **SSH session logging is partial**: The obligation references `SyslogFacility AUTH` but no actual logging task is present in the role files. The obligation is correctly attached to the ssh:login rules but requires an external enforcement mechanism (e.g., auditd or rsyslog configuration).

4. **pg_hba.conf implicit deny**: The `lineinfile` task in `roles/db/tasks/main.yml` adds `host all all <subnet> scram-sha-256` entries but does not explicitly configure a `DENY` rule. PostgreSQL's pg_hba default is to deny; this is captured by `rule-012` (default-deny).

5. **No nginx TLS configuration visible**: `roles/dmz/tasks/main.yml` installs nginx and opens HTTPS port 443 via firewalld, but no TLS certificate paths or SSL parameters are defined. The TLS hardening posture is unknown.

6. **openssh-server 9.1p1**: While no critical CVEs were found, OpenSSH 9.x introduced `RevokedKeys` and `AllowStreamLocalForwarding` changes. The `sshd_config` template in `roles/*/tasks/main.yml` only sets `AllowGroups` and does not configure these newer options.

7. **No file integrity / monitoring rules**: No AIDE, auditd, or tripwire configurations are present in any role. Compliance tier PCI-DSS requires file-integrity monitoring.

---

## Policy Statistics

- **Total rules**: 12 (11 permit, 1 deny)
- **Action breakdown**: ssh:login ×3, db:login ×2, network:connect ×3, filesystem:execute ×1, user:create ×2, default-deny ×1
- **Distinct subjects covered**: admin, developer, dba (3 of 3 users)
- **Distinct resources covered**: 3 hosts, 4 services, 3 networks, 1 path
- **Obligations attached**: 7 (session_logging ×3, privilege_level ×2, account_config ×2)
