# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:38:44_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 15 | Rules: 14_  
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
        "department": "operations",
        "clearance": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "department": "engineering",
        "clearance": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "groups": {
      "values": [
        "sudo",
        "developers"
      ],
      "domain": [
        "sudo",
        "developers"
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
        "engineering"
      ],
      "source": "group_vars/all.yml"
    }
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
        "name": "http",
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
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers-subnet",
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
      "source": "group_vars/all.yml"
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
    "rule_id": "rule-001",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        45,
        48
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "command": {
        "equals": "ALL"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        37,
        42
      ]
    },
    "obligations": [
      {
        "type": "audit",
        "detail": "sudo actions logged per compliance_tier soc2"
      }
    ]
  },
  {
    "rule_id": "rule-003",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": [
        49,
        55
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "target_system": {
        "equals": "webservers"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        23,
        29
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
      "role_attr": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        17,
        21
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
      "role_attr": {
        "equals": "NOSUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        23,
        27
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        29,
        33
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "subject_condition": {
      "groups": {
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
      "environment": {
        "equals": "production"
      }
    },
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
    "rule_id": "rule-009",
    "subject_condition": {
      "groups": {
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
      "environment": {
        "equals": "production"
      }
    },
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
      "file": "policy",
      "task": "default-deny",
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
  },
  {
    "id": "rule-002",
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
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
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
      "database": {
        "equals": "postgresql"
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
    "cve_id": "CVE-2013-2250",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned apache version against CVE-2013-2250"
  },
  {
    "cve_id": "CVE-2013-1777",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned apache version against CVE-2013-1777"
  },
  {
    "cve_id": "CVE-2012-2379",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned apache version against CVE-2012-2379"
  },
  {
    "cve_id": "CVE-2013-4316",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned apache version against CVE-2013-4316"
  },
  {
    "cve_id": "CVE-2012-0838",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned apache version against CVE-2012-0838"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned openssh version against CVE-2000-0999"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned openssh version against CVE-2000-0525"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned openssh version against CVE-2003-0693"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned openssh version against CVE-2003-0786"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned openssh version against CVE-2001-0144"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned postgresql version against CVE-2002-1399"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned postgresql version against CVE-2013-1902"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned postgresql version against CVE-2007-3279"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned postgresql version against CVE-2013-1903"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "recommendation": "Review patch status for pinned postgresql version against CVE-2024-1597"
  }
]
```

## Report

# ABAC Policy Mining Report

## Summary
Successfully mined an Attribute-Based Access Control (ABAC) policy from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The policy covers 10 rules across SSH, sudo, firewall, user provisioning, database access, and filesystem permissions.

## Scope
- **Subjects**: 2 users (`admin`, `appuser`), 2 groups (`sudo`, `developers`)
- **Resources**: 2 hosts (`web01.lab.local`, `db01.lab.local`), 2 services (HTTP/80, PostgreSQL/5432), 1 filesystem path, 2 network zones
- **Environment**: `labcorp`, `production`, `soc2` compliance tier

## Vulnerability Assessment
Evaluated pinned software versions:
- Apache httpd: `2.4.49-1`
- OpenSSH: `1:9.6p1-3ubuntu1`
- PostgreSQL: `16.2-1.pgdg22.04+1`

Found multiple CVEs across critical/remote and KEV datasets. Recommendations advise reviewing patch status against the specific pinned versions.

## Ambiguities
- Firewall rule `rule-003` allows HTTP from `0.0.0.0/0` (internet-facing) without explicit geo-IP or rate-limiting constraints in the Ansible config.
- `appuser` has `confidential` clearance but no explicit sudo or database superuser grants; access is restricted to read-only DB roles.
- No explicit session logging or MFA enforcement found in the configuration beyond implicit soc2 compliance requirements.
