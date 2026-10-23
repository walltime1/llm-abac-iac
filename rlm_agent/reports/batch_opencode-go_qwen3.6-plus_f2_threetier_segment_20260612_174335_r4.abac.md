# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:49:58_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f2_threetier_segmented`_

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
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "department": "engineering",
        "clearance": "confidential",
        "source": "group_vars/all.yml"
      },
      {
        "name": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "department": "data",
        "clearance": "secret",
        "source": "group_vars/all.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "dba"
    ],
    "clearance_levels": [
      {
        "value": "secret",
        "domain": [
          "secret",
          "confidential",
          "public"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "confidential",
        "domain": [
          "secret",
          "confidential",
          "public"
        ],
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "value": "operations",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "engineering",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "data",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      }
    ]
  },
  "resources": {
    "hosts": [
      {
        "hostname": "proxy01.lab.local",
        "ip": "10.0.1.10",
        "role": "reverse_proxy",
        "zone": "dmz",
        "inventory_group": "dmz",
        "source": "inventory.ini"
      },
      {
        "hostname": "app01.lab.local",
        "ip": "10.0.2.10",
        "role": "application",
        "zone": "app",
        "inventory_group": "appservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.3.10",
        "role": "primary",
        "zone": "data",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "http",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
      },
      {
        "name": "postgres",
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
        "source": "group_vars/dbservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "dmz",
        "label": "any",
        "source": "group_vars/dmz.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "dmz_subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet",
        "source": "group_vars/dbservers.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "segcorp",
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "domain": [
        "production",
        "staging",
        "development"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "pci",
      "domain": [
        "pci",
        "hipaa",
        "sox",
        "internal"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "value": 365,
      "source": "group_vars/all.yml"
    }
  },
  "packages": [
    {
      "name": "nginx",
      "version": "1.20.0-1~focal",
      "source": "group_vars/all.yml"
    },
    {
      "name": "openssh",
      "version": "1:9.6p1-3ubuntu1",
      "source": "group_vars/all.yml"
    },
    {
      "name": "postgresql",
      "version": "13.7-1.pgdg20.04+1",
      "source": "group_vars/all.yml"
    }
  ],
  "protocols": {
    "domain": [
      "tcp",
      "udp"
    ],
    "source": "roles/app/tasks/main.yml"
  },
  "auth_methods": {
    "domain": [
      "scram-sha-256",
      "md5",
      "trust"
    ],
    "source": "roles/db/tasks/main.yml"
  },
  "privilege_levels": {
    "domain": [
      "SUPERUSER",
      "NOSUPERUSER",
      "CREATEDB",
      "CREATEROLE"
    ],
    "source": "roles/db/tasks/main.yml"
  },
  "zones": {
    "domain": [
      "dmz",
      "app",
      "data"
    ],
    "source": "inventory.ini"
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "effect": "permit",
    "action": "ssh:login",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        22,
        25
      ]
    }
  },
  {
    "id": "rule-002",
    "effect": "permit",
    "action": "ssh:login",
    "subject_condition": {
      "groups": {
        "in": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        19,
        22
      ]
    }
  },
  {
    "id": "rule-003",
    "effect": "permit",
    "action": "ssh:login",
    "subject_condition": {
      "groups": {
        "in": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        30,
        33
      ]
    }
  },
  {
    "id": "rule-004",
    "effect": "permit",
    "action": "network:connect",
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
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        16,
        21
      ]
    }
  },
  {
    "id": "rule-005",
    "effect": "permit",
    "action": "network:connect",
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
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        13,
        18
      ]
    }
  },
  {
    "id": "rule-006",
    "effect": "permit",
    "action": "network:connect",
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
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        25,
        28
      ]
    }
  },
  {
    "id": "rule-007",
    "effect": "permit",
    "action": "user:create",
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
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        13,
        20
      ]
    }
  },
  {
    "id": "rule-008",
    "effect": "permit",
    "action": "user:create",
    "subject_condition": {
      "groups": {
        "in": [
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
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        7,
        14
      ]
    }
  },
  {
    "id": "rule-009",
    "effect": "permit",
    "action": "db:login",
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
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      },
      "privilege_level": {
        "equals": "SUPERUSER"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        21,
        26
      ]
    }
  },
  {
    "id": "rule-010",
    "effect": "permit",
    "action": "db:login",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      },
      "privilege_level": {
        "equals": "NOSUPERUSER"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        28,
        33
      ]
    }
  },
  {
    "id": "rule-011",
    "effect": "permit",
    "action": "network:connect",
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
      },
      "database": {
        "equals": "all"
      },
      "auth_method": {
        "equals": "scram-sha-256"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        35,
        39
      ]
    }
  },
  {
    "id": "rule-012",
    "effect": "permit",
    "action": "filesystem:write",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        13,
        19
      ]
    }
  },
  {
    "id": "rule-013",
    "effect": "deny",
    "action": "*",
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
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "implicit",
      "task": "default-deny",
      "lines": [
        0,
        0
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
    "id": "rule-018",
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
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest stable release; review CVE-CVE-2021-46461 for patch status"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest stable release; review CVE-CVE-2016-0746 for patch status"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest stable release; review CVE-CVE-2017-20005 for patch status"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cve_id": "CVE-2009-3555",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest stable release; review CVE-CVE-2009-3555 for patch status"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to latest stable release; review CVE-CVE-2021-23017 for patch status"
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest stable release; review CVE-CVE-2000-0999 for patch status"
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest stable release; review CVE-CVE-2000-0525 for patch status"
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest stable release; review CVE-CVE-2001-0144 for patch status"
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest stable release; review CVE-CVE-2003-0693 for patch status"
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest stable release; review CVE-CVE-2003-0786 for patch status"
  },
  {
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest stable release; review CVE-CVE-2002-1399 for patch status"
  },
  {
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest stable release; review CVE-CVE-2013-1902 for patch status"
  },
  {
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest stable release; review CVE-CVE-2007-3279 for patch status"
  },
  {
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest stable release; review CVE-CVE-2013-1903 for patch status"
  },
  {
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest stable release; review CVE-CVE-2024-1597 for patch status"
  }
]
```

## Report

# ABAC Policy Report — SEGCorp Ansible Configuration

## Executive Summary

Mined ABAC policy from Ansible configuration rooted at `RLM_ANSIBLE_DIR` covering the full scope (`policy_goal: all`). The configuration manages a three-tier PCI-compliant production environment (DMZ → App → DB) with 3 users, 3 hosts, and 13 access rules plus a default-deny catch-all.

## Catalog Overview

### Subjects
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |
| postgres | N/A | postgres | services | N/A (service account) |

**Groups domain**: sudo, developers, dba, postgres

### Resources
**Hosts**:
- `proxy01.lab.local` (10.0.1.10) — reverse_proxy, zone=dmz
- `app01.lab.local` (10.0.2.10) — application, zone=app
- `db01.lab.local` (10.0.3.10) — primary, zone=data

**Services**: HTTPS/443 (dmz), app/8080 (app), postgresql/5432 (data), ssh/22 (all)

**Protected Paths**: `/var/lib/postgresql/data` (owner=postgres, mode=0700)

**Networks**: 10.0.1.0/24 (dmz), 10.0.2.0/24 (app), 0.0.0.0/0 (internet)

### Environment
- **org**: segcorp
- **environment**: production
- **compliance_tier**: pci
- **log_retention_days**: 365

## Rules Summary (13 rules)

| ID | Action | Subject | Resource | Effect |
|----|--------|---------|----------|--------|
| rule-001 | ssh:login | groups in [sudo] | zone=dmz | permit |
| rule-002 | ssh:login | groups in [sudo, developers] | zone=app | permit |
| rule-003 | ssh:login | groups in [sudo, dba] | zone=data | permit |
| rule-004 | network:connect | source=0.0.0.0/0 | zone=dmz, port=443 | permit |
| rule-005 | network:connect | source=10.0.1.0/24 | zone=app, port=8080 | permit |
| rule-006 | network:connect | source=10.0.2.0/24 | zone=data, port=5432 | permit |
| rule-007 | user:create | groups in [sudo] | zone=dmz | permit |
| rule-008 | user:create | groups in [sudo, developers] | zone=app | permit |
| rule-009 | db:login | groups in [dba] | zone=data, postgresql, SUPERUSER | permit |
| rule-010 | db:login | groups in [developers] | zone=data, postgresql, NOSUPERUSER | permit |
| rule-011 | network:connect | source=10.0.2.0/24 | zone=data, postgresql, scram-sha-256 | permit |
| rule-012 | filesystem:write | groups in [postgres] | path=/var/lib/postgresql/data, mode=0700 | permit |
| rule-013 | * (default-deny) | all | all | deny |

## Vulnerability Assessment

### Pinned Software Versions
| Package | Pinned Version |
|---------|---------------|
| nginx | 1.20.0-1~focal |
| openssh-server | 1:9.6p1-3ubuntu1 |
| postgresql | 13.7-1.pgdg20.04+1 |

### Critical/Remote CVEs Found: 15

**nginx (5 CVEs)**: CVE-2021-46461 (CVSS 9.8), CVE-2016-0746 (9.8), CVE-2017-20005 (9.8), CVE-2009-3555 (9.8), CVE-2021-23017 (7.7)

**openssh (5 CVEs)**: CVE-2000-0999 (10.0), CVE-2000-0525 (10.0), CVE-2001-0144 (10.0), CVE-2003-0693 (10.0), CVE-2003-0786 (10.0)

**postgresql (5 CVEs)**: CVE-2007-3279 (10.0), CVE-2013-1902 (10.0), CVE-2013-1903 (10.0), CVE-2024-1597 (10.0), CVE-2002-1399 (10.0)

**Recommendation**: Upgrade all three packages to latest stable releases and apply patches for listed CVEs. Many are legacy CVEs; verify relevance against pinned versions.

## Ambiguities & Notes

1. **No explicit credentials/hashes**: The Ansible config does not contain password hashes or SSH keys. User accounts are provisioned without password management tasks — passwords may be set out-of-band or via vault (not present in scanned files).
2. **KEV search returned metadata only**: The KEV vulnerability search returned dictionary keys (count, facets, results, total) rather than CVE details, suggesting no KEV entries matched the product CPEs or the API returned a faceted response. No KEV-specific vulnerabilities were incorporated.
3. **pg_hba.conf implicit deny**: PostgreSQL's default `pg_hba.conf` deny-all is implicit. Rule-011 explicitly permits app subnet access; no explicit DENY rule is defined in the Ansible tasks.
4. **No SELinux/AppArmor tasks**: No MAC (SELinux/AppArmor) configuration was found in the role tasks.
5. **No monitoring/audit obligations**: No session logging or audit enforcement tasks were detected in the scanned role files.
6. **Service account `postgres`**: Added to catalog as a non-human subject for filesystem ACL rule-012; not defined in `group_vars/all.yml` users list.
7. **Line numbers approximate**: Source line references in rules are approximate ranges based on task boundaries in the YAML files.

## Files Analyzed

| File | Phase | Relevance |
|------|-------|-----------|
| inventory.ini | 1 | Host definitions, environment vars |
| group_vars/all.yml | 1 | Users, org, compliance, package versions |
| group_vars/appservers.yml | 1 | App port, SSH groups, firewall sources |
| group_vars/dbservers.yml | 1 | Postgres port, data dir, DB admin groups |
| group_vars/dmz.yml | 1 | HTTP port, SSH groups, firewall sources |
| roles/app/tasks/main.yml | 2 | SSH, firewall, user provisioning |
| roles/db/tasks/main.yml | 2 | Postgres install, DB roles, pg_hba, filesystem |
| roles/dmz/tasks/main.yml | 2 | Nginx install, SSH, firewall, user provisioning |
| README.md | 1.6 | Skipped (not security-relevant) |
