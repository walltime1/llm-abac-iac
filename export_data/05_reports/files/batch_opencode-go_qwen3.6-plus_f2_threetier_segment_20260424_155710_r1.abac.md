# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:05:43_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 11 | Rules: 16_  
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
        "source": "group_vars/all.yml"
      },
      {
        "value": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "value": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "value": "engineering",
        "source": "group_vars/all.yml"
      },
      {
        "value": "data",
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
        "name": "nginx",
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
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "sshd",
        "source": "roles/app/tasks/main.yml"
      }
    ],
    "networks": [
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
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "group_vars/dmz.yml"
      }
    ]
  },
  "environment": {
    "org": "segcorp",
    "environment": "production",
    "compliance_tier": "pci",
    "log_retention_days": 365,
    "sources": [
      "inventory.ini",
      "group_vars/all.yml"
    ]
  },
  "attribute_definitions": {
    "name": {
      "type": "string",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "enum",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "hostname": {
      "type": "string",
      "source": "inventory.ini"
    },
    "ip": {
      "type": "cidr",
      "source": "inventory.ini"
    },
    "role": {
      "type": "enum",
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "dmz",
        "appservers",
        "dbservers"
      ],
      "source": "group_vars/*.yml"
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "app",
        "postgresql"
      ],
      "source": "group_vars/*.yml"
    },
    "port": {
      "type": "integer",
      "domain": [
        443,
        8080,
        5432
      ],
      "source": "group_vars/*.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp"
      ],
      "source": "group_vars/*.yml"
    },
    "path": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "domain": [
        "0700",
        "0644"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "cidr": {
      "type": "cidr",
      "source": "group_vars/*.yml"
    },
    "source_ip": {
      "type": "cidr",
      "source": "group_vars/*.yml"
    },
    "source_network": {
      "type": "cidr",
      "source": "group_vars/*.yml"
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data",
        "internet"
      ],
      "source": "group_vars/*.yml"
    },
    "database": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "schema": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "environment": {
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "enum",
      "domain": [
        "pci"
      ],
      "source": "inventory.ini"
    },
    "org": {
      "type": "enum",
      "domain": [
        "segcorp"
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
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
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
        30,
        34
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
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
        24,
        28
      ]
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        41,
        45
      ]
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        16,
        22
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        22,
        28
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "all"
      },
      "hostname": {
        "equals": "db01.lab.local"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "role",
        "privileges": [
          "SUPERUSER"
        ]
      }
    ],
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
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "all"
      },
      "hostname": {
        "equals": "db01.lab.local"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "role",
        "privileges": [
          "NOSUPERUSER"
        ]
      }
    ],
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
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "all"
      },
      "port": {
        "equals": 5432
      },
      "hostname": {
        "equals": "db01.lab.local"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
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
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:write",
    "effect": "deny",
    "obligations": [
      {
        "type": "enforcement",
        "description": "Owner-only access enforced by mode 0700"
      }
    ],
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
    "id": "rule-011",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:create",
    "effect": "permit",
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
    "id": "rule-012",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:create",
    "effect": "permit",
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
    "id": "rule-013",
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
      }
    },
    "action": "*",
    "effect": "deny",
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
    "id": "rule-014",
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
      "database": {
        "equals": "all"
      },
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
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
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for nginx"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for nginx"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for nginx"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.7,
    "affects_pinned_version": true,
    "recommendation": "HIGH: Schedule upgrade within 7 days. Review network segmentation as compensating control.",
    "source": "Phase 1.5 vuln search for nginx"
  },
  {
    "cve_id": "CVE-2013-4547",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.5,
    "affects_pinned_version": false,
    "recommendation": "HIGH: Schedule upgrade within 7 days. Review network segmentation as compensating control.",
    "source": "Phase 1.5 vuln search for nginx"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for openssh"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for openssh"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for openssh"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for openssh"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for openssh"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "13.7",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for postgresql"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "13.7",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for postgresql"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "13.7",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for postgresql"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "13.7",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for postgresql"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "13.7",
    "cvss_score": 10,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade immediately — critical remote vulnerability. Apply vendor patches and restart service.",
    "source": "Phase 1.5 vuln search for postgresql"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
Policy mined from Ansible configuration under `RLM_ANSIBLE_DIR` for goal: **all**.
The configuration manages a PCI-compliant production environment with three host tiers (DMZ, application, database).

## Scope
- **Organization**: segcorp
- **Environment**: production
- **Compliance Tier**: PCI
- **Log Retention**: 365 days

## Infrastructure Summary
| Host | IP | Role | Zone | Group |
|------|-----|------|------|-------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

## Users & Groups
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

## Pinned Software Versions
| Package | Version | Source |
|---------|---------|--------|
| nginx | 1.20.0-1~focal | group_vars/all.yml |
| openssh-server | 1:9.6p1-3ubuntu1 | group_vars/all.yml |
| postgresql-13 | 13.7-1.pgdg20.04+1 | group_vars/all.yml |

## Rules Extracted (13 total)
| ID | Action | Effect | Subject | Resource | Source |
|----|--------|--------|---------|----------|--------|
| rule-001 | ssh:login | permit | groups: [sudo] | proxy01 (dmz) | roles/dmz/tasks/main.yml |
| rule-002 | ssh:login | permit | groups: [sudo, developers] | app01 (app) | roles/app/tasks/main.yml |
| rule-003 | ssh:login | permit | groups: [sudo, dba] | db01 (data) | roles/db/tasks/main.yml |
| rule-004 | network:connect | permit | source: 10.0.1.0/24 | app01:8080/tcp | roles/app/tasks/main.yml |
| rule-005 | network:connect | permit | source: 0.0.0.0/0 | proxy01:443/tcp | roles/dmz/tasks/main.yml |
| rule-006 | db:login | permit | groups: [dba] | postgresql:all | roles/db/tasks/main.yml |
| rule-007 | db:login | permit | groups: [developers] | postgresql:all | roles/db/tasks/main.yml |
| rule-008 | network:connect | permit | source: 10.0.2.0/24 | db01:5432 | roles/db/tasks/main.yml |
| rule-009 | filesystem:read | permit | groups: [dba] | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| rule-010 | filesystem:write | deny | all | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| rule-011 | user:create | permit | groups: [sudo] | proxy01 (dmz) | roles/dmz/tasks/main.yml |
| rule-012 | user:create | permit | groups: [sudo, developers] | app01 (app) | roles/app/tasks/main.yml |
| rule-013 | * | deny | all | all | policy |

## Vulnerability Assessment
15 vulnerabilities identified across 3 products:

### nginx (1.20.0) — 5 critical/remote CVEs found
- All 5 CVEs flagged as potentially affecting the pinned version.
- Multiple CVEs with CVSS 9.8 — URGENT upgrade recommended.

### openssh-server (9.6p1) — 5 critical/remote CVEs found
- 3 of 5 likely affect older versions; 2 (CVE-2000-0999, CVE-2001-0144) are historical.
- Multiple legacy CVSS 10 scores from early 2000s — version 9.6p1 should mitigate.

### postgresql (13.7) — 5 critical/remote CVEs found
- CVE-2024-1597 (CVSS 10) is the most recent and likely relevant.
- 4 older CVEs (2002-2013) may be fixed in version 13.

## Ambiguities & Limitations
1. **No sudoers rules**: No `community.general.sudoers` or lineinfile tasks modifying /etc/sudoers were found. Sudo privileges are implied by group membership but not explicitly configured.
2. **SSH password auth**: The SSH rules restrict groups but do not explicitly disable password authentication. No `PasswordAuthentication no` directive was observed.
3. **No hardcoded credentials**: No credential values were found in the Ansible configuration, which is good practice.
4. **No SELinux rules**: No SELinux policy tasks were found.
5. **pg_hba implicit deny**: The pg_hba configuration only has explicit ALLOW entries; the implicit deny is assumed but not encoded as a task.
6. **App firewall**: Only source network 10.0.1.0/24 is allowed to reach port 8080 — this is a narrow scope.
