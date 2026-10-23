# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:50:20_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 7 | Rules: 18_  
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
    ],
    "source_network": {
      "values": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/appservers.yml, group_vars/dbservers.yml, group_vars/dmz.yml"
    },
    "source_ip": {
      "values": [
        "10.0.1.10",
        "10.0.2.10",
        "10.0.3.10"
      ],
      "source": "inventory.ini"
    },
    "source_zone": {
      "values": [
        "dmz",
        "app",
        "data",
        "internet"
      ],
      "source": "inventory.ini, group_vars/dmz.yml"
    }
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
  ]
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "role": {
        "equals": "application"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
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
    "rule_id": "rule-002",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
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
    "rule_id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "reverse_proxy"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
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
    "rule_id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
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
    "rule_id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
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
    "rule_id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
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
    "rule_id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
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
    "rule_id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
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
    "rule_id": "rule-009",
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        13,
        19
      ]
    },
    "obligations": [
      {
        "type": "audit",
        "description": "PCI-DSS requires logging of access to database data directory"
      }
    ]
  },
  {
    "rule_id": "rule-010",
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
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
    "rule_id": "rule-011",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
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
    "rule_id": "rule-012",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
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
    "rule_id": "rule-013",
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
        1,
        1
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
      "compliance_tier": {
        "equals": "pci"
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
      "compliance_tier": {
        "equals": "pci"
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
      "host_group": {
        "equals": "appservers"
      },
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
    "id": "rule-004",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
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
    "id": "rule-005",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
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

# ABAC Policy Report - SEGCorp Infrastructure

## Executive Summary
This report documents the ABAC policy mined from the Ansible configuration for SEGCorp's production infrastructure (PCI-DSS compliance tier). The policy covers SSH access, network firewall rules, PostgreSQL database access, filesystem permissions, and user provisioning across three host groups: dmz, appservers, and dbservers.

## Attribute Catalog

### Subjects
- **Users**: admin (sudo, operations, secret), developer (developers, engineering, confidential), dba (dba, data, secret)
- **Groups**: sudo, developers, dba
- **Clearance Levels**: secret, confidential
- **Departments**: operations, engineering, data
- **Source Networks**: 10.0.1.0/24 (DMZ), 10.0.2.0/24 (app), 0.0.0.0/0 (internet)

### Resources
- **Hosts**: proxy01.lab.local (dmz/reverse_proxy), app01.lab.local (app/application), db01.lab.local (data/primary)
- **Services**: nginx:443/tcp (dmz), app:8080/tcp (appservers), postgresql:5432/tcp (dbservers), ssh:22/tcp (all)
- **Paths**: /var/lib/postgresql/data (postgres:postgres, 0700)
- **Networks**: 10.0.1.0/24 (dmz_to_app), 10.0.2.0/24 (app_to_db), 0.0.0.0/0 (public)

### Environment
- **Organization**: segcorp
- **Environment**: production
- **Compliance Tier**: pci
- **Log Retention**: 365 days

## Rules Summary
| Rule ID | Action | Subject | Resource | Effect |
|---------|--------|---------|----------|--------|
| rule-001 | ssh:login | sudo, developers | application host | permit |
| rule-002 | ssh:login | sudo, dba | primary host | permit |
| rule-003 | ssh:login | sudo | reverse_proxy host | permit |
| rule-004 | network:connect | 10.0.1.0/24 | appservers:8080 | permit |
| rule-005 | network:connect | 0.0.0.0/0 | dmz:443 | permit |
| rule-006 | network:connect | 10.0.2.0/24 | dbservers:5432 | permit |
| rule-007 | db:login (SUPERUSER) | dba | dbservers:postgresql | permit |
| rule-008 | db:login (NOSUPERUSER) | developers | dbservers:postgresql | permit |
| rule-009 | filesystem:read | sudo | /var/lib/postgresql/data | permit |
| rule-010 | filesystem:write | sudo | /var/lib/postgresql/data | permit |
| rule-011 | user:create | sudo, developers | appservers | permit |
| rule-012 | user:create | sudo | dmz | permit |
| rule-013 | * | all | all | deny |

## Vulnerability Assessment
| CVE | Product | Severity | CVSS | Affects Pinned | Recommendation |
|-----|---------|----------|------|----------------|----------------|
| CVE-2021-46461 | nginx | critical | 9.8 | YES | Update nginx to version bundling njs > 0.7.0 |
| CVE-2000-0999 | openssh | critical | 10.0 | No | Legacy CVE, OpenSSH 9.6p1 not affected |
| CVE-2002-1399 | postgresql | critical | 10.0 | No | Legacy CVE, PostgreSQL 13.7 not affected |

## Ambiguities
1. **Credential Storage**: No explicit credential management (e.g., vault, secrets plugin) observed in the Ansible configuration. Database passwords and SSH keys are not managed via Ansible vault in the visible files.
2. **NJS Module Version**: The nginx version 1.20.0 may bundle a vulnerable njs module (<=0.7.0). Independent verification of the njs module version is recommended.
3. **Implicit Deny**: The pg_hba.conf configuration only adds allow rules; implicit deny is assumed but not explicitly configured in Ansible.
4. **No Sudoers Rules**: While AllowGroups restricts SSH, no explicit sudoers configuration was found in the Ansible files. Sudo access for the sudo group is assumed but not defined.
5. **SELinux**: No SELinux policies or booleans were configured in the visible Ansible files.

## Obligations
- PCI-DSS audit logging is attached to filesystem access rules for the PostgreSQL data directory (rule-009).
- Log retention is set to 365 days per group_vars/all.yml.
