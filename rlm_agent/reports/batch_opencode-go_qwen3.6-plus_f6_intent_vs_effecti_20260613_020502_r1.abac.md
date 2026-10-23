# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 02:12:42_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 16 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

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
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "group_vars/all.yml"
      },
      {
        "name": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "clearance": "secret",
        "department": "data",
        "source": "group_vars/all.yml"
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [],
        "clearance": "internal",
        "department": "system",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": {
      "values": [
        "sudo",
        "developers",
        "dba"
      ],
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "values": [
        "secret",
        "confidential"
      ],
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "values": [
        "operations",
        "engineering",
        "data"
      ],
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source_networks": {
      "values": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "domain": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/*.yml"
    },
    "source_network": {
      "values": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/*.yml"
    },
    "user": {
      "values": [
        "admin",
        "developer",
        "dba",
        "postgres"
      ],
      "domain": [
        "admin",
        "developer",
        "dba",
        "postgres"
      ],
      "source": "group_vars/all.yml, roles/db/tasks/main.yml"
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
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
      },
      {
        "name": "https",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
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
        "label": "DMZ subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "Appservers subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "Internet",
        "source": "group_vars/dmz.yml"
      }
    ],
    "host_groups": {
      "values": [
        "dmz",
        "appservers",
        "dbservers"
      ],
      "domain": [
        "dmz",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "protocols": {
      "values": [
        "tcp"
      ],
      "domain": [
        "tcp",
        "udp"
      ],
      "source": "group_vars/*.yml"
    },
    "databases": {
      "values": [
        "all"
      ],
      "domain": [
        "all",
        "postgres",
        "appdb"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "service_attr": {
      "values": [
        "ssh",
        "postgresql",
        "app",
        "https"
      ],
      "domain": [
        "ssh",
        "postgresql",
        "app",
        "https"
      ],
      "source": "roles/*/tasks/main.yml"
    },
    "port_attr": {
      "values": [
        22,
        5432,
        8080,
        443
      ],
      "source": "group_vars/*.yml, roles/*/tasks/main.yml"
    },
    "protocol_attr": {
      "values": [
        "tcp"
      ],
      "domain": [
        "tcp",
        "udp"
      ],
      "source": "group_vars/*.yml"
    },
    "database_attr": {
      "values": [
        "all"
      ],
      "domain": [
        "all",
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "host_group_attr": {
      "values": [
        "dmz",
        "appservers",
        "dbservers"
      ],
      "domain": [
        "dmz",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "path_attr": {
      "values": [
        "/var/lib/postgresql/data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "owner_attr": {
      "values": [
        "postgres"
      ],
      "domain": [
        "postgres",
        "root",
        "appuser"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group_attr": {
      "values": [
        "postgres"
      ],
      "domain": [
        "postgres",
        "root",
        "appuser"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode_attr": {
      "values": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": "segcorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
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
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "ssh"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        21,
        25
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "ssh"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        38,
        42
      ]
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "service": {
        "equals": "ssh"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        27,
        31
      ]
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
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
      "task": "Create DB superuser role for DBAs",
      "lines": [
        20,
        24
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
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
      "task": "Create DB read-only role for developers",
      "lines": [
        26,
        30
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
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
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        32,
        36
      ]
    }
  },
  {
    "id": "rule-007",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        13,
        19
      ]
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        19,
        25
      ]
    }
  },
  {
    "id": "rule-009",
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
      "lines": [
        12,
        18
      ]
    }
  },
  {
    "id": "rule-010",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        12,
        18
      ]
    }
  },
  {
    "id": "rule-011",
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
    "environment_condition": {
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
        6,
        11
      ]
    }
  },
  {
    "id": "rule-012",
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
    "environment_condition": {
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
        12,
        17
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "*",
    "effect": "deny",
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
    "id": "rule-015",
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
    "id": "rule-016",
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
    "id": "rule-017",
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
    "id": "rule-018",
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
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Upgrade nginx from pinned 1.20.0 to latest stable release. CRITICAL: This vulnerability is in the KEV catalog - immediate patching required."
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade nginx from pinned 1.20.0 to latest stable release."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from pinned 1.20.0 to latest stable release."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from pinned 1.20.0 to latest stable release."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.7,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from pinned 1.20.0 to latest stable release."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh-server",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh from pinned 9.1p1 to latest stable release."
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh-server",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh from pinned 9.1p1 to latest stable release."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh-server",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh from pinned 9.1p1 to latest stable release."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh-server",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh from pinned 9.1p1 to latest stable release."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh-server",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh from pinned 9.1p1 to latest stable release."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade postgresql from pinned 16.2 to latest minor release."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade postgresql from pinned 16.2 to latest minor release."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from pinned 16.2 to latest minor release. CRITICAL: KEV-listed vulnerability."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade postgresql from pinned 16.2 to latest minor release."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade postgresql from pinned 16.2 to latest minor release."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
Mined an Attribute-Based Access Control (ABAC) policy from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`.
Coverage: **all** slices (ssh, sudo, db-access, firewall, filesystem).

## Coverage Summary

| Slice | Rules | Status |
|-------|-------|--------|
| SSH | 3 | rule-001 (appservers), rule-002 (dbservers), rule-003 (dmz) |
| DB Access | 2 | rule-004 (DBA superuser), rule-005 (developer read-only) |
| Firewall | 3 | rule-006 (pg_hba), rule-007 (app firewall), rule-008 (HTTPS) |
| Filesystem | 2 | rule-009 (postgres read), rule-010 (postgres write) |
| Identity | 2 | rule-011 (app user provision), rule-012 (dmz admin provision) |
| Default Deny | 1 | rule-013 (catch-all) |

**Total rules: 13**

## Attribute Catalog
- **Subjects**: 4 users (admin, developer, dba, postgres), 3 groups (sudo, developers, dba)
- **Clearance levels**: secret, confidential
- **Departments**: operations, engineering, data
- **Resources**: 3 hosts, 3 services, 1 filesystem path, 3 network segments
- **Environment**: org=segcorp, environment=production, compliance_tier=pci

## Vulnerability Assessment

### Pinned Software
| Package | Pinned Version | Critical/Remote CVEs | KEV CVEs |
|---------|---------------|---------------------|----------|
| nginx | 1.20.0 | 5 | 1 (CVE-2009-3555) |
| openssh-server | 9.1p1 | 5 | 0 |
| postgresql | 16.2 | 5 | 1 (CVE-2024-1597) |

### Key Findings
- Most critical/remote CVEs are historical (2000-2013 era) and do **not** affect the pinned versions.
- **CVE-2009-3555** (nginx, CVSS 9.8, KEV): TLS renegotiation vulnerability. Very old; likely not applicable to nginx 1.20.0.
- **CVE-2024-1597** (postgresql, CVSS 10, KEV): Actively exploited; verify impact on postgresql 16.2.

## Ambiguities

1. **No sudoers rules**: No explicit sudo configuration found in the Ansible files. The `sudo` group is referenced in SSH AllowGroups but no sudo privilege rules were defined.
2. **No explicit DENY rules**: Firewall rules are allow-only; deny-default is implicit. Represented as rule-013 (default-deny).
3. **Postgres pg_hba**: Uses `host all all` which is broad; no per-database or per-schema restrictions found.
4. **User provisioning**: The `user` task uses a loop over all `users` with a `when` filter, but the actual provisioned users depend on runtime inventory data.
5. **Session logging/audit**: No explicit session logging or audit obligations found in the configuration.
6. **Credentials management**: No credential handling (vault, secrets) tasks found in the role files.
7. **System user "postgres"**: Not defined in the users list in group_vars/all.yml; discovered from filesystem task.

## Operator Grammar Compliance
All rules use only the four allowed operators: `equals`, `in`, `any_of`, `all_of`.
No forbidden patterns (natural-language strings, MongoDB operators, nested operators) were used.

## Source Files Analyzed
- `inventory.ini`
- `group_vars/all.yml`
- `group_vars/appservers.yml`
- `group_vars/dbservers.yml`
- `group_vars/dmz.yml`
- `roles/app/tasks/main.yml`
- `roles/db/tasks/main.yml`
- `roles/dmz/tasks/main.yml`
