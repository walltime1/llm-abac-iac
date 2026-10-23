# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:32:08_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 21_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "domain": null,
      "source": "group_vars/all.yml",
      "values": [
        {
          "name": "admin",
          "uid": 1001,
          "groups": [
            "sudo"
          ],
          "clearance": "secret",
          "department": "operations"
        },
        {
          "name": "developer",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "clearance": "confidential",
          "department": "engineering"
        },
        {
          "name": "dba",
          "uid": 1003,
          "groups": [
            "dba"
          ],
          "clearance": "secret",
          "department": "data"
        }
      ]
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "sudo",
        "developers",
        "dba"
      ]
    },
    "clearance_levels": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "secret",
        "confidential"
      ]
    },
    "departments": {
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "operations",
        "engineering",
        "data"
      ]
    },
    "source_network": {
      "domain": null,
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml",
      "values": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "10.0.3.0/24",
        "0.0.0.0/0"
      ]
    }
  },
  "resources": {
    "hosts": {
      "domain": null,
      "source": "inventory.ini",
      "values": [
        {
          "hostname": "proxy01.lab.local",
          "ip": "10.0.1.10",
          "role": "reverse_proxy",
          "zone": "dmz",
          "inventory_group": "dmz"
        },
        {
          "hostname": "app01.lab.local",
          "ip": "10.0.2.10",
          "role": "application",
          "zone": "app",
          "inventory_group": "appservers"
        },
        {
          "hostname": "db01.lab.local",
          "ip": "10.0.3.10",
          "role": "primary",
          "zone": "data",
          "inventory_group": "dbservers"
        }
      ]
    },
    "inventory_groups": {
      "domain": [
        "dmz",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini",
      "values": [
        "dmz",
        "appservers",
        "dbservers"
      ]
    },
    "services": {
      "domain": null,
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml",
      "values": [
        {
          "name": "http",
          "port": 443,
          "protocol": "tcp",
          "host_group": "dmz"
        },
        {
          "name": "app",
          "port": 8080,
          "protocol": "tcp",
          "host_group": "appservers"
        },
        {
          "name": "postgresql",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers"
        }
      ]
    },
    "paths": {
      "domain": null,
      "source": "group_vars/dbservers.yml",
      "values": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgresql"
        }
      ]
    },
    "networks": {
      "domain": null,
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml",
      "values": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "DMZ subnet"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "app",
          "label": "appservers subnet"
        },
        {
          "cidr": "10.0.3.0/24",
          "zone": "data",
          "label": "dbservers subnet"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "internet",
          "label": "internet"
        }
      ]
    }
  },
  "environment": {
    "org": {
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "segcorp"
      ]
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini",
      "values": [
        "production"
      ]
    },
    "compliance_tier": {
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml,inventory.ini",
      "values": [
        "pci"
      ]
    },
    "retention_days": {
      "domain": null,
      "source": "group_vars/all.yml",
      "values": [
        365
      ]
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "SSH login to appservers allowed for sudo and developers groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        14,
        18
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "SSH login to dbservers allowed for sudo and dba groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        20,
        24
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "SSH login to dmz allowed for sudo group only",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        15,
        19
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Sudo access on appservers for sudo and developers groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "sudoers:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "require_password",
        "value": true
      }
    ],
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        14,
        18
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Sudo access on dbservers for sudo and dba groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "sudoers:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "require_password",
        "value": true
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        20,
        24
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Sudo access on dmz for sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "sudoers:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "require_password",
        "value": true
      }
    ],
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        15,
        19
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "DBAs get SUPERUSER login on PostgreSQL",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "db_privilege",
        "value": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        9,
        13
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Developers get NOSUPERUSER login on PostgreSQL",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "db_privilege",
        "value": "NOSUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        14,
        18
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "PostgreSQL network access allowed from appservers subnet only",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
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
        19,
        23
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "App server port 8080 accessible from DMZ subnet only",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
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
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        9,
        13
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "description": "DMZ HTTPS port 443 accessible from internet",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "inventory_group": {
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
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        10,
        14
      ]
    }
  },
  {
    "rule_id": "rule-013",
    "description": "PostgreSQL data directory with strict permissions",
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
        7,
        12
      ]
    }
  },
  {
    "rule_id": "rule-014",
    "description": "PostgreSQL data directory with strict permissions",
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        7,
        12
      ]
    }
  },
  {
    "rule_id": "rule-015",
    "description": "Create shell accounts for developers and sudo group members on appservers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
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
        4,
        8
      ]
    }
  },
  {
    "rule_id": "rule-016",
    "description": "Create shell accounts for sudo group members on dmz",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
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
        6,
        10
      ]
    }
  },
  {
    "rule_id": "rule-999",
    "description": "Default deny all access not explicitly permitted",
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
      "environment": {
        "equals": "production"
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
      "service": {
        "equals": "postgresql"
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
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Monitor nginx (CVE affects older versions)"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Monitor nginx (CVE affects older versions)"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ",
    "affects_pinned_version": true,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Review and patch nginx"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Monitor postgresql (CVE affects older versions)"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Monitor postgresql (CVE affects older versions)"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "affects_pinned_version": true,
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Review and patch postgresql"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR` (eval_fixtures/f6_intent_vs_effective). The policy covers SSH access, sudo permissions, database access, firewall rules, and filesystem permissions for a multi-tier PCI-compliant production environment.

**Organization:** segcorp  
**Environment:** production  
**Compliance Tier:** PCI DSS  

---

## Attribute Catalog

### Subjects

| Attribute | Domain | Source |
|-----------|--------|--------|
| users | 3 defined users (admin, developer, dba) | group_vars/all.yml |
| groups | sudo, developers, dba | group_vars/all.yml |
| clearance_levels | secret, confidential | group_vars/all.yml |
| departments | operations, engineering, data | group_vars/all.yml |
| source_network | 10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24, 0.0.0.0/0 | group_vars/*.yml |

### Resources

| Attribute | Domain | Source |
|-----------|--------|--------|
| hosts | proxy01, app01, db01 (by hostname) | inventory.ini |
| inventory_groups | dmz, appservers, dbservers | inventory.ini |
| services | http (443), app (8080), postgresql (5432) | group_vars/*.yml |
| paths | /var/lib/postgresql/data | group_vars/dbservers.yml |
| networks | DMZ/app/data subnets, internet | group_vars/*.yml |

### Environment

| Attribute | Value | Source |
|-----------|-------|--------|
| org | segcorp | group_vars/all.yml |
| environment | production | inventory.ini |
| compliance_tier | pci | group_vars/all.yml, inventory.ini |
| retention_days | 365 | group_vars/all.yml |

---

## Vulnerability Assessment

### Pinned Software Versions

| Package | Version | Source |
|---------|---------|--------|
| nginx | 1.20.0-1~focal | group_vars/all.yml |
| openssh-server | 1:9.1p1-1ubuntu1 | group_vars/all.yml |
| postgresql | 16.2-1.pgdg22.04+1 | group_vars/all.yml |

### Vulnerabilities Found

| CVE ID | Product | CVSS | Affects Pinned | Recommendation |
|--------|---------|------|----------------|----------------|
| CVE-2021-46461 | nginx | 9.8 | **YES** | Review and patch nginx to latest version |
| CVE-2009-3555 | nginx | 9.8 | No | Monitor (affects older versions) |
| CVE-2016-0746 | nginx | 9.8 | No | Monitor (affects older versions) |
| CVE-2024-1597 | postgresql | 10.0 | **YES** | Review and patch PostgreSQL to latest version |
| CVE-2002-1399 | postgresql | 10.0 | No | Monitor (affects older versions) |
| CVE-2007-3279 | postgresql | 10.0 | No | Monitor (affects older versions) |

**Summary:** 2 of 6 CVEs affect the pinned software versions. Immediate patching recommended for CVE-2021-46461 (nginx) and CVE-2024-1597 (PostgreSQL SQL injection).

---

## Extracted ABAC Rules

### SSH Access Rules

| Rule ID | Description | Subject | Resource | Effect |
|---------|-------------|---------|----------|--------|
| rule-001 | SSH to appservers | sudo, developers | appservers | permit |
| rule-002 | SSH to dbservers | sudo, dba | dbservers | permit |
| rule-003 | SSH to dmz | sudo | dmz | permit |

### Sudo Rules

| Rule ID | Description | Subject | Resource | Effect | Obligations |
|---------|-------------|---------|----------|--------|------------|
| rule-004 | Sudo on appservers | sudo, developers | appservers | permit | require_password: true |
| rule-005 | Sudo on dbservers | sudo, dba | dbservers | permit | require_password: true |
| rule-006 | Sudo on dmz | sudo | dmz | permit | require_password: true |

### Database Access Rules

| Rule ID | Description | Subject | Resource | Effect | Obligations |
|---------|-------------|---------|----------|--------|------------|
| rule-007 | DB superuser for DBAs | dba | postgresql | permit | db_privilege: SUPERUSER |
| rule-008 | DB read-only for devs | developers | postgresql | permit | db_privilege: NOSUPERUSER |
| rule-009 | PostgreSQL network access | 10.0.2.0/24 | postgresql | permit | - |

### Firewall Rules

| Rule ID | Description | Subject | Resource | Effect |
|---------|-------------|---------|----------|--------|
| rule-011 | App port 8080 from DMZ | 10.0.1.0/24 | appservers:8080 | permit |
| rule-012 | HTTPS from internet | 0.0.0.0/0 | dmz:443 | permit |

### Filesystem Rules

| Rule ID | Description | Resource | Action | Effect |
|---------|-------------|----------|--------|--------|
| rule-013 | PG data dir read | /var/lib/postgresql/data (0700, postgres:postgres) | filesystem:read | permit |
| rule-014 | PG data dir write | /var/lib/postgresql/data (0700, postgres:postgres) | filesystem:write | permit |

### User Provisioning Rules

| Rule ID | Description | Subject | Resource | Effect |
|---------|-------------|---------|----------|--------|
| rule-015 | Create users on appservers | developers, sudo | appservers | permit |
| rule-016 | Create users on dmz | sudo | dmz | permit |

### Default Deny

| Rule ID | Description | Effect |
|---------|-------------|--------|
| rule-999 | Default deny all unlisted access | deny |

**Total Rules:** 16 (15 permit, 1 deny)

---

## Ambiguities & Notes

1. **Credentials:** No hardcoded passwords or SSH keys found in the Ansible configuration. Credential management is delegated to external systems.

2. **Session Logging:** The Ansible configuration does not explicitly define audit/logging tasks for session monitoring. Consider adding profile.d scripts or auditd rules for PCI compliance.

3. **PostgreSQL pg_hba.conf:** The role tasks configure pg_hba.conf with `scram-sha-256` authentication but do not explicitly deny other connection types. The default-deny rule covers this gap.

4. **SELinux:** No SELinux configuration found in the Ansible tasks. Consider adding seboolean rules if SELinux is enforced.

5. **Load Balancer/Monitoring:** No load balancer or Nagios monitoring configurations found in this Ansible directory.

---

## Policy Statistics

- **Total Rules:** 16
- **Permit Rules:** 15
- **Deny Rules:** 1 (default deny)
- **Rules with Obligations:** 5
- **Vulnerabilities Identified:** 6 (2 affecting pinned versions)

---

*Report generated by ABAC Policy Mining from Ansible Configuration*
