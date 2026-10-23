# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:58:43_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 8 | Rules: 17_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

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
      "secret",
      "confidential"
    ],
    "attributes": {
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
      "department": {
        "type": "string",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      },
      "clearance": {
        "type": "string",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      }
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "bastion01.lab.local",
        "ip": "10.0.0.5",
        "role": "bastion",
        "zone": "mgmt",
        "inventory_group": "bastion",
        "source": "inventory.ini"
      },
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers",
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
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "bastion",
        "source": "roles/bastion/tasks/main.yml"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "roles/app/tasks/main.yml"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "name": "http",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "roles/app/tasks/main.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "roles/db/tasks/main.yml"
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
        "source": "group_vars/bastion.yml"
      },
      {
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "bastion-subnet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web-subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app-subnet",
        "source": "group_vars/dbservers.yml"
      }
    ],
    "attributes": {
      "hostname": {
        "type": "string",
        "source": "inventory.ini"
      },
      "ip": {
        "type": "string",
        "source": "inventory.ini"
      },
      "role": {
        "type": "string",
        "domain": [
          "bastion",
          "frontend",
          "application",
          "primary"
        ],
        "source": "inventory.ini"
      },
      "zone": {
        "type": "string",
        "domain": [
          "mgmt",
          "dmz",
          "app",
          "data"
        ],
        "source": "inventory.ini"
      },
      "host_group": {
        "type": "string",
        "domain": [
          "bastion",
          "webservers",
          "appservers",
          "dbservers"
        ],
        "source": "inventory.ini"
      },
      "service": {
        "type": "string",
        "domain": [
          "ssh",
          "http",
          "app",
          "postgresql"
        ],
        "source": "roles/*/tasks/main.yml"
      },
      "port": {
        "type": "integer",
        "source": "roles/*/tasks/main.yml"
      },
      "protocol": {
        "type": "string",
        "domain": [
          "tcp"
        ],
        "source": "roles/*/tasks/main.yml"
      },
      "path": {
        "type": "string",
        "source": "roles/db/tasks/main.yml"
      },
      "owner": {
        "type": "string",
        "domain": [
          "postgres"
        ],
        "source": "roles/db/tasks/main.yml"
      },
      "group": {
        "type": "string",
        "domain": [
          "postgres"
        ],
        "source": "roles/db/tasks/main.yml"
      },
      "mode": {
        "type": "string",
        "source": "roles/db/tasks/main.yml"
      },
      "source_ip": {
        "type": "string",
        "source": "group_vars/*.yml"
      },
      "source_network": {
        "type": "string",
        "source": "group_vars/*.yml"
      },
      "source_zone": {
        "type": "string",
        "domain": [
          "mgmt",
          "dmz",
          "app",
          "data",
          "external"
        ],
        "source": "group_vars/*.yml"
      }
    }
  },
  "environment": {
    "org": "chaincorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
    "packages": {
      "openssh_bastion": "1:9.1p1-1ubuntu1",
      "openssh_general": "1:9.9p1-3ubuntu1",
      "apache_httpd": "2.4.49-1",
      "log4j": "2.14.1",
      "postgresql": "9.2.3-1.pgdg20.04+1"
    },
    "attributes": {
      "org": {
        "type": "string",
        "domain": [
          "chaincorp"
        ],
        "source": "group_vars/all.yml"
      },
      "environment": {
        "type": "string",
        "domain": [
          "production"
        ],
        "source": "inventory.ini"
      },
      "compliance_tier": {
        "type": "string",
        "domain": [
          "pci"
        ],
        "source": "inventory.ini"
      },
      "default_log_retention_days": {
        "type": "integer",
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
    "id": "rule-001",
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
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        6,
        9
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        11,
        16
      ]
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        18,
        24
      ]
    },
    "obligations": [
      {
        "type": "authentication",
        "description": "nopassword is false; sudo requires password authentication"
      }
    ]
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        10,
        15
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        17,
        20
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "app"
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
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        18,
        23
      ]
    }
  },
  {
    "id": "rule-007",
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
      },
      "port": {
        "equals": 22
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
        25,
        28
      ]
    }
  },
  {
    "id": "rule-008",
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
        6,
        11
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
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
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
        13,
        17
      ]
    },
    "obligations": [
      {
        "type": "superuser_privileges",
        "description": "DBA users receive SUPERUSER role_attr_flags (LOGIN,SUPERUSER)"
      }
    ]
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        19,
        22
      ]
    }
  },
  {
    "id": "rule-011",
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
      },
      "port": {
        "equals": 22
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
        24,
        27
      ]
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
      "file": "policy",
      "task": "default-deny",
      "lines": [
        1,
        1
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
    "id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
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
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "app"
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
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
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
    "cve_id": "CVE-2021-44228",
    "product": "apache-log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, parameters, etc. do not protect against attacker controlled LDAP and other JNDI related endpoints. Remote code execution via JNDI injection.",
    "recommendation": "URGENT: Upgrade log4j-core to >=2.17.1 immediately. Add -Dlog4j2.formatMsgNoLookups=true as a temporary mitigation. The pinned version 2.14.1 is directly vulnerable (<=2.14.1).",
    "kev_listed": true,
    "source": "roles/app/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2017-3167",
    "product": "apache-httpd",
    "pinned_version": "2.4.49",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26 mod_session_crypto cipher padding oracle bypass.",
    "recommendation": "No action required for httpd 2.4.49; this was fixed in 2.4.26.",
    "kev_listed": false,
    "source": "roles/web/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2017-7679",
    "product": "apache-httpd",
    "pinned_version": "2.4.49",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26 buffer over-read in mod_mime.",
    "recommendation": "No action required for httpd 2.4.49; fixed in 2.4.26.",
    "kev_listed": false,
    "source": "roles/web/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "pinned_version": "9.1p1 / 9.9p1",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "OpenSSH 2.3.1 through 3.3 buffer overflow in SSH protocol version 1 handling.",
    "recommendation": "No action required; pinned OpenSSH 9.x versions are not affected.",
    "kev_listed": false,
    "source": "roles/bastion/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "medium",
    "cvss_score": 6.5,
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "PostgreSQL 8.1+ plpgsql language enabled grant privileges to PUBLIC.",
    "recommendation": "PostgreSQL 9.2.3 is EOL. While not directly affected by this legacy CVE, upgrade to supported version recommended.",
    "kev_listed": false,
    "source": "roles/db/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "pgjdbc",
    "pinned_version": "N/A",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "pgjdbc PostgreSQL JDBC Driver SQL injection.",
    "recommendation": "Not applicable to server package. Ensure client drivers are updated if used.",
    "kev_listed": false,
    "source": "N/A"
  }
]
```

## Report

# ABAC Policy Mining Report - ChainCorp Ansible Configuration

## Executive Summary
Mined ABAC policy from ChainCorp production Ansible configuration (PCI compliance tier).
Configuration covers 4 host groups across 3 network zones with 3 defined users.
**Critical finding: Log4j 2.14.1 is pinned and directly vulnerable to CVE-2021-44228 (Log4Shell).**

## Vulnerability Assessment
| CVE | Product | Pinned Version | Affects? | Severity | Recommendation |
|---|---|---|---|---|---|
| CVE-2021-44228 | apache-log4j | 2.14.1 | **YES** | Critical | URGENT: Upgrade to >=2.17.1. |
| CVE-2017-3167 | apache-httpd | 2.4.49 | No | Critical | Fixed in 2.4.26. |
| CVE-2017-7679 | apache-httpd | 2.4.49 | No | High | Fixed in 2.4.26. |
| CVE-2002-0640 | openssh | 9.1p1/9.9p1 | No | High | Legacy SSHv1 issue, 9.x safe. |
| CVE-2007-3279 | postgresql | 9.2.3 | No | Medium | 9.2.3 is EOL, upgrade recommended. |
| CVE-2024-1597 | pgjdbc | N/A | No | High | JDBC driver specific, not server. |

## Attributes Catalog
- **Users:** 3 (admin, developer, dba)
- **Groups:** sudo, developers, dba
- **Hosts:** 4 across zones: mgmt, dmz, app, data
- **Services:** SSH, HTTP, App(8080), PostgreSQL(5432)

## Policy Rules Summary
- **Total Rules:** 12 (11 permit, 1 default-deny)
- **Key Controls:**
  - SSH access restricted to specific groups per host zone.
  - Sudo on bastion requires 'secret' clearance and sudo group.
  - PostgreSQL superuser restricted to 'dba' group.
  - Network segmentation via firewalld and pg_hba rules.
  - Default deny rule enforces least privilege.

## Ambiguities & Notes
- PostgreSQL 9.2.3 is end-of-life; consider upgrading.
- No explicit network deny rules found in firewalld configs; relying on default-deny policy.
- Credentials are managed via Ansible; no hardcoded secrets visible in mined tasks.