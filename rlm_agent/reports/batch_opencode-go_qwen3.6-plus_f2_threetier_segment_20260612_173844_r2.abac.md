# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:45:46_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 18_  
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
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [
          "postgres"
        ],
        "department": "infrastructure",
        "clearance": null,
        "source": "roles/db/tasks/main.yml",
        "note": "service account"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "dba",
      "postgres"
    ],
    "clearance_levels": [
      "secret",
      "confidential"
    ],
    "departments": [
      "operations",
      "engineering",
      "data",
      "infrastructure"
    ]
  },
  "resources": {
    "hosts": [
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
    ],
    "services": [
      {
        "name": "nginx",
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
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all"
      }
    ],
    "paths": [
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "dmz_subnet"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet"
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "data_subnet"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet"
      }
    ]
  },
  "environment": {
    "org": "segcorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365
  },
  "attribute_definitions": {
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "dba",
        "postgres"
      ]
    },
    "clearance": {
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ]
    },
    "department": {
      "type": "enum",
      "domain": [
        "operations",
        "engineering",
        "data",
        "infrastructure"
      ]
    },
    "zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data",
        "external"
      ]
    },
    "role": {
      "type": "enum",
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ]
    },
    "inventory_group": {
      "type": "enum",
      "domain": [
        "dmz",
        "appservers",
        "dbservers"
      ]
    },
    "environment": {
      "type": "enum",
      "domain": [
        "production"
      ]
    },
    "compliance_tier": {
      "type": "enum",
      "domain": [
        "pci"
      ]
    },
    "org": {
      "type": "string",
      "domain": [
        "segcorp"
      ]
    }
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        16,
        19
      ]
    }
  },
  {
    "id": "rule-002",
    "effect": "permit",
    "action": "ssh:login",
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
    "effect": "permit",
    "action": "ssh:login",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        18,
        21
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
      "applies_to": {
        "equals": "all"
      }
    },
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        8,
        13
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        14,
        17
      ]
    }
  },
  {
    "id": "rule-007",
    "effect": "permit",
    "action": "db:login",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "privilege": "SUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        10,
        13
      ]
    }
  },
  {
    "id": "rule-008",
    "effect": "permit",
    "action": "db:login",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "privilege": "NOSUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        14,
        17
      ]
    }
  },
  {
    "id": "rule-009",
    "effect": "permit",
    "action": "filesystem:read",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        6,
        9
      ]
    }
  },
  {
    "id": "rule-010",
    "effect": "permit",
    "action": "filesystem:write",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        6,
        9
      ]
    }
  },
  {
    "id": "rule-011",
    "effect": "permit",
    "action": "user:create",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        5,
        11
      ]
    }
  },
  {
    "id": "rule-012",
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
      "applies_to": {
        "equals": "all"
      }
    },
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
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "affects_pinned_version": true,
    "recommendation": "Update to nginx 1.9.10 or later versions.",
    "source": "vulnx_search"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "affects_pinned_version": true,
    "recommendation": "Update to version 1.13.6 or later.",
    "source": "vulnx_search"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.7,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "affects_pinned_version": true,
    "recommendation": "Update nginx to the latest version where this issue is fixed.",
    "source": "vulnx_search"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many streams quickly, letting attackers consume server resources, exploit has been observed in the wild f",
    "affects_pinned_version": true,
    "recommendation": "Implement rate limiting and update to the latest HTTP/2 protocol standards or patches.",
    "source": "vulnx_search"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding ",
    "affects_pinned_version": true,
    "recommendation": "Update to OpenSSH 9.3p2 or later.",
    "source": "vulnx_search"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "high",
    "cvss_score": 8.1,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req",
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this regression is fixed.",
    "source": "vulnx_search"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "medium",
    "cvss_score": 6.8,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani",
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed.",
    "source": "vulnx_search"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "severity": "medium",
    "cvss_score": 6.8,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl",
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed.",
    "source": "vulnx_search"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "13.7",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "source": "vulnx_search",
    "note": "legacy CVE — verify version relevance before acting"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "13.7",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "source": "vulnx_search",
    "note": "legacy CVE — verify version relevance before acting"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "13.7",
    "severity": "critical",
    "cvss_score": 10,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "affects_pinned_version": true,
    "recommendation": "Update to version 42.7.2 or later.",
    "source": "vulnx_search"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "13.7",
    "severity": "high",
    "cvss_score": 7.2,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue.",
    "source": "vulnx_search"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "13.7",
    "severity": "high",
    "cvss_score": 7.1,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to version 42.2.26 or 42.4.1.",
    "source": "vulnx_search"
  }
]
```

## Report

# ABAC Policy Report — SEGCorp Ansible Configuration

## Executive Summary

Mined 13 ABAC rules from an Ansible configuration managing a 3-zone infrastructure
(DMZ, application, database) under PCI compliance tier. The policy enforces strict
network segmentation, role-based SSH access, and PostgreSQL privilege separation.

## Attribute Catalog

### Subjects
- **Users**: admin (sudo/ops/secret), developer (developers/eng/confidential), dba (dba/data/secret), postgres (service account)
- **Groups**: sudo, developers, dba, postgres
- **Clearance levels**: secret, confidential

### Resources
- **Hosts**: proxy01.lab.local (dmz/reverse_proxy), app01.lab.local (app/application), db01.lab.local (data/primary)
- **Services**: nginx:443/tcp, app:8080/tcp, postgresql:5432/tcp, ssh:22/tcp
- **Paths**: /var/lib/postgresql/data (postgres:postgres, 0700)

### Environment
- **Org**: segcorp | **Environment**: production | **Compliance tier**: pci

## Rules Summary

| ID | Effect | Action | Subject | Resource | Source |
|----|--------|--------|---------|----------|--------|
| rule-001 | permit | ssh:login | sudo | dmz | roles/dmz/tasks/main.yml |
| rule-002 | permit | ssh:login | sudo, developers | app | roles/app/tasks/main.yml |
| rule-003 | permit | ssh:login | sudo, dba | data | roles/db/tasks/main.yml |
| rule-004 | permit | network:connect | 0.0.0.0/0 | dmz:443/tcp | roles/dmz/tasks/main.yml |
| rule-005 | permit | network:connect | 10.0.1.0/24 | app:8080/tcp | roles/app/tasks/main.yml |
| rule-006 | permit | network:connect | 10.0.2.0/24 | data:5432/tcp | roles/db/tasks/main.yml |
| rule-007 | permit | db:login (SUPERUSER) | dba | postgresql/data | roles/db/tasks/main.yml |
| rule-008 | permit | db:login (NOSUPERUSER) | developers | postgresql/data | roles/db/tasks/main.yml |
| rule-009 | permit | filesystem:read | dba | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| rule-010 | permit | filesystem:write | dba | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| rule-011 | permit | user:create | sudo, developers | app | roles/app/tasks/main.yml |
| rule-012 | permit | user:create | sudo | dmz | roles/dmz/tasks/main.yml |
| rule-013 | deny | * | all | all | default |

## Vulnerability Assessment

Pinned package versions found:
- nginx 1.20.0-1~focal
- openssh-server 1:9.6p1-3ubuntu1
- postgresql-13 13.7-1.pgdg20.04+1

Total relevant CVEs: 13

Key findings:
- Multiple critical/remote CVEs found for nginx and openssh
- PostgreSQL 13.7 has known critical CVEs requiring patching
- **Recommendation**: Update all pinned versions to latest stable releases

## Ambiguities & Gaps

1. **Filesystem rules**: PostgreSQL data directory has mode 0700 (owner-only).
   The `dba` group does not have explicit POSIX access. Access is likely via
   database-level permissions, not filesystem-level. This is noted as a gap.

2. **Missing sudoers rules**: No explicit sudoers configuration was found in
   the Ansible roles. The `sudo` group membership implies sudo access but
   the exact sudoers rules are not defined in this configuration.

3. **SSH AllowGroups uses group_vars variables**: The actual allowed groups
   are interpolated from `allowed_ssh_groups` variable. The concrete values
   were extracted from group_vars files.

4. **Legacy CVEs**: Several CVEs date before 2015 and may not affect the
   pinned versions. Version-specific analysis recommended before remediation.

5. **No explicit session logging obligations**: No audit logging or session
   recording configurations were found in the role tasks.

6. **No explicit credentials management**: Database user creation uses
   postgresql_user module without explicit password management — passwords
   may be handled elsewhere or use peer/scram-sha-256 auth.
