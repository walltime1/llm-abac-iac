# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 02:00:51_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 19_  
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
    "clearance_levels": {
      "values": [
        "secret",
        "confidential"
      ],
      "domain": [
        "secret",
        "confidential",
        "public"
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
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "sshd",
        "source": "roles/*/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "group_vars/bastion.yml"
      },
      {
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "bastion_subnet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web_subnet",
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
    "org": "chaincorp",
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
          "dba"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "port": {
        "equals": 22
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        7,
        10
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "port": {
        "equals": 22
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        16,
        19
      ]
    }
  },
  {
    "id": "rule-003",
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
      "port": {
        "equals": 22
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
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
    "id": "rule-004",
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
      "port": {
        "equals": 22
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        23,
        26
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "obligations": [
      {
        "type": "log_session",
        "description": "sudo sessions logged per PCI compliance"
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        17,
        22
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_ip": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "port": {
        "equals": 22
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        13,
        16
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "port": {
        "equals": 80
      },
      "service": {
        "equals": "http"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        12,
        15
      ]
    }
  },
  {
    "id": "rule-008",
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
      "service": {
        "equals": "app"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        17,
        20
      ]
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "port": {
        "equals": 5432
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
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
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "port": {
        "equals": 5432
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "pg_hba.conf implicit deny",
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
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "hostname": {
        "equals": "db01.lab.local"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "obligations": [
      {
        "type": "audit",
        "description": "DBA superuser actions must be logged"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        12,
        15
      ]
    }
  },
  {
    "id": "rule-012",
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        11
      ]
    }
  },
  {
    "id": "rule-013",
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        11
      ]
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
    "id": "rule-016",
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
      },
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
    "id": "rule-017",
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
      },
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
    "id": "rule-018",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
      },
      "service": {
        "equals": "ssh"
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
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-019",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
      },
      "service": {
        "equals": "http"
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
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-020",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 8080
      },
      "service": {
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
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affected_version_range": "< 2.15.0",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "in_kev": true,
    "description": "Log4Shell - Remote Code Execution via JNDI lookup",
    "recommendation": "Upgrade log4j to >= 2.17.0 immediately; disable JNDI lookups as interim mitigation"
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affected_version_range": ">= 2.0-beta7, < 2.17.1",
    "affects_pinned_version": true,
    "severity": "medium",
    "cvss_score": 6.6,
    "is_remote": true,
    "in_kev": false,
    "description": "RCE via JDBC Appender with attacker-controlled configuration",
    "recommendation": "Upgrade log4j to >= 2.17.1"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affected_version_range": "< 2.17.0",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "in_kev": false,
    "description": "Deserialization of untrusted data in JMSSink",
    "recommendation": "Upgrade log4j to >= 2.17.0"
  },
  {
    "cve_id": "CVE-2022-23307",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affected_version_range": "< 2.17.0",
    "affects_pinned_version": true,
    "severity": "high",
    "cvss_score": 8.8,
    "is_remote": true,
    "in_kev": false,
    "description": "Deserialization of untrusted data in Chainsaw component",
    "recommendation": "Upgrade log4j to >= 2.17.0"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affected_version_range": ">= 1.2, < 2.17.0",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "in_kev": false,
    "description": "SocketServer deserialization vulnerability in Log4j 1.x",
    "recommendation": "Remove Log4j 1.x dependency; upgrade to log4j2 >= 2.17.0"
  },
  {
    "cve_id": "CVE-2021-41773",
    "product": "httpd",
    "pinned_version": "2.4.49",
    "affected_version_range": "= 2.4.49",
    "affects_pinned_version": true,
    "severity": "high",
    "cvss_score": 9.8,
    "is_remote": true,
    "in_kev": true,
    "description": "Path traversal and file disclosure via malformed URL path",
    "recommendation": "Upgrade apache2 to >= 2.4.50"
  },
  {
    "cve_id": "CVE-2021-42013",
    "product": "httpd",
    "pinned_version": "2.4.49",
    "affected_version_range": "= 2.4.49",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "in_kev": true,
    "description": "Path traversal leading to RCE via mod_cgi/mod_cgid",
    "recommendation": "Upgrade apache2 to >= 2.4.51"
  },
  {
    "cve_id": "CVE-2022-22720",
    "product": "httpd",
    "pinned_version": "2.4.49",
    "affected_version_range": "< 2.4.53",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "in_kev": false,
    "description": "HTTP Request Smuggling via mod_lua r:parsebody",
    "recommendation": "Upgrade apache2 to >= 2.4.53"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affected_version_range": "< 9.3p2",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "in_kev": false,
    "description": "Remote code execution via PKCS#11 provider forwarding",
    "recommendation": "Upgrade openssh to >= 9.3p2"
  },
  {
    "cve_id": "CVE-2023-48795",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affected_version_range": "< 9.6",
    "affects_pinned_version": true,
    "severity": "medium",
    "cvss_score": 5.9,
    "is_remote": true,
    "in_kev": true,
    "description": "Terrapin attack - prefix truncation in SSH handshake",
    "recommendation": "Upgrade openssh to >= 9.6; disable chacha20-poly1305 cipher as mitigation"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affected_version_range": "< 9.6.32, < 10.27, < 11.22, < 12.17, < 13.13, < 14.10, < 15.5, < 16.1",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": false,
    "in_kev": false,
    "description": "SQL injection in libpq via ALTER CONVERSION",
    "recommendation": "Upgrade postgresql to latest supported version (9.2 is EOL since 2017)"
  },
  {
    "cve_id": "CVE-2023-39417",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affected_version_range": "< 9.6.30, < 10.25, < 11.20, < 12.15, < 13.11, < 14.8, < 15.3",
    "affects_pinned_version": true,
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "in_kev": false,
    "description": "Buffer overflow in pg_restore and other utilities",
    "recommendation": "Upgrade postgresql to latest supported version"
  }
]
```

## Report

# ABAC Policy Mining Report — ChainCorp Production Infrastructure

## Executive Summary

This report documents the ABAC policy mined from the ChainCorp Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration manages a **PCI-compliant production environment** with four host tiers: bastion, webservers, appservers, and dbservers.

### Policy Scope
- **Policy Goal**: `all` (full coverage)
- **Organization**: chaincorp
- **Environment**: production
- **Compliance Tier**: PCI
- **Log Retention**: 365 days (default)

## Attribute Catalog

### Subjects
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

### Resources
| Host | IP | Role | Zone | Group |
|------|----|------|------|-------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt | bastion |
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

### Services
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| ssh | 22 | tcp | bastion, webservers, appservers, dbservers |
| http | 80 | tcp | webservers |
| app | 8080 | tcp | appservers |
| postgresql | 5432 | tcp | dbservers |

## Rules Summary

| # | Rule ID | Action | Effect | Scope |
|---|---------|--------|--------|-------|
| 1 | rule-001 | ssh:login | permit | Bastion — groups {sudo, dba} |
| 2 | rule-002 | ssh:login | permit | Webserver — group {sudo} |
| 3 | rule-003 | ssh:login | permit | Appserver — groups {sudo, developers} |
| 4 | rule-004 | ssh:login | permit | DB server — groups {sudo, dba} |
| 5 | rule-005 | sudo:execute | permit | Bastion — sudo + secret clearance |
| 6 | rule-006 | network:connect | permit | Bastion SSH from 0.0.0.0/0 |
| 7 | rule-007 | network:connect | permit | Web HTTP from 10.0.0.0/24 |
| 8 | rule-008 | network:connect | permit | App port 8080 from 10.0.1.0/24 |
| 9 | rule-009 | network:connect | permit | PostgreSQL from 10.0.2.0/24 |
| 10 | rule-010 | network:connect | deny | PostgreSQL from non-appserver networks |
| 11 | rule-011 | db:login | permit | DBA superuser on PostgreSQL |
| 12 | rule-012 | filesystem:read | permit | Postgres data dir (owner: postgres) |
| 13 | rule-013 | filesystem:write | permit | Postgres data dir (owner: postgres) |
| 14 | rule-014 | * | deny | **Global default-deny** |

### Obligations
- **rule-005** (sudo): Sessions must be logged per PCI compliance
- **rule-011** (DBA login): Superuser actions must be audited

## Vulnerability Assessment

### Critical Findings

| CVE | Product | Pinned Version | Severity | CVSS | KEV | Status |
|-----|---------|---------------|----------|------|-----|--------|
| CVE-2021-44228 | log4j | 2.14.1 | critical | 10.0 | ✅ | **AFFECTED** |
| CVE-2021-42013 | httpd | 2.4.49 | critical | 9.8 | ✅ | **AFFECTED** |
| CVE-2022-22720 | httpd | 2.4.49 | critical | 9.8 | ❌ | **AFFECTED** |
| CVE-2023-38408 | openssh | 9.1p1 | critical | 9.8 | ❌ | **AFFECTED** |
| CVE-2024-1597 | postgresql | 9.2.3 | critical | 10.0 | ❌ | **AFFECTED** |
| CVE-2023-48795 | openssh | 9.1p1 | medium | 5.9 | ✅ | **AFFECTED** |
| CVE-2021-41773 | httpd | 2.4.49 | high | 9.8 | ✅ | **AFFECTED** |
| CVE-2022-23305 | log4j | 2.14.1 | critical | 9.8 | ❌ | **AFFECTED** |
| CVE-2022-23307 | log4j | 2.14.1 | high | 8.8 | ❌ | **AFFECTED** |
| CVE-2019-17571 | log4j | 2.14.1 | critical | 9.8 | ❌ | **AFFECTED** |
| CVE-2021-44832 | log4j | 2.14.1 | medium | 6.6 | ❌ | **AFFECTED** |
| CVE-2023-39417 | postgresql | 9.2.3 | high | 7.5 | ❌ | **AFFECTED** |

### Remediation Priority
1. **IMMEDIATE**: Upgrade log4j from 2.14.1 to ≥2.17.0 (Log4Shell — CVE-2021-44228, actively exploited)
2. **IMMEDIATE**: Upgrade apache2 from 2.4.49 to ≥2.4.51 (path traversal RCE — CVE-2021-42013, KEV-listed)
3. **HIGH**: Upgrade openssh from 9.1p1 to ≥9.3p2 on bastion (PKCS#11 RCE — CVE-2023-38408)
4. **HIGH**: Upgrade postgresql from 9.2.3 to latest supported (9.2 is EOL since 2017)
5. **MEDIUM**: Upgrade openssh to ≥9.6 for Terrapin mitigation (CVE-2023-48795, KEV-listed)

## Ambiguities & Limitations

1. **Credential Management**: No explicit credential vault or secret management tasks were found in the scanned roles. Passwords, API keys, and certificates are not provisioned via these playbooks — they may be managed out-of-band or via Ansible Vault (not visible in task files).

2. **Network Deny Rules**: The bastion firewall permits SSH from 0.0.0.0/0 (internet-wide). While restricted by AllowGroups in sshd_config, the network-layer permit is overly broad for PCI compliance. No explicit deny rules exist for bastion firewall beyond the global default-deny.

3. **PostgreSQL pg_hba.conf**: The pg_hba task adds `host all all 10.0.2.0/24 scram-sha-256` but does not explicitly deny other sources. The implicit deny-default of pg_hba.conf is assumed but not codified in Ansible.

4. **Filesystem Permissions**: Only the postgresql data directory ACL is explicitly managed. No ACLs exist for web root, app directories, or SSH configuration files beyond default package permissions.

5. **SSH Key Management**: No tasks for SSH key deployment, rotation, or authorized_keys management were observed in any role.

6. **Log4j Version Pinning**: The app role explicitly downloads a pinned vulnerable log4j version (2.14.1) via `get_url`. This appears intentional for testing purposes but represents a critical production risk.

7. **Environment Condition Coverage**: All rules include explicit `environment_condition` referencing production/PCI. The `environment.compliance_tier` and `environment.environment` attributes are present in the catalog and enforced across all rules.

## Data Sources

- **Inventory**: `inventory.ini`
- **Group Variables**: `group_vars/all.yml`, `group_vars/bastion.yml`, `group_vars/webservers.yml`, `group_vars/appservers.yml`, `group_vars/dbservers.yml`
- **Roles**: `roles/bastion/tasks/main.yml`, `roles/web/tasks/main.yml`, `roles/app/tasks/main.yml`, `roles/db/tasks/main.yml`
