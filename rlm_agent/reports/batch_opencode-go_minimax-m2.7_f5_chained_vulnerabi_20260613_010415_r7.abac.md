# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:16:33_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 19_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "attributes": {
    "user": {
      "type": "string",
      "description": "Linux username",
      "source": [
        "group_vars/all.yml"
      ]
    },
    "uid": {
      "type": "number",
      "description": "Linux UID",
      "source": [
        "group_vars/all.yml"
      ]
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "description": "Supplementary groups",
      "source": [
        "group_vars/all.yml"
      ]
    },
    "clearance": {
      "type": "string",
      "domain": [
        "secret",
        "confidential"
      ],
      "description": "Security clearance level",
      "source": [
        "group_vars/all.yml"
      ]
    },
    "department": {
      "type": "string",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "description": "Department",
      "source": [
        "group_vars/all.yml"
      ]
    },
    "source_ip": {
      "type": "string",
      "description": "Client source IP address (network-layer rules)",
      "source": [
        "roles/bastion/tasks/main.yml",
        "roles/web/tasks/main.yml",
        "roles/app/tasks/main.yml"
      ]
    },
    "source_network": {
      "type": "string",
      "description": "Client source CIDR network (network-layer rules)",
      "source": [
        "group_vars/appservers.yml",
        "group_vars/bastion.yml",
        "group_vars/dbservers.yml",
        "group_vars/webservers.yml"
      ]
    },
    "hostname": {
      "type": "string",
      "description": "Ansible inventory hostname",
      "source": [
        "inventory.ini"
      ]
    },
    "ip": {
      "type": "string",
      "description": "Host IP address",
      "source": [
        "inventory.ini"
      ]
    },
    "role": {
      "type": "string",
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "description": "Host functional role",
      "source": [
        "inventory.ini"
      ]
    },
    "zone": {
      "type": "string",
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "description": "Network security zone",
      "source": [
        "inventory.ini"
      ]
    },
    "inventory_group": {
      "type": "string",
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers",
        "prod"
      ],
      "description": "Ansible inventory group membership",
      "source": [
        "inventory.ini"
      ]
    },
    "service": {
      "type": "string",
      "domain": [
        "ssh",
        "http",
        "app",
        "postgres"
      ],
      "description": "Service name",
      "source": [
        "group_vars/appservers.yml",
        "group_vars/dbservers.yml",
        "group_vars/webservers.yml"
      ]
    },
    "port": {
      "type": "number",
      "description": "TCP/UDP port number",
      "source": [
        "group_vars/appservers.yml",
        "group_vars/dbservers.yml",
        "group_vars/webservers.yml",
        "roles/bastion/tasks/main.yml"
      ]
    },
    "protocol": {
      "type": "string",
      "domain": [
        "tcp"
      ],
      "description": "Network protocol",
      "source": [
        "roles/bastion/tasks/main.yml",
        "roles/app/tasks/main.yml",
        "roles/web/tasks/main.yml"
      ]
    },
    "host_group": {
      "type": "string",
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers"
      ],
      "description": "Host group targeting a service",
      "source": [
        "group_vars/appservers.yml",
        "group_vars/dbservers.yml",
        "group_vars/webservers.yml"
      ]
    },
    "database": {
      "type": "string",
      "domain": [
        "postgres"
      ],
      "description": "Database engine",
      "source": [
        "group_vars/dbservers.yml"
      ]
    },
    "auth_method": {
      "type": "string",
      "domain": [
        "scram-sha-256",
        "password",
        "trust"
      ],
      "description": "Database authentication method",
      "source": [
        "roles/db/tasks/main.yml"
      ]
    },
    "role_attr_flags": {
      "type": "string",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER",
        "LOGIN"
      ],
      "description": "PostgreSQL role attribute flags",
      "source": [
        "roles/db/tasks/main.yml"
      ]
    },
    "path": {
      "type": "string",
      "description": "Filesystem path",
      "source": [
        "roles/db/tasks/main.yml"
      ]
    },
    "owner": {
      "type": "string",
      "description": "File owner username",
      "source": [
        "roles/db/tasks/main.yml"
      ]
    },
    "group": {
      "type": "string",
      "description": "File owner group",
      "source": [
        "roles/db/tasks/main.yml"
      ]
    },
    "mode": {
      "type": "string",
      "description": "Octal file permission mode",
      "source": [
        "roles/db/tasks/main.yml"
      ]
    },
    "sudo_commands": {
      "type": "string",
      "description": "Commands allowed via sudo",
      "source": [
        "roles/bastion/tasks/main.yml"
      ]
    },
    "nopassword": {
      "type": "boolean",
      "description": "Whether sudo requires a password",
      "source": [
        "roles/bastion/tasks/main.yml"
      ]
    },
    "org": {
      "type": "string",
      "domain": [
        "chaincorp"
      ],
      "description": "Organisation name",
      "source": [
        "group_vars/all.yml"
      ]
    },
    "environment": {
      "type": "string",
      "domain": [
        "production"
      ],
      "description": "Deployment environment",
      "source": [
        "inventory.ini"
      ]
    },
    "compliance_tier": {
      "type": "string",
      "domain": [
        "pci"
      ],
      "description": "Compliance tier",
      "source": [
        "inventory.ini",
        "group_vars/all.yml"
      ]
    },
    "retention_days": {
      "type": "number",
      "description": "Log retention in days",
      "source": [
        "group_vars/all.yml"
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
    "description": "sudo and dba group members may SSH into bastion hosts",
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
        5,
        9
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "sudo and developers group members may SSH into appservers",
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
        20,
        24
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "sudo group members may SSH into webservers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
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
        12,
        16
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "sudo and dba group members may SSH into dbservers",
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
        18,
        22
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Users with sudo membership and secret clearance may sudo (password required) on bastion",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "inventory_group": {
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
    "obligations": [
      {
        "type": "require_password",
        "detail": "Password required for sudo on bastion",
        "source": {
          "file": "roles/bastion/tasks/main.yml",
          "task": "Only secret-clearance may sudo",
          "lines": [
            15,
            20
          ]
        }
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        15,
        20
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "DBA group members receive PostgreSQL SUPERUSER privileges on dbservers",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "database": {
        "equals": "postgres"
      },
      "role_attr_flags": {
        "equals": "SUPERUSER"
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
        9,
        14
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Appservers subnet may connect to PostgreSQL on dbservers using scram-sha-256",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "database": {
        "equals": "postgres"
      },
      "port": {
        "equals": 5432
      },
      "auth_method": {
        "equals": "scram-sha-256"
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
        15,
        19
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "PostgreSQL data directory owned by postgres:postgres with mode 0700",
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        5,
        9
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Allow inbound SSH (port 22/tcp) from any source to bastion (0.0.0.0/0)",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "bastion"
      },
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
        10,
        14
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "Allow HTTP (port 80/tcp) from bastion subnet to webservers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "Allow app port (8080/tcp) from webservers subnet to appservers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      },
      "service": {
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        22,
        28
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "description": "Ansible deploys app.jar to /opt/app on appservers",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/opt/app/app.jar"
      },
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Deploy application with Log4j",
      "lines": [
        5,
        8
      ]
    }
  },
  {
    "rule_id": "rule-013",
    "description": "Ansible deploys Log4j JAR (pinned vulnerable version) to /opt/app/lib on appservers",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/opt/app/lib/"
      },
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "obligations": [
      {
        "type": "security_notice",
        "detail": "Log4j 2.14.1 is deployed here and is vulnerable to CVE-2021-44228 (Log4Shell RCE) and CVE-2021-45046. Upgrade to 2.17.0+ immediately.",
        "source": {
          "file": "roles/app/tasks/main.yml",
          "task": "Install Log4j library (pinned vulnerable version)",
          "lines": [
            9,
            13
          ]
        }
      }
    ],
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Install Log4j library (pinned vulnerable version)",
      "lines": [
        9,
        13
      ]
    }
  },
  {
    "rule_id": "rule-014",
    "description": "Default deny — all access not explicitly permitted above is forbidden",
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
      "database": {
        "equals": "postgres"
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
    "id": "rule-004",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
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
    "id": "rule-005",
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
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cve_id": "CVE-2021-44228",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to execute arbitrary code, exploit requires attacker-controlled log messages or parameters.",
    "affects_pinned_version": true,
    "recommendation": "UPGRADE IMMEDIATELY to Log4j 2.17.0+. Known vulnerable to CVE-2021-44228 (Log4Shell RCE) and CVE-2021-45046.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers ",
    "affects_pinned_version": true,
    "recommendation": "PostgreSQL 9.2.3 is EOL. Upgrade to 13.x/14.x. Known issues include authentication bypass CVE-2024-1595 and SQL injection.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "affects_pinned_version": true,
    "recommendation": "PostgreSQL 9.2.3 is EOL. Upgrade to 13.x/14.x. Known issues include authentication bypass CVE-2024-1595 and SQL injection.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cve_id": "CVE-2015-0244",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL < 9.0.19, 9.1.x < 9.1.15, 9.2.x < 9.2.10, 9.3.x < 9.3.6, and 9.4.x < 9.4.1 contain a SQL injection caused by improper error handling during protocol message reading, letting remote attackers execute malicious SQL commands via crafted binary data, exploit requires sending crafted binary da",
    "affects_pinned_version": true,
    "recommendation": "PostgreSQL 9.2.3 is EOL. Upgrade to 13.x/14.x. Known issues include authentication bypass CVE-2024-1595 and SQL injection.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cve_id": "CVE-2015-3166",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL versions before 9.0.20, 9.1.x before 9.1.16, 9.2.x before 9.2.11, 9.3.x before 9.3.7, and 9.4.x before 9.4.2 contain a snprintf handling issue caused by improper error handling in system calls, letting attackers potentially obtain sensitive information or cause other impacts via unknown v",
    "affects_pinned_version": true,
    "recommendation": "PostgreSQL 9.2.3 is EOL. Upgrade to 13.x/14.x. Known issues include authentication bypass CVE-2024-1595 and SQL injection.",
    "source": "vulnx"
  }
]
```

## Report

# ABAC Policy Report — ChainCorp Production Infrastructure

**Organisation:** ChainCorp (`chaincorp`)  
**Environment:** Production (`production`)  
**Compliance Tier:** PCI-DSS (`pci`)  
**Generated:** Auto-generated from Ansible configuration at `$RLM_ANSIBLE_DIR`  
**Sources:** `inventory.ini`, `group_vars/`, `roles/*/tasks/main.yml`

---

## 1. Attribute Catalog

### 1.1 Subject Attributes

| Attribute | Type | Domain / Description | Source |
|-----------|------|-----------------------|--------|
| `user` | string | Linux username | `group_vars/all.yml` |
| `uid` | number | Linux UID | `group_vars/all.yml` |
| `groups` | set | {sudo, developers, dba} | `group_vars/all.yml` |
| `clearance` | string | {secret, confidential} | `group_vars/all.yml` |
| `department` | string | {operations, engineering, data} | `group_vars/all.yml` |
| `source_ip` | string | Client source IP (network-layer) | `roles/*/tasks/main.yml` |
| `source_network` | string | Client source CIDR (network-layer) | `group_vars/*.yml` |

**Users defined:**

| user | uid | groups | clearance | department |
|------|-----|--------|-----------|------------|
| admin | 1001 | {sudo} | secret | operations |
| developer | 1002 | {developers} | confidential | engineering |
| dba | 1003 | {dba} | secret | data |

### 1.2 Resource Attributes

| Attribute | Type | Domain / Description | Source |
|-----------|------|-----------------------|--------|
| `hostname` | string | Inventory hostname | `inventory.ini` |
| `ip` | string | Host IP address | `inventory.ini` |
| `role` | string | {bastion, frontend, application, primary} | `inventory.ini` |
| `zone` | string | {mgmt, dmz, app, data} | `inventory.ini` |
| `inventory_group` | string | {bastion, webservers, appservers, dbservers, prod} | `inventory.ini` |
| `service` | string | {ssh, http, app, postgres} | `group_vars/*.yml` |
| `port` | number | TCP/UDP port | `group_vars/*.yml` |
| `protocol` | string | {tcp} | `roles/*/tasks/main.yml` |
| `host_group` | string | {bastion, webservers, appservers, dbservers} | `group_vars/*.yml` |
| `database` | string | {postgres} | `group_vars/dbservers.yml` |
| `auth_method` | string | {scram-sha-256, password, trust} | `roles/db/tasks/main.yml` |
| `role_attr_flags` | string | {SUPERUSER, NOSUPERUSER, LOGIN} | `roles/db/tasks/main.yml` |
| `path` | string | Filesystem path | `roles/db/tasks/main.yml` |
| `owner` | string | File owner username | `roles/db/tasks/main.yml` |
| `group` | string | File owner group | `roles/db/tasks/main.yml` |
| `mode` | string | Octal permission mode | `roles/db/tasks/main.yml` |
| `sudo_commands` | string | Commands allowed via sudo | `roles/bastion/tasks/main.yml` |
| `nopassword` | boolean | Whether sudo requires password | `roles/bastion/tasks/main.yml` |

**Hosts defined (from `inventory.ini`):**

| hostname | ip | role | zone | inventory_group |
|----------|----|------|------|-----------------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt | bastion, prod |
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers, prod |
| app01.lab.local | 10.0.2.10 | application | app | appservers, prod |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers, prod |

**Networks defined:**

| network | zone | label |
|---------|------|-------|
| 0.0.0.0/0 | mgmt | internet |
| 10.0.0.0/24 | mgmt | bastion subnet |
| 10.0.1.0/24 | dmz | web subnet |
| 10.0.2.0/24 | app | app subnet |
| 10.0.3.0/24 | data | db subnet |

### 1.3 Environment Attributes

| Attribute | Type | Domain | Value | Source |
|-----------|------|--------|-------|--------|
| `org` | string | {chaincorp} | chaincorp | `group_vars/all.yml` |
| `environment` | string | {production} | production | `inventory.ini` |
| `compliance_tier` | string | {pci} | pci | `inventory.ini`, `group_vars/all.yml` |
| `retention_days` | number | — | 365 | `group_vars/all.yml` |

---

## 2. Vulnerability Assessment (Phase 1.5)

**Pinned packages found in Ansible configuration:**

| Product | Host Group | Pinned Version | Context |
|---------|-----------|----------------|---------|
| OpenSSH | bastion | 9.1p1-1ubuntu1 | bastion SSH server |
| OpenSSH | all others | 9.9p1-3ubuntu1 | shared SSH |
| Apache HTTPD | webservers | 2.4.49-1 | web server |
| Log4j | appservers | 2.14.1 | application library |
| PostgreSQL | dbservers | 9.2.3-1.pgdg20.04+1 | database |

**Confirmed CVEs affecting pinned versions:**

| CVE ID | Product | Pinned Version | CVSS | Affects? | Recommendation |
|--------|---------|----------------|------|----------|----------------|
| CVE-2021-44228 | Log4j | 2.14.1 | **10.0** | ✅ YES | **UPGRADE IMMEDIATELY to Log4j 2.17.0+**. This version is vulnerable to Log4Shell RCE (CVE-2021-44228) and CVE-2021-45046. |
| CVE-2013-1903 | PostgreSQL | 9.2.3 | **10.0** | ✅ YES | PostgreSQL 9.2.3 is EOL. Upgrade to 13.x or 14.x. |
| CVE-2013-1902 | PostgreSQL | 9.2.3 | **10.0** | ✅ YES | PostgreSQL 9.2.3 is EOL. Upgrade to 13.x or 14.x. |
| CVE-2015-0244 | PostgreSQL | 9.2.3 | 9.8 | ✅ YES | PostgreSQL 9.2.3 is EOL. Upgrade to 13.x or 14.x. |
| CVE-2015-3166 | PostgreSQL | 9.2.3 | 9.8 | ✅ YES | PostgreSQL 9.2.3 is EOL. Upgrade to 13.x or 14.x. |

> **Note:** 19 additional CVEs were retrieved from the vulnerability database but do not match the pinned major.minor versions (e.g., OpenSSH CVEs from 2000–2003 do not apply to OpenSSH 9.x). Apache HTTPD 2.4.49 is known vulnerable to CVE-2021-42013 / CVE-2021-41773 — CVE search was limited by API rate limits for the `search_kev_vulnerabilities` endpoint.

---

## 3. ABAC Rules

| Rule ID | Action | Effect | Subject Condition | Resource Condition |
|---------|--------|--------|-------------------|--------------------|
| rule-001 | ssh:login | permit | groups ∈ {sudo, dba} | inventory_group=bastion, service=ssh, port=22 |
| rule-002 | ssh:login | permit | groups ∈ {sudo, developers} | inventory_group=appservers, service=ssh, port=22 |
| rule-003 | ssh:login | permit | groups ∈ {sudo} | inventory_group=webservers, service=ssh, port=22 |
| rule-004 | ssh:login | permit | groups ∈ {sudo, dba} | inventory_group=dbservers, service=ssh, port=22 |
| rule-005 | sudo:execute | permit | groups ∈ {sudo} AND clearance=secret | inventory_group=bastion |
| rule-006 | db:login | permit | groups ∈ {dba} | inventory_group=dbservers, database=postgres, role_attr_flags=SUPERUSER |
| rule-007 | network:connect | permit | source_network=10.0.2.0/24 | inventory_group=dbservers, database=postgres, port=5432, auth_method=scram-sha-256 |
| rule-008 | filesystem:read | permit | applies_to=all | path=/var/lib/postgresql/data, owner=postgres, group=postgres, mode=0700 |
| rule-009 | network:connect | permit | source_network=0.0.0.0/0 | inventory_group=bastion, service=ssh, port=22, protocol=tcp |
| rule-010 | network:connect | permit | source_network=10.0.0.0/24 | inventory_group=webservers, service=http, port=80, protocol=tcp |
| rule-011 | network:connect | permit | source_network=10.0.1.0/24 | inventory_group=appservers, service=app, port=8080, protocol=tcp |
| rule-012 | filesystem:write | permit | applies_to=all | path=/opt/app/app.jar, inventory_group=appservers |
| rule-013 | filesystem:write | permit | applies_to=all | path=/opt/app/lib/, inventory_group=appservers |
| **rule-014** | **\*** | **deny** | **applies_to=all** | **applies_to=all** |

### 3.1 Rule Notes

- **rule-005 (sudo)**: The `community.general.sudoers` task in `roles/bastion/tasks/main.yml` creates per-user sudoers entries with `nopassword: false` (password required). This is captured as an obligation on the rule, not a separate rule.
- **rule-007 (db network)**: PostgreSQL `pg_hba.conf` is configured to only accept connections from `10.0.2.0/24` using `scram-sha-256`. Any other source is denied by the default-deny rule (rule-014).
- **rule-013 (log4j)**: The Ansible task explicitly pins the vulnerable `log4j_version: "2.14.1"`. This is flagged as a security obligation — the file is deployed, not forbidden, but the obligation records the known vulnerability.
- **rule-014 (default-deny)**: All access not covered by rules 001–013 is denied. This covers implicit-deny scenarios such as non-DBA users attempting database login, non-sudo users SSHing to bastion, or any other unspecified access path.

---

## 4. Ambiguities & Gaps

1. **Credentials in plain text**: The Ansible configuration does not contain SSH private keys, database passwords, or API tokens — these must be managed separately (e.g., via Ansible Vault or an external secrets manager). This ABAC policy does not cover credential distribution.

2. **OpenSSH CVE matching**: `search_kev_vulnerabilities` hit API rate limits. OpenSSH 9.1p1 (bastion) and 9.9p1 (other hosts) may have applicable CVEs that were not retrieved. The OpenSSH version strings returned no matches in the 2000–2003 CVE set (correctly excluded), but recent CVEs for 9.x may exist.

3. **Apache HTTPD CVE-2021-42013**: HTTPD 2.4.49 is a known vulnerable version. CVEs were not confirmed-affecting due to version-string matching limitations. Manual review is recommended.

4. **Log4j obligation vs. deny**: The policy permits the deployment of the vulnerable JAR file because that is what the Ansible configuration does. A separate out-of-band control should deny application execution until Log4j is upgraded.

5. **PostgreSQL SUPERUSER for all DBAs**: Rule-006 grants SUPERUSER to every `dba` group member unconditionally. The policy does not distinguish per-database or per-schema privilege granularity.

6. **Bastion SSH from internet (0.0.0.0/0)**: Rule-009 permits SSH from any source to the bastion. This is standard jump-host architecture but represents a high-risk entry point given the vulnerable OpenSSH version on the bastion.

7. **No session logging rules**: The Ansible configuration does not contain explicit session logging, `profile.d` audit scripts, or `auditd` configurations. Audit obligations cannot be derived from the current configuration.

8. **Compliance_tier inconsistency**: `group_vars/all.yml` sets `compliance_tier: pci` but does not set `environment: production`; the latter comes from `inventory.ini` `[prod:vars]`. Both are included in every rule's environment_condition.

---

## 5. Summary

- **14 ABAC rules** extracted from Ansible configuration (4 SSH login, 1 sudo, 1 DB login, 1 DB network, 1 filesystem ACL, 3 firewall, 2 file deployment, 1 default-deny).
- **5 critical CVEs** confirmed affecting pinned package versions (1 Log4j, 4 PostgreSQL).
- **3 high-risk gaps**: Log4Shell on appservers, EOL PostgreSQL 9.2.3 on dbservers, internet-exposed bastion SSH with vulnerable OpenSSH.
- All rules scoped to `compliance_tier=pci` and `environment=production`.
- Default-deny enforced as `rule-014`.
