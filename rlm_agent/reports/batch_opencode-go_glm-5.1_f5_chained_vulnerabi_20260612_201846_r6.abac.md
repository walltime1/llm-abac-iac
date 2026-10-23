# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 21:08:15_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 20 | Rules: 21_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "type": "enum",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "domain": [
        1001,
        1002,
        1003
      ],
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
    "source_ip": {
      "type": "string",
      "source": "roles/bastion/tasks/main.yml"
    },
    "source_network": {
      "type": "cidr",
      "source": "roles/app/tasks/main.yml"
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data",
        "internet"
      ],
      "source": "inventory.ini"
    }
  },
  "resources": {
    "hostname": {
      "type": "enum",
      "domain": [
        "bastion01.lab.local",
        "web01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "domain": [
        "10.0.0.5",
        "10.0.1.10",
        "10.0.2.10",
        "10.0.3.10"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "type": "enum",
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "enum",
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
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
      "domain": [
        22,
        80,
        8080,
        5432
      ],
      "source": "group_vars/*.yml"
    },
    "path": {
      "type": "string",
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "enum",
      "domain": [
        "chaincorp"
      ],
      "source": "group_vars/all.yml"
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
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "integer",
      "domain": [
        365
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
    "description": "Allow SSH login to bastion hosts for sudo and dba groups",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "8-12"
    }
  },
  {
    "id": "rule-002",
    "description": "Allow SSH login to app servers for sudo and developers groups",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "22-25"
    }
  },
  {
    "id": "rule-003",
    "description": "Allow SSH login to web servers for sudo group only",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "16-19"
    }
  },
  {
    "id": "rule-004",
    "description": "Allow SSH login to db servers for sudo and dba groups",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "18-21"
    }
  },
  {
    "id": "rule-005",
    "description": "Allow sudo on bastion for users with secret clearance in sudo group (password required)",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "nopassword": false
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "22-29"
    }
  },
  {
    "id": "rule-006",
    "description": "Allow SSH from internet to bastion (firewalld)",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall - allow SSH from internet",
      "lines": "14-20"
    }
  },
  {
    "id": "rule-007",
    "description": "Allow app port from web subnet to app servers (firewalld)",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall - allow app port from web subnet",
      "lines": "16-21"
    }
  },
  {
    "id": "rule-008",
    "description": "Allow HTTP from bastion/mgmt subnet to web servers (firewalld)",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall - allow HTTP from bastion subnet",
      "lines": "10-15"
    }
  },
  {
    "id": "rule-009",
    "description": "Allow DBA group members SUPERUSER+LOGIN role on PostgreSQL",
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
      "port": {
        "equals": 5432
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
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "10-13"
    }
  },
  {
    "id": "rule-010",
    "description": "Allow PostgreSQL connections from app subnet (pg_hba)",
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
      },
      "database": {
        "equals": "all"
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "15-17"
    }
  },
  {
    "id": "rule-011",
    "description": "Deny PostgreSQL connections from non-app-subnet sources (pg_hba implicit deny)",
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
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "15-17"
    }
  },
  {
    "id": "rule-012",
    "description": "Allow DBA group read access to postgres data directory (mode 0700)",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
    }
  },
  {
    "id": "rule-013",
    "description": "Allow DBA group write access to postgres data directory (mode 0700)",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
    }
  },
  {
    "id": "rule-014",
    "description": "Allow DBA group execute access to postgres data directory (mode 0700)",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
    }
  },
  {
    "id": "rule-015",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "implicit",
      "task": "default-deny",
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
    "id": "rule-019",
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
    "id": "rule-021",
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
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "description": "Log4Shell: Remote code execution via JNDI lookup injection in Log4j 2.0-beta9 through 2.14.1",
    "recommendation": "Upgrade Log4j to 2.17.1 or later immediately. This is a CISA KEV entry with known ransomware use.",
    "source": "roles/app/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Log4j 1.2 contains insecure deserialization in SocketServer class allowing remote code execution",
    "recommendation": "Upgrade Log4j to 2.17.1+ and remove Log4j 1.x dependencies from classpath.",
    "source": "roles/app/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Log4j 1.2.x JDBCAppender SQL injection via pattern converters in log messages",
    "recommendation": "Upgrade Log4j to 2.17.1+ and migrate away from JDBCAppender.",
    "source": "roles/app/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Apache Log4j socket receiver deserialization vulnerability allowing remote code execution",
    "recommendation": "Upgrade Log4j to 2.17.1+ and disable socket receiver if not needed.",
    "source": "roles/app/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3-1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "PostgreSQL aggregate function privilege escalation allowing remote code execution",
    "recommendation": "Upgrade PostgreSQL to a supported version (16.x+). Version 9.2 is EOL and receives no security patches.",
    "source": "roles/db/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "9.2.3-1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "PostgreSQL buffer overflow vulnerabilities in multiple functions",
    "recommendation": "Upgrade PostgreSQL to a supported version (16.x+). Version 9.2 is EOL.",
    "source": "roles/db/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2013-1777",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Apache httpd mod_dav buffer underflow allowing remote code execution",
    "recommendation": "Upgrade Apache httpd to 2.4.58+ immediately. Version 2.4.49 has path traversal and other critical flaws.",
    "source": "roles/web/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2009-2412",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Apache httpd mod_proxy buffer overflow allowing remote code execution",
    "recommendation": "Upgrade Apache httpd to 2.4.58+. Version 2.4.49 is critically vulnerable.",
    "source": "roles/web/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.1p1-1ubuntu1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "description": "OpenSSH buffer overflow in buffer_append_space allowing remote code execution",
    "recommendation": "Already running 9.1p1+ which is not affected. Keep patched.",
    "source": "roles/bastion/tasks/main.yml"
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "pinned_version": "9.1p1-1ubuntu1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "description": "OpenSSH remote shell access vulnerability in challenge-response authentication",
    "recommendation": "Already running 9.1p1+ which is not affected. Keep patched.",
    "source": "roles/bastion/tasks/main.yml"
  }
]
```

## Report

# ABAC Policy Mining Report — Chaincorp Ansible Infrastructure

## Executive Summary

This report presents an Attribute-Based Access Control (ABAC) policy mined from the Chaincorp Ansible configuration. The infrastructure comprises four host groups (bastion, webservers, appservers, dbservers) in a PCI-compliant production environment. **Critical vulnerabilities** were identified in all pinned software packages, most notably Log4Shell (CVE-2021-44228) in the application tier and an EOL PostgreSQL version in the data tier.

## Infrastructure Overview

| Host Group | Hostname | IP | Role | Zone |
|---|---|---|---|---|
| bastion | bastion01.lab.local | 10.0.0.5 | bastion | mgmt |
| webservers | web01.lab.local | 10.0.1.10 | frontend | dmz |
| appservers | app01.lab.local | 10.0.2.10 | application | app |
| dbservers | db01.lab.local | 10.0.3.10 | primary | data |

**Environment:** production | **Compliance Tier:** PCI | **Org:** chaincorp

## Users

| User | UID | Groups | Department | Clearance |
|---|---|---|---|---|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

## Extracted ABAC Rules Summary

### SSH Access (4 rules)
- **Bastion:** sudo + dba groups may SSH
- **App servers:** sudo + developers groups may SSH
- **Web servers:** sudo group only may SSH
- **DB servers:** sudo + dba groups may SSH

### Sudo (1 rule)
- **Bastion:** Users with secret clearance AND in sudo group may execute sudo (password required)

### Network/Firewall (3 permit rules + 1 deny)
- **Bastion:** SSH (port 22) open from 0.0.0.0/0 (internet-facing)
- **App servers:** Port 8080 open from web subnet (10.0.1.0/24)
- **Web servers:** HTTP (port 80) open from mgmt subnet (10.0.0.0/24)
- **DB servers:** PostgreSQL denied from non-app-subnet sources (implicit pg_hba deny)

### Database Access (1 rule)
- **DB servers:** DBA group members granted SUPERUSER+LOGIN role on PostgreSQL

### Filesystem (3 rules)
- **DB servers:** DBA group has read/write/execute on /var/lib/postgresql/data (mode 0700, owner postgres)

### Default Deny (1 rule)
- All access not explicitly permitted is denied

## Critical Vulnerabilities

### Log4j (Application Tier) — **CRITICAL**
| CVE | CVSS | Affects Pinned Version | KEV |
|---|---|---|---|
| CVE-2021-44228 (Log4Shell) | 10.0 | Yes | Yes (ransomware) |
| CVE-2019-17571 | 9.8 | Yes | No |
| CVE-2022-23305 | 9.8 | Yes | No |
| CVE-2017-5645 | 9.8 | Yes | No |

**Recommendation:** Upgrade Log4j to 2.17.1+ immediately. Log4Shell is actively exploited with known ransomware use.

### PostgreSQL (Data Tier) — **CRITICAL**
| CVE | CVSS | Affects Pinned Version | KEV |
|---|---|---|---|
| CVE-2024-1597 | 10.0 | Yes | No |
| CVE-2002-1399 | 10.0 | Yes | No |

**Recommendation:** PostgreSQL 9.2 is EOL. Upgrade to 16.x+ immediately.

### Apache httpd (Web Tier) — **CRITICAL**
| CVE | CVSS | Affects Pinned Version | KEV |
|---|---|---|---|
| CVE-2013-1777 | 10.0 | Yes | No |
| CVE-2009-2412 | 10.0 | Yes | No |

**Recommendation:** Apache 2.4.49 has path traversal (CVE-2021-41773) and other critical flaws. Upgrade to 2.4.58+.

### OpenSSH (Bastion) — Low Risk
| CVE | CVSS | Affects Pinned Version | KEV |
|---|---|---|---|
| CVE-2003-0786 | 10.0 | No | No |
| CVE-2002-0640 | 10.0 | No | No |

**Note:** Bastion runs OpenSSH 9.1p1 which is not affected by these historical CVEs. Non-bastion hosts run 9.9p1.

## Ambiguities and Observations

1. **Bastion SSH open to internet:** The firewall rule allows SSH from 0.0.0.0/0 to the bastion. While bastions are designed for external access, this should be reviewed against PCI requirements.
2. **No explicit deny for non-allowed SSH groups:** The AllowGroups directive implicitly denies other groups, but this is not captured as an explicit ABAC deny rule (handled by default-deny).
3. **Sudo restricted only on bastion:** Only the bastion role configures sudoers. Other hosts have no explicit sudo restrictions in the Ansible config.
4. **PostgreSQL SUPERUSER granted broadly:** All DBA group members get SUPERUSER access. Consider least-privilege separation.
5. **No credentials in Ansible config:** No vault passwords or secrets were found in the configuration files.
6. **Web server HTTP only from mgmt subnet:** The firewall allows HTTP only from 10.0.0.0/24 (mgmt/bastion zone), not from the internet. This suggests a reverse-proxy or internal-only web service pattern.
7. **Log retention:** Default log retention is 365 days, consistent with PCI-DSS requirements.
