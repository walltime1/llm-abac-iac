# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 12:29:25_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 20 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "description": "Human users defined in the Ansible configuration",
    "domain": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string"
          },
          "uid": {
            "type": "integer"
          },
          "groups": {
            "type": "array",
            "items": {
              "type": "string"
            }
          },
          "clearance": {
            "type": "string"
          },
          "department": {
            "type": "string"
          },
          "source": {
            "type": "string"
          }
        }
      }
    },
    "values": [
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
      }
    ],
    "source": "group_vars/all.yml"
  },
  "groups": {
    "description": "Distinct groups defined across all Ansible configurations",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "sudo",
      "developers",
      "dba"
    ],
    "source": "group_vars/all.yml"
  },
  "clearance": {
    "description": "Information clearance levels assigned to users",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "secret",
      "confidential"
    ],
    "source": "group_vars/all.yml"
  },
  "department": {
    "description": "Organizational department of each user",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "operations",
      "engineering",
      "data"
    ],
    "source": "group_vars/all.yml"
  },
  "hostname": {
    "description": "Inventory hostname of a managed host",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "bastion01.lab.local",
      "web01.lab.local",
      "app01.lab.local",
      "db01.lab.local"
    ],
    "source": "inventory.ini"
  },
  "ip": {
    "description": "IP address of a managed host (free-form, not enumerated)",
    "domain": null,
    "source": "inventory.ini"
  },
  "role": {
    "description": "Functional role of a managed host",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "bastion",
      "frontend",
      "application",
      "primary"
    ],
    "source": "inventory.ini"
  },
  "zone": {
    "description": "Network security zone of a managed host",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "mgmt",
      "dmz",
      "app",
      "data"
    ],
    "source": "inventory.ini"
  },
  "host_group": {
    "description": "Inventory group membership (including parent group prod)",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "bastion",
      "webservers",
      "appservers",
      "dbservers",
      "prod"
    ],
    "source": "inventory.ini"
  },
  "service": {
    "description": "Network service name",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "ssh",
      "http",
      "app",
      "postgresql"
    ],
    "source": "Multiple group_vars files"
  },
  "port": {
    "description": "TCP/UDP port number for a service (free-form)",
    "domain": null,
    "source": "Multiple group_vars files"
  },
  "protocol": {
    "description": "Network protocol for a service",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "tcp"
    ],
    "source": "roles/*/tasks/main.yml firewalld entries"
  },
  "source_ip": {
    "description": "Source IP address or CIDR prefix for a network rule (free-form)",
    "domain": null,
    "source": "group_vars/*.yml"
  },
  "path": {
    "description": "Absolute filesystem path",
    "domain": null,
    "source": "roles/*/tasks/main.yml"
  },
  "owner": {
    "description": "Unix owner of a file or directory",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "postgres",
      "root"
    ],
    "source": "roles/db/tasks/main.yml"
  },
  "group": {
    "description": "Unix group of a file or directory",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "postgres"
    ],
    "source": "roles/db/tasks/main.yml"
  },
  "mode": {
    "description": "Octal Unix permission mode (free-form)",
    "domain": null,
    "source": "roles/db/tasks/main.yml"
  },
  "database": {
    "description": "Database engine name",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "postgresql"
    ],
    "source": "roles/db/tasks/main.yml"
  },
  "priv_level": {
    "description": "PostgreSQL privilege level for a database user",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "SUPERUSER",
      "NOSUPERUSER",
      "ALL"
    ],
    "source": "roles/db/tasks/main.yml"
  },
  "environment": {
    "description": "Deployment environment",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "production"
    ],
    "source": "inventory.ini [prod:vars]"
  },
  "compliance_tier": {
    "description": "Regulatory compliance tier",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "pci"
    ],
    "source": "inventory.ini [prod:vars] / group_vars/all.yml"
  },
  "org": {
    "description": "Organization name",
    "domain": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "values": [
      "chaincorp"
    ],
    "source": "group_vars/all.yml"
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "Bastion host accepts SSH logins from users in sudo or dba groups",
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
      "service": {
        "equals": "ssh"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        8,
        11
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Users with sudo group AND secret clearance may sudo on bastion (password required)",
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "Sudo sessions on bastion must be logged via session audit script",
        "source_file": "roles/bastion/tasks/main.yml",
        "task": "Only secret-clearance may sudo"
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        13,
        19
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Bastion firewall permits TCP/22 from any source (0.0.0.0/0 -- internet SSH)",
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
        "equals": "22"
      },
      "protocol": {
        "equals": "tcp"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall -- allow SSH from internet",
      "lines": [
        20,
        24
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "DB server accepts SSH logins from users in sudo or dba groups",
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
      "service": {
        "equals": "ssh"
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
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        22,
        25
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Users in dba group receive PostgreSQL SUPERUSER privileges on the database server",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "database": {
        "equals": "postgresql"
      },
      "service": {
        "equals": "postgresql"
      },
      "priv_level": {
        "equals": "SUPERUSER"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        10,
        14
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "PostgreSQL accepts connections from the appservers subnet (10.0.2.0/24) via scram-sha-256",
    "subject_condition": {
      "source_ip": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": "5432"
      },
      "protocol": {
        "equals": "tcp"
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
        15,
        19
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "PostgreSQL data directory owned by postgres:postgres with mode 0700",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
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
        5,
        10
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Web server accepts SSH logins from users in sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "service": {
        "equals": "ssh"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        14,
        17
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Web server firewall permits TCP/80 from the bastion/mgmt subnet (10.0.0.0/24)",
    "subject_condition": {
      "source_ip": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "port": {
        "equals": "80"
      },
      "protocol": {
        "equals": "tcp"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall -- allow HTTP from bastion subnet",
      "lines": [
        9,
        13
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "App server accepts SSH logins from users in sudo or developers groups",
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
      "service": {
        "equals": "ssh"
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
        21,
        24
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "App server firewall permits TCP/8080 from the webserver subnet (10.0.1.0/24)",
    "subject_condition": {
      "source_ip": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "port": {
        "equals": "8080"
      },
      "protocol": {
        "equals": "tcp"
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
      "task": "Firewall -- allow app port from web subnet",
      "lines": [
        17,
        20
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "description": "Application JAR file is deployed to /opt/app/app.jar via Ansible copy module",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "path": {
        "equals": "/opt/app/app.jar"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Deploy application with Log4j {{ log4j_version }}",
      "lines": [
        5,
        8
      ]
    }
  },
  {
    "rule_id": "rule-013",
    "description": "Default-deny: all subjects, all resources, all actions are denied unless explicitly permitted above",
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
      "file": "synthesized",
      "task": "default-deny policy",
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
      "hostname": {
        "equals": "db01.lab.local"
      },
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
      "port": {
        "equals": "22"
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
    "id": "rule-003",
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
        "equals": "5432"
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
        "equals": "80"
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
        "equals": "8080"
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
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10.0,
    "product": "ssh",
    "pinned_version_affected": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "remediation": "Update to a version where this issue is fixed, or enable Privilege Separation.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:openssh"
  },
  {
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10.0,
    "product": "ssh",
    "pinned_version_affected": false,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "remediation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:openssh"
  },
  {
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10.0,
    "product": "ssh",
    "pinned_version_affected": false,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "remediation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:openssh"
  },
  {
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "cvss_score": 10.0,
    "product": "ssh",
    "pinned_version_affected": false,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir",
    "remediation": "Update to the latest version or apply security patches addressing the integer overflow issue.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:openssh"
  },
  {
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10.0,
    "product": "ssh",
    "pinned_version_affected": false,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "remediation": "Update to OpenSSH version 3.7 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:openssh"
  },
  {
    "cve_id": "CVE-2002-0640",
    "severity": "critical",
    "cvss_score": 10.0,
    "product": "ssh",
    "pinned_version_affected": false,
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentica",
    "remediation": "Update to the latest version of OpenSSH that addresses this vulnerability.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:openssh"
  },
  {
    "cve_id": "CVE-2002-0083",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "ssh",
    "pinned_version_affected": false,
    "description": "OpenSSH 2.0 through 3.0.2 contains an off-by-one error in the channel code, letting local users or remote malicious servers gain privileges, exploit requires attacker to control the server or local en",
    "remediation": "Update to the latest version of OpenSSH that addresses this issue.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:openssh"
  },
  {
    "cve_id": "CVE-2002-0639",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "ssh",
    "pinned_version_affected": false,
    "description": "OpenSSH 2.9.9 through 3.3 contains an integer overflow caused by improper handling during challenge response authentication in sshd, letting remote attackers execute arbitrary code when using SKEY or ",
    "remediation": "Update to the latest version of OpenSSH that addresses this vulnerability.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:openssh"
  },
  {
    "cve_id": "CVE-2023-28531",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "ssh",
    "pinned_version_affected": false,
    "description": "OpenSSH before 9.3 contains a vulnerability in ssh-add that adds smartcard keys to ssh-agent without enforcing per-hop destination constraints, letting attackers potentially escalate privileges or acc",
    "remediation": "Update to OpenSSH 9.3 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:openssh"
  },
  {
    "cve_id": "CVE-2016-1908",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "ssh",
    "pinned_version_affected": false,
    "description": "OpenSSH < 7.2 mishandles failed cookie generation for untrusted X11 forwarding caused by reliance on local X11 server for access control, letting remote X11 clients trigger fallback and gain trusted f",
    "remediation": "Update to OpenSSH 7.2 or later to fix cookie handling and access control logic.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:openssh"
  },
  {
    "cve_id": "CVE-2017-7679",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "httpd",
    "pinned_version_affected": false,
    "description": "Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26 contain a buffer over-read caused by reading one byte past the end of a buffer in mod_mime when sending a malicious Content-Type header, lettin",
    "remediation": "Update to version 2.2.33 or 2.4.26 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:apache httpd"
  },
  {
    "cve_id": "CVE-2017-3167",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "httpd",
    "pinned_version_affected": false,
    "description": "Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26 contain a bypass of authentication requirements caused by use of ap_get_basic_auth_pw() outside of the authentication phase by third-party modu",
    "remediation": "Update to version 2.2.33 or 2.4.26 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:apache httpd"
  },
  {
    "cve_id": "CVE-2018-1312",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "httpd",
    "pinned_version_affected": false,
    "description": "Apache httpd 2.2.0 to 2.4.29 contains a nonce generation flaw in Digest authentication caused by non-random nonce creation, letting attackers replay HTTP requests across servers without detection.",
    "remediation": "Update to Apache httpd version 2.4.30 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:apache httpd"
  },
  {
    "cve_id": "CVE-2017-3169",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "httpd",
    "pinned_version_affected": false,
    "description": "Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26 contain a NULL pointer dereference caused by third-party modules calling ap_hook_process_connection() during an HTTPS request, letting attacker",
    "remediation": "Update to version 2.2.33 or 2.4.26 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:apache httpd"
  },
  {
    "cve_id": "CVE-2020-11984",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "httpd",
    "pinned_version_affected": false,
    "description": "Apache HTTP Server 2.4.32 to 2.4.44 contains an info disclosure and possible remote code execution caused by a vulnerability in mod_proxy_uwsgi, letting remote attackers access sensitive information a",
    "remediation": "Update to Apache HTTP Server 2.4.45 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:apache httpd"
  },
  {
    "cve_id": "CVE-2021-42013",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "httpd",
    "pinned_version_affected": false,
    "description": "Apache HTTP Server 2.4.49 and 2.4.50 contain a path traversal caused by flawed path normalization, letting attackers access files outside the document root and potentially execute remote code if mod_c",
    "remediation": "Update to Apache HTTP Server 2.4.51 or later versions.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:apache httpd"
  },
  {
    "cve_id": "CVE-2021-41773",
    "severity": "high",
    "cvss_score": 9.8,
    "product": "httpd",
    "pinned_version_affected": false,
    "description": "Apache HTTP Server 2.4.49 contains a path traversal caused by flawed path normalization, letting attackers map URLs outside the document root and potentially access sensitive files or leak source code",
    "remediation": "Update to the latest version of Apache HTTP Server, preferably version 2.4.50 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:apache httpd"
  },
  {
    "cve_id": "CVE-2017-9788",
    "severity": "critical",
    "cvss_score": 9.1,
    "product": "httpd",
    "pinned_version_affected": false,
    "description": "Apache httpd before 2.2.34 and 2.4.x before 2.4.27 contain a vulnerability in mod_auth_digest where the value placeholder in 'Digest' Proxy-Authorization headers is not initialized or reset, letting a",
    "remediation": "Update to Apache httpd 2.2.34 or later, and 2.4.27 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:apache httpd"
  },
  {
    "cve_id": "CVE-2017-15715",
    "severity": "high",
    "cvss_score": 8.1,
    "product": "httpd",
    "pinned_version_affected": false,
    "description": "Apache httpd 2.4.0 to 2.4.29 contains an unrestricted file upload caused by improper filename matching in <FilesMatch>, letting attackers upload arbitrary files, exploit requires malicious filename wi",
    "remediation": "Update to version 2.4.30 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:apache httpd"
  },
  {
    "cve_id": "CVE-1999-0071",
    "severity": "high",
    "cvss_score": 7.5,
    "product": "httpd",
    "pinned_version_affected": false,
    "description": "Apache httpd versions 1.1.1 and earlier contain a cookie buffer overflow caused by improper handling of cookie data, letting remote attackers execute arbitrary code, exploit requires sending malicious",
    "remediation": "Update to the latest version of Apache httpd.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:apache httpd"
  },
  {
    "cve_id": "CVE-2021-44228",
    "severity": "critical",
    "cvss_score": 10.0,
    "product": "log4j2",
    "pinned_version_affected": true,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to e",
    "remediation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:log4j"
  },
  {
    "cve_id": "CVE-2022-23305",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "log4j2",
    "pinned_version_affected": false,
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploit requires specific JDBCAppender configuration.",
    "remediation": "Upgrade to Log4j 2.0-beta8 or later, which supports parameterized queries and enhances security.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:log4j"
  },
  {
    "cve_id": "CVE-2020-9493",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "log4j2",
    "pinned_version_affected": false,
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting attackers execute malicious code, exploit requires attacker to send crafted seriali",
    "remediation": "Update to version 2.1.0 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:log4j"
  },
  {
    "cve_id": "CVE-2019-17571",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "log4j2",
    "pinned_version_affected": false,
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, explo",
    "remediation": "Update to the latest version of Log4j 1.2 or upgrade to Log4j 2.x.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:log4j"
  },
  {
    "cve_id": "CVE-2017-5645",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "log4j2",
    "pinned_version_affected": false,
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket servers, letting attackers execute arbitrary code rem",
    "remediation": "Update to Log4j 2.8.2 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:log4j"
  },
  {
    "cve_id": "CVE-2021-45046",
    "severity": "critical",
    "cvss_score": 9.0,
    "product": "log4j2",
    "pinned_version_affected": true,
    "description": "Apache Log4j2 contains a remote code execution caused by vulnerable thread context lookup pattern in certain non-default configurations, letting remote attackers execute arbitrary code, exploit requir",
    "remediation": "Update to the latest version of Log4j2 or apply recommended configuration changes.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:log4j"
  },
  {
    "cve_id": "CVE-2022-23307",
    "severity": "high",
    "cvss_score": 8.8,
    "product": "log4j2",
    "pinned_version_affected": false,
    "description": "Apache Chainsaw and Apache Log4j 1.2.x contain an insecure deserialization caused by improper handling of serialized data, letting attackers execute arbitrary code or cause denial of service, exploit ",
    "remediation": "Update to the latest version of Apache Chainsaw and Log4j, or apply security patches addressing deserialization issues.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:log4j"
  },
  {
    "cve_id": "CVE-2022-23302",
    "severity": "high",
    "cvss_score": 8.8,
    "product": "log4j2",
    "pinned_version_affected": false,
    "description": "Log4j 1.x contains a deserialization of untrusted data caused by JMSSink configuration referencing LDAP or having write access, letting attackers perform JNDI requests that result in remote code execu",
    "remediation": "Upgrade to Log4j 2, which addresses this and other issues.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:log4j"
  },
  {
    "cve_id": "CVE-2023-26464",
    "severity": "high",
    "cvss_score": 7.5,
    "product": "log4j2",
    "pinned_version_affected": false,
    "description": "Log4j 1.x on JRE less than 1.7 contains a denial of service caused by deserialization of specially-crafted nested hashmaps or hashtables, letting attackers exhaust memory, exploit requires attacker to",
    "remediation": "Update to Log4j 2.x or later versions.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:log4j"
  },
  {
    "cve_id": "CVE-2021-4104",
    "severity": "high",
    "cvss_score": 7.5,
    "product": "log4j2",
    "pinned_version_affected": false,
    "description": "Log4j 1.2 with JMSAppender configured contains a deserialization of untrusted data caused by write access to the configuration, letting attackers perform JNDI requests that may lead to remote code exe",
    "remediation": "Upgrade to Log4j 2, which addresses this and other issues.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:log4j"
  },
  {
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10.0,
    "product": "postgres",
    "pinned_version_affected": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "remediation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:postgresql"
  },
  {
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10.0,
    "product": "postgres",
    "pinned_version_affected": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "remediation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:postgresql"
  },
  {
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10.0,
    "product": "postgres",
    "pinned_version_affected": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "remediation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:postgresql"
  },
  {
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10.0,
    "product": "postgres",
    "pinned_version_affected": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "remediation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:postgresql"
  },
  {
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10.0,
    "product": "postgres",
    "pinned_version_affected": false,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "remediation": "Update to version 42.7.2 or later.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:postgresql"
  },
  {
    "cve_id": "CVE-2015-0244",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "postgres",
    "pinned_version_affected": false,
    "description": "PostgreSQL < 9.0.19, 9.1.x < 9.1.15, 9.2.x < 9.2.10, 9.3.x < 9.3.6, and 9.4.x < 9.4.1 contain a SQL injection caused by improper error handling during protocol message reading, letting remote attacker",
    "remediation": "Update to PostgreSQL 9.0.19, 9.1.15, 9.2.10, 9.3.6, or 9.4.1 or later versions.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:postgresql"
  },
  {
    "cve_id": "CVE-2019-10211",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "postgres",
    "pinned_version_affected": false,
    "description": "PostgreSQL Windows installer before versions 11.5, 10.10, 9.6.15, 9.5.19, 9.4.24 contains a code execution vulnerability caused by bundled OpenSSL executing code from an unprotected directory, letting",
    "remediation": "Update to PostgreSQL version 11.5, 10.10, 9.6.15, 9.5.19, 9.4.24 or later versions.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:postgresql"
  },
  {
    "cve_id": "CVE-2022-26520",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "postgres",
    "pinned_version_affected": false,
    "description": "pgjdbc before 42.3.3 contains a file write vulnerability caused by misuse of java.util.logging.FileHandler through loggerFile and loggerLevel properties, letting attackers control file writes, exploit",
    "remediation": "Update to version 42.3.3 or later, and ensure untrusted connection properties are not used.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:postgresql"
  },
  {
    "cve_id": "CVE-2018-16850",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "postgres",
    "pinned_version_affected": false,
    "description": "PostgreSQL before versions 11.1, 10.6 contains a sql_injection caused by crafted trigger definitions in pg_upgrade and pg_dump via CREATE TRIGGER ... REFERENCING, letting attackers execute arbitrary S",
    "remediation": "Update to PostgreSQL 11.1, 10.6 or later versions.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:postgresql"
  },
  {
    "cve_id": "CVE-2017-7546",
    "severity": "critical",
    "cvss_score": 9.8,
    "product": "postgres",
    "pinned_version_affected": false,
    "description": "PostgreSQL versions before 9.2.22, 9.3.18, 9.4.13, 9.5.8, and 9.6.4 contain an incorrect authentication flaw caused by improper password validation, letting remote attackers access database accounts w",
    "remediation": "Update to PostgreSQL 9.2.22, 9.3.18, 9.4.13, 9.5.8, or 9.6.4 or later versions.",
    "is_kev": false,
    "is_remote": true,
    "source_query": "critical_remote:postgresql"
  }
]
```

## Report

# ABAC Policy Report — Chaincorp Production Infrastructure

**Organization:** chaincorp  **Environment:** production  **Compliance Tier:** PCI-DSS
**Source:** Ansible configuration rooted at `RLM_ANSIBLE_DIR`

---

## 1. Attribute Catalog

### 1.1 Subject Attributes

| Attribute | Type | Values / Domain | Source |
|---|---|---|---|
| `name` | string | admin, developer, dba | group_vars/all.yml |
| `uid` | integer | 1001, 1002, 1003 | group_vars/all.yml |
| `groups` | set | sudo, developers, dba | group_vars/all.yml |
| `clearance` | enum | secret, confidential | group_vars/all.yml |
| `department` | enum | operations, engineering, data | group_vars/all.yml |

### 1.2 Resource Attributes

| Attribute | Type | Values / Domain | Source |
|---|---|---|---|
| `hostname` | enum | bastion01.lab.local, web01.lab.local, app01.lab.local, db01.lab.local | inventory.ini |
| `ip` | free-form | 10.0.0.5, 10.0.1.10, 10.0.2.10, 10.0.3.10 | inventory.ini |
| `role` | enum | bastion, frontend, application, primary | inventory.ini |
| `zone` | enum | mgmt, dmz, app, data | inventory.ini |
| `host_group` | set | bastion, webservers, appservers, dbservers, prod | inventory.ini |
| `service` | enum | ssh, http, app, postgresql | group_vars/*.yml |
| `port` | free-form | 22, 80, 8080, 5432 | group_vars/*.yml |
| `protocol` | enum | tcp | roles/*/tasks/main.yml |
| `source_ip` | free-form (CIDR) | 0.0.0.0/0, 10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24 | group_vars/*.yml |
| `path` | free-form | /var/lib/postgresql/data, /opt/app/app.jar | roles/*/tasks/main.yml |
| `owner` | enum | postgres, root | roles/db/tasks/main.yml |
| `group` | enum | postgres | roles/db/tasks/main.yml |
| `mode` | free-form (octal) | 0700 | roles/db/tasks/main.yml |
| `database` | enum | postgresql | roles/db/tasks/main.yml |
| `priv_level` | enum | SUPERUSER, NOSUPERUSER, ALL | roles/db/tasks/main.yml |

### 1.3 Environment Attributes

| Attribute | Type | Values / Domain | Source |
|---|---|---|---|
| `environment` | enum | production | inventory.ini [prod:vars] |
| `compliance_tier` | enum | pci | inventory.ini [prod:vars] / group_vars/all.yml |
| `org` | enum | chaincorp | group_vars/all.yml |

---

## 2. Discovered Vulnerabilities (Phase 1.5)

**Packages pinned in Ansible configuration:**
- `openssh-server=1:9.1p1-1ubuntu1` (bastion) and `1:9.9p1-3ubuntu1` (other hosts)
- `apache2=2.4.49-1` (web server)
- `log4j-core=2.14.1` (application server) — **CRITICAL**
- `postgresql-9.2=9.2.3-1.pgdg20.04+1` (database server)

### 2.1 Critical Vulnerabilities Affecting Pinned Versions

| CVE ID | Product | CVSS | Severity | Pinned Affected | Remediation |
|---|---|---|---|---|---|
| **CVE-2021-44228** | log4j2 | **10.0** | critical | **Yes (2.14.1)** | Update to Log4j 2.15.0+ which disables JNDI lookups by default |
| CVE-2003-0786 | ssh | 10.0 | critical | No (OpenSSH 3.7 era) | Enable Privilege Separation |
| CVE-2000-0999 | ssh | 10.0 | critical | No (OpenSSH ~2000 era) | Update to latest OpenSSH |
| CVE-2000-0525 | ssh | 10.0 | critical | No | Disable UseLogin in sshd_config |
| CVE-2001-0144 | ssh | 10.0 | critical | No | Update to latest SSH |
| CVE-2003-0693 | ssh | 10.0 | critical | No (OpenSSH <3.7) | Update to OpenSSH 3.7+ |
| CVE-2002-0640 | ssh | 10.0 | critical | No | Update OpenSSH |
| CVE-2007-3279 | postgres | 10.0 | critical | No (PostgreSQL 8.1+) | Restrict PUBLIC privileges on plpgsql |
| CVE-2013-1903 | postgres | 10.0 | critical | No | Update to PostgreSQL 9.2.4+ |
| CVE-2013-1902 | postgres | 10.0 | critical | No | Use secure temp file handling |
| CVE-2017-7679 | httpd | 9.8 | critical | No (Apache 2.4.27+) | Update Apache httpd |

**Immediate Action Required:** CVE-2021-44228 (Log4Shell) affects the pinned `log4j-core=2.14.1` deployed on `app01.lab.local`.
Remote code execution is possible via crafted JNDI lookups in log messages. Patch `app01.lab.local` to Log4j 2.15.0+
as the highest priority. 40 total CVEs retrieved across 4 products (ssh, httpd, log4j2, postgres).

---

## 3. ABAC Access Rules (Phase 2)

### 3.1 Rule Summary Table

| Rule ID | Subject(s) | Action | Target | Effect |
|---|---|---|---|---|
| rule-001 | sudo, dba groups | ssh:login | bastion01.lab.local | permit |
| rule-002 | sudo + secret clearance | sudo:execute | bastion01.lab.local | permit |
| rule-003 | any (0.0.0.0/0) | network:connect | bastion01:22/tcp | permit |
| rule-004 | sudo, dba groups | ssh:login | db01.lab.local | permit |
| rule-005 | dba group | db:login SUPERUSER | db01.lab.local/postgresql | permit |
| rule-006 | appservers subnet 10.0.2.0/24 | network:connect | db01:5432/tcp | permit |
| rule-007 | dba group | filesystem:write | /var/lib/postgresql/data | permit |
| rule-008 | sudo group | ssh:login | web01.lab.local | permit |
| rule-009 | mgmt subnet 10.0.0.0/24 | network:connect | web01.lab.local:80/tcp | permit |
| rule-010 | sudo, developers groups | ssh:login | app01.lab.local | permit |
| rule-011 | web subnet 10.0.1.0/24 | network:connect | app01.lab.local:8080/tcp | permit |
| rule-012 | sudo group | filesystem:write | /opt/app/app.jar | permit |
| **rule-013** | **all** | ******** | **all** | **deny** |

### 3.2 Rule Details with Provenance

**rule-001** — SSH Login to Bastion Host
- **Subjects:** users in `sudo` or `dba` groups
- **Resource:** `bastion01.lab.local`, service `ssh`
- **Action:** `ssh:login` — permit
- **Source:** `roles/bastion/tasks/main.yml` | task 'Restrict bastion logins' | lines 8-11
- **Extracted from:** `lineinfile` writing `AllowGroups sudo dba` to `/etc/ssh/sshd_config`

**rule-002** — Sudo on Bastion (Secret Clearance Only)
- **Subjects:** users in `sudo` group AND `clearance = secret`
- **Resource:** `bastion01.lab.local`
- **Action:** `sudo:execute` — permit (password required, nopassword=false)
- **Obligation:** Sudo sessions on bastion must be logged via session audit script
- **Source:** `roles/bastion/tasks/main.yml` | task 'Only secret-clearance may sudo' | lines 13-19
- **Extracted from:** `community.general.sudoers` with `commands: ALL`, `nopassword: false`,
  `when: "'sudo' in item.groups and item.clearance == 'secret'"`

**rule-003** — Bastion Firewall: SSH from Internet
- **Source:** any host (`source_ip = 0.0.0.0/0`)
- **Resource:** `bastion01.lab.local`, port `22/tcp`
- **Action:** `network:connect` — permit
- **Source:** `roles/bastion/tasks/main.yml` | task 'Firewall — allow SSH from internet' | lines 20-24
- **Extracted from:** `ansible.posix.firewalld` with `firewall_allow_from: [0.0.0.0/0]`, port `22/tcp`
- **Security note:** Internet-wide SSH exposure is high-risk; a VPN or bastion-only jump pattern
  is recommended for PCI compliance.

**rule-004** — SSH Login to DB Server
- **Subjects:** users in `sudo` or `dba` groups
- **Resource:** `db01.lab.local`, service `ssh`
- **Action:** `ssh:login` — permit
- **Source:** `roles/db/tasks/main.yml` | task 'Restrict SSH to sudo and dba groups' | lines 22-25

**rule-005** — DB Superuser for DBAs
- **Subjects:** users in `dba` group
- **Resource:** `db01.lab.local`, database `postgresql`, `priv_level = SUPERUSER`
- **Action:** `db:login` — permit
- **Source:** `roles/db/tasks/main.yml` | task 'Create DB superuser role for DBAs' | lines 10-14
- **Extracted from:** `community.postgresql.postgresql_user` with `role_attr_flags: LOGIN,SUPERUSER`
- **Security note:** SUPERUSER grants full database privileges; DPA/audit obligations apply

**rule-006** — PostgreSQL Network Access from Appservers Subnet
- **Source:** hosts in `source_ip = 10.0.2.0/24` (appservers subnet)
- **Resource:** `db01.lab.local`, service `postgresql`, port `5432/tcp`
- **Action:** `network:connect` — permit
- **Source:** `roles/db/tasks/main.yml` | task 'Allow postgres only from appservers subnet' | lines 15-19
- **Extracted from:** `lineinfile` appending `host all all 10.0.2.0/24 scram-sha-256` to `/etc/postgresql/pg_hba.conf`

**rule-007** — PostgreSQL Data Directory Permissions
- **Subjects:** users in `dba` group
- **Resource:** `db01.lab.local`, path `/var/lib/postgresql/data`, owner `postgres`, group `postgres`, mode `0700`
- **Action:** `filesystem:write` — permit
- **Source:** `roles/db/tasks/main.yml` | task 'Ensure postgres data dir' | lines 5-10
- **Extracted from:** `ansible.builtin.file` with `owner: postgres`, `group: postgres`, `mode: '0700'`

**rule-008** — SSH Login to Web Server
- **Subjects:** users in `sudo` group
- **Resource:** `web01.lab.local`, service `ssh`
- **Action:** `ssh:login` — permit
- **Source:** `roles/web/tasks/main.yml` | task 'Restrict SSH to sudo group' | lines 14-17

**rule-009** — Web Server Firewall: HTTP from Bastion Subnet
- **Source:** hosts in `source_ip = 10.0.0.0/24` (mgmt/bastion subnet)
- **Resource:** `web01.lab.local`, port `80/tcp`
- **Action:** `network:connect` — permit
- **Source:** `roles/web/tasks/main.yml` | task 'Firewall — allow HTTP from bastion subnet' | lines 9-13

**rule-010** — SSH Login to App Server
- **Subjects:** users in `sudo` or `developers` groups
- **Resource:** `app01.lab.local`, service `ssh`
- **Action:** `ssh:login` — permit
- **Source:** `roles/app/tasks/main.yml` | task 'Restrict SSH to approved groups' | lines 21-24

**rule-011** — App Server Firewall: Application Port from Web Subnet
- **Source:** hosts in `source_ip = 10.0.1.0/24` (webservers subnet)
- **Resource:** `app01.lab.local`, port `8080/tcp`
- **Action:** `network:connect` — permit
- **Source:** `roles/app/tasks/main.yml` | task 'Firewall — allow app port from web subnet' | lines 17-20

**rule-012** — Application JAR Deployment
- **Subjects:** users in `sudo` group
- **Resource:** `app01.lab.local`, path `/opt/app/app.jar`
- **Action:** `filesystem:write` — permit
- **Source:** `roles/app/tasks/main.yml` | task 'Deploy application with Log4j' | lines 5-8
- **Security note:** Deployment embeds vulnerable Log4j 2.14.1 — see Section 2

**rule-013** — Default Deny
- **All subjects, all resources, all actions**
- **Action:** `*` — deny
- **Rationale:** Explicit deny-all closes implicit permit gaps; all explicitly permitted accesses
  are enumerated above (rules 001-012)

---

## 4. Network Topology Summary

    Internet (0.0.0.0/0) --SSH:22/tcp--> bastion01.lab.local [mgmt zone]
                                         |
                          SSH (sudo/dba) | SSH (sudo/dba)
                                         v
                        web01.lab.local --HTTP:80--> [bastion subnet 10.0.0.0/24]
                        [dmz zone]         |
                          |           SSH (sudo/developers)
                    HTTP (mgmt)            v
                    [web subnet      app01.lab.local --app_port:8080
                      10.0.1.0/24]         [app zone]
                          |                   |
                app_port:8080/tcp       [apps subnet 10.0.2.0/24]
                          |                   |
                          +-------DB:5432-----> db01.lab.local [data zone]
                                    [pg_hba: scram-sha-256]

---

## 5. Ambiguities and Notes

1. **Credentials in plaintext:** No credential-passing tasks (passwords, API tokens, private keys) were
   detected in the role task files. If credentials are passed via `ansible-vault` or `vars_prompt`,
   they are not visible in the current file scan and should be flagged as a security ambiguity.

2. **Session logging (rule-002 obligation):** The `bastion` sudoers task specifies an obligation to
   log sessions via audit script, but no session-audit role or script was found in the file scan.
   The obligation is recorded on rule-002 pending implementation verification.

3. **Implicit deny for network rules:** The `pg_hba.conf` task only appends a permit rule;
   the Ansible file does not show a corresponding deny-all entry. The default-deny rule-013
   covers this gap at the policy level.

4. **No dedicated monitoring/metrics rules:** No Nagios, NRPE, or Prometheus exporter tasks were
   found in the role file scan. Monitoring access rules are omitted from this policy.

5. **No host-level firewall default-drop:** Each firewalld task is additive (permanent:true, state:enabled)
   with no explicit default-drop policy. The default-deny rule-013 closes this gap.

---

## 6. Files Processed

| Phase | File | Role in Policy |
|---|---|---|
| Catalog | inventory.ini | Host inventory: 4 hosts, 5 groups |
| Catalog | group_vars/all.yml | Org/dept/compliance attrs, 3 users, 4 packages |
| Catalog | group_vars/bastion.yml | SSH/firewall allow-lists for bastion |
| Catalog | group_vars/appservers.yml | App port and allow-lists |
| Catalog | group_vars/dbservers.yml | Postgres port, data dir, DB allow-list |
| Catalog | group_vars/webservers.yml | HTTP port, firewall allow-list |
| Rules | roles/bastion/tasks/main.yml | SSH login restriction, sudo, firewall |
| Rules | roles/db/tasks/main.yml | SSH restriction, postgres user, pg_hba, data dir |
| Rules | roles/web/tasks/main.yml | SSH restriction, firewall |
| Rules | roles/app/tasks/main.yml | SSH restriction, firewall, app JAR deploy |

---

*Report generated by ABAC policy miner — Ansible configuration rooted at `RLM_ANSIBLE_DIR`*