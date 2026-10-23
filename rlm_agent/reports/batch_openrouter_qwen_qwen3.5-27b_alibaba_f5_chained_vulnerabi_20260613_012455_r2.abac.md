# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:37:21_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 13 | Rules: 17_  
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
    "groups": [
      "sudo",
      "developers",
      "dba"
    ],
    "clearance_levels": [
      "confidential",
      "secret"
    ],
    "departments": [
      "operations",
      "engineering",
      "data"
    ]
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
        "host_group": "all",
        "source": "roles/*/tasks/main.yml"
      },
      {
        "name": "httpd",
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
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "db_subnet",
        "source": "inventory.ini"
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
      "role": {
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "10-14"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
      "role": {
        "equals": "frontend"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "22-26"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
      "role": {
        "equals": "application"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "28-32"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
      "role": {
        "equals": "primary"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "26-30"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
      "role": {
        "equals": "bastion"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "16-22"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "obligations": [
      {
        "type": "nopassword",
        "value": false
      }
    ]
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "14-18"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "privileges": [
      "SUPERUSER",
      "LOGIN"
    ]
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "20-24"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "service": {
        "equals": "httpd"
      },
      "port": {
        "equals": 80
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "14-19"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "application"
      },
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": "22-27"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
      "role": {
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": "8-13"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-011",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "10-14"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "implicit",
      "task": "default-deny",
      "lines": "N/A"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
    "id": "rule-014",
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
    "id": "rule-015",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "httpd"
      },
      "port": {
        "equals": 80
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
    "id": "rule-016",
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
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
    "cve_id": "CVE-2000-0999",
    "product": "OpenBSD SSH - Buffer Overflow",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "OpenSSH - Buffer Overflow",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentica",
    "recommendation": "Update to the latest version of OpenSSH that addresses this vulnerability.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "OpenSSH - Privilege Escalation",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "OpenSSH - Buffer Overflow",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "recommendation": "Update to OpenSSH version 3.7 or later.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "OpenSSH - Privilege Escalation",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "Apache Log4j2 - JNDI Injection",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to e",
    "recommendation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "Apache Log4j - Remote Code Execution",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket servers, letting attackers execute arbitrary code rem",
    "recommendation": "Update to Log4j 2.8.2 or later.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "Apache Chainsaw - Insecure Deserialization",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting attackers execute malicious code, exploit requires attacker to send crafted seriali",
    "recommendation": "Update to version 2.1.0 or later.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "Log4j - SQL Injection",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploit requires specific JDBCAppender configuration.",
    "recommendation": "Upgrade to Log4j 2.0-beta8 or later, which supports parameterized queries and enhances security.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "Log4j - Insecure Deserialization",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, explo",
    "recommendation": "Update to the latest version of Log4j 1.2 or upgrade to Log4j 2.x.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "PostgreSQL - Integer Overflow",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "PostgreSQL - Privilege Escalation",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "pgjdbc - SQL Injection",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "recommendation": "Update to version 42.7.2 or later.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "PostgreSQL - Information Disclosure",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "PostgreSQL - Insecure Temporary Files",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "Apache Log4j2 - Remote Code Execution",
    "severity": "critical",
    "cvss_score": 9,
    "is_remote": true,
    "description": "Apache Log4j2 contains a remote code execution caused by vulnerable thread context lookup pattern in certain non-default configurations, letting remote attackers execute arbitrary code, exploit requir",
    "recommendation": "Update to the latest version of Log4j2 or apply recommended configuration changes.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2021-4104",
    "product": "Log4j - JNDI Injection",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "description": "Log4j 1.2 with JMSAppender configured contains a deserialization of untrusted data caused by write access to the configuration, letting attackers perform JNDI requests that may lead to remote code exe",
    "recommendation": "Upgrade to Log4j 2, which addresses this and other issues.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "Log4j - Denial of Service",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "description": "Log4j 1.x on JRE less than 1.7 contains a denial of service caused by deserialization of specially-crafted nested hashmaps or hashtables, letting attackers exhaust memory, exploit requires attacker to",
    "recommendation": "Update to Log4j 2.x or later versions.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "Apache Log4j2 - Remote Code Execution",
    "severity": "medium",
    "cvss_score": 6.6,
    "is_remote": true,
    "description": "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding 2.3.2 and 2.12.4) contain a remote code execution caused by unsafe JNDI LDAP data source URI usage in JDBC Appender, letting attackers with c",
    "recommendation": "Update to Log4j2 version 2.17.1, 2.12.4, or 2.3.2 to mitigate the vulnerability.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "PostgreSQL - Command Injection",
    "severity": "high",
    "cvss_score": 7.2,
    "is_remote": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
    "recommendation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue.",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "PostgreSQL JDBC Driver - SQL Injection",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
    "recommendation": "Upgrade to version 42.2.26 or 42.4.1.",
    "affects_pinned_version": true
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment for **chaincorp** with PCI compliance requirements.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | chaincorp |
| Environment | production |
| Compliance Tier | pci |
| Log Retention | 365 days |

## Subjects (Users)

| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |

**Groups**: sudo, developers, dba
**Clearance Levels**: confidential, secret
**Departments**: operations, engineering, data

## Resources

### Hosts

| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt | bastion |
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

### Services

| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| ssh | 22 | tcp | all |
| httpd | 80 | tcp | webservers |
| app | 8080 | tcp | appservers |
| postgresql | 5432 | tcp | dbservers |

### Networks

| CIDR | Zone | Label |
|------|------|-------|
| 10.0.0.0/24 | mgmt | bastion_subnet |
| 10.0.1.0/24 | dmz | web_subnet |
| 10.0.2.0/24 | app | app_subnet |
| 10.0.3.0/24 | data | db_subnet |

## Extracted ABAC Rules

### SSH Access Rules

| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-001 | groups: sudo,dba | bastion,ssh | ssh:login | permit |
| rule-002 | groups: sudo | frontend,ssh | ssh:login | permit |
| rule-003 | groups: sudo,developers | application,ssh | ssh:login | permit |
| rule-004 | groups: sudo,dba | primary,ssh | ssh:login | permit |

### Privilege Escalation

| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-005 | groups: sudo, clearance: secret | bastion | sudo:execute | permit |

### Database Access

| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-006 | groups: dba | primary,postgresql | db:login | permit |

### Network Policies

| Rule ID | Source | Resource | Action | Effect |
|---------|--------|----------|--------|--------|
| rule-007 | 10.0.2.0/24 | primary,postgresql:5432 | network:connect | permit |
| rule-008 | 10.0.0.0/24 | frontend,httpd:80 | network:connect | permit |
| rule-009 | 10.0.1.0/24 | application,app:8080 | network:connect | permit |
| rule-010 | 0.0.0.0/0 | bastion,ssh:22 | network:connect | permit |

### Filesystem Access

| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-011 | user: postgres | /var/lib/postgresql/data | filesystem:read | permit |

### Default Policy

| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-012 | all | all | * | deny |

## Vulnerability Assessment

### Summary

| Severity | Count |
|----------|-------|
| Critical | 16 |
| High | 4 |
| Medium | 1 |
| **Total** | **21** |

### Critical Findings

#### Log4j (v2.14.1)
- **CVE-2021-44228** (Log4Shell): Remote code execution via JNDI injection (CVSS 10.0)
- **CVE-2021-45046**: Thread context lookup RCE (CVSS 9.0)
- **CVE-2021-4104**: JMSAppender deserialization (CVSS 7.5)
- **CVE-2023-26464**: Denial of service (CVSS 7.5)

#### PostgreSQL (v9.2.3)
- **CVE-2013-1903**: Information disclosure (CVSS 10.0)
- **CVE-2013-1902**: Insecure temporary files (CVSS 10.0)
- **CVE-2019-9193**: Command injection via COPY (CVSS 7.2)
- **CVE-2022-31197**: JDBC SQL injection (CVSS 7.1)

#### OpenSSH (v9.1p1 on bastion, v9.9p1 elsewhere)
- **CVE-2023-38408**: Command injection (CVSS 9.8)
- **CVE-2024-6387**: Race condition (CVSS 8.1)
- Multiple historical critical vulnerabilities

### Recommendations

1. **URGENT**: Upgrade Log4j from 2.14.1 to 2.17.1+ to mitigate Log4Shell
2. **URGENT**: Upgrade PostgreSQL from 9.2.3 to 14.x or 15.x
3. **HIGH**: Upgrade OpenSSH on bastion from 9.1p1 to 9.3p2+
4. **HIGH**: Review firewall rule allowing 0.0.0.0/0 to bastion SSH
5. **MEDIUM**: Implement network segmentation between zones

## Ambiguities

1. **Credentials**: No explicit credential management found in configuration
2. **Session Logging**: No audit/logging obligations explicitly defined
3. **SELinux**: No SELinux policy rules found
4. **HTTPD Version**: Apache 2.4.49 found but no critical vulnerabilities returned

## Files Processed

- inventory.ini
- group_vars/all.yml
- group_vars/appservers.yml
- group_vars/bastion.yml
- group_vars/dbservers.yml
- group_vars/webservers.yml
- roles/app/tasks/main.yml
- roles/bastion/tasks/main.yml
- roles/db/tasks/main.yml
- roles/web/tasks/main.yml

---
*Report generated from Ansible configuration mining*
