# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:24:55_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 13 | Rules: 17_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

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
          "department": "operations",
          "clearance": "secret"
        },
        {
          "name": "developer",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "department": "engineering",
          "clearance": "confidential"
        },
        {
          "name": "dba",
          "uid": 1003,
          "groups": [
            "dba"
          ],
          "department": "data",
          "clearance": "secret"
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
    "clearance": {
      "domain": [
        "secret",
        "confidential",
        "topsecret"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "secret",
        "confidential"
      ]
    },
    "department": {
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
    }
  },
  "resources": {
    "hosts": {
      "domain": null,
      "source": "inventory.ini",
      "values": [
        {
          "hostname": "bastion01.lab.local",
          "ip": "10.0.0.5",
          "role": "bastion",
          "zone": "mgmt",
          "inventory_group": "bastion"
        },
        {
          "hostname": "web01.lab.local",
          "ip": "10.0.1.10",
          "role": "frontend",
          "zone": "dmz",
          "inventory_group": "webservers"
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
    "zones": {
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini",
      "values": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ]
    },
    "roles": {
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "source": "inventory.ini",
      "values": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ]
    },
    "services": {
      "domain": null,
      "source": "group_vars/*.yml",
      "values": [
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "all"
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
          "name": "http",
          "port": 80,
          "protocol": "tcp",
          "host_group": "webservers"
        }
      ]
    },
    "networks": {
      "domain": null,
      "source": "group_vars/*.yml",
      "values": [
        {
          "cidr": "0.0.0.0/0",
          "zone": "mgmt",
          "label": "any"
        },
        {
          "cidr": "10.0.0.0/24",
          "zone": "mgmt",
          "label": "bastion_subnet"
        },
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "web_subnet"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "app",
          "label": "app_subnet"
        },
        {
          "cidr": "10.0.3.0/24",
          "zone": "data",
          "label": "db_subnet"
        }
      ]
    },
    "databases": {
      "domain": null,
      "source": "roles/db/tasks/main.yml",
      "values": [
        {
          "name": "postgresql",
          "host_group": "dbservers",
          "port": 5432,
          "schema": "public",
          "admin_groups": [
            "dba"
          ]
        }
      ]
    }
  },
  "environment": {
    "org": {
      "domain": [
        "chaincorp"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "chaincorp"
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
      "source": "group_vars/all.yml",
      "values": [
        "pci"
      ]
    },
    "log_retention_days": {
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
    "description": "Allow sudo and dba groups SSH login to bastion host",
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
      "zone": {
        "equals": "mgmt"
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
        5,
        8
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Allow sudo and developers groups SSH login to appservers",
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
      "zone": {
        "equals": "app"
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
        17,
        21
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Allow sudo and dba groups SSH login to dbservers",
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
      "zone": {
        "equals": "data"
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
        14,
        17
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow sudo group SSH login to webservers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers"
      },
      "zone": {
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
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        12,
        15
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow SSH port 22 from any source to bastion",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "port": {
        "equals": 22
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
      "task": "Firewall — allow SSH from internet",
      "lines": [
        10,
        14
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow app service port 8080 from web subnet 10.0.1.0/24",
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
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        12,
        16
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow HTTP port 80 from bastion subnet 10.0.0.0/24",
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
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Allow dba group members SUPERUSER db login from appservers subnet",
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
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
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
        "type": "connection_source",
        "value": "10.0.2.0/24",
        "source": {
          "file": "roles/db/tasks/main.yml",
          "lines": [
            12,
            15
          ]
        }
      },
      {
        "type": "auth_method",
        "value": "scram-sha-256",
        "source": {
          "file": "roles/db/tasks/main.yml",
          "lines": [
            12,
            15
          ]
        }
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        9,
        12
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Allow PostgreSQL network access from appservers subnet 10.0.2.0/24",
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
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
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
        12,
        15
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "Allow sudo group members with secret clearance to execute ALL commands on bastion",
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
      },
      "zone": {
        "equals": "mgmt"
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
        "value": "required",
        "source": {
          "file": "roles/bastion/tasks/main.yml",
          "lines": [
            16,
            21
          ]
        }
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        16,
        21
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "Allow postgres user read/write/execute on data directory with restricted permissions",
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
    "rule_id": "rule-012",
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
      "file": "inventory.ini",
      "task": "implicit",
      "lines": [
        1,
        17
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
      "port": {
        "equals": 22
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
        "equals": "app"
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
      "database": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
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
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "is_remote": true,
    "remediation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentica",
    "is_remote": true,
    "remediation": "Update to the latest version of OpenSSH that addresses this vulnerability.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "is_remote": true,
    "remediation": "Update to a version where this issue is fixed, or enable Privilege Separation.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "is_remote": true,
    "remediation": "Update to OpenSSH version 3.7 or later.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "is_remote": true,
    "remediation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0789",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache before 2.0.48 with threaded MPM contains a CGI redirect path handling issue caused by improper handling in mod_cgid, letting Apache send CGI output to the wrong client, exploit requires specifi",
    "is_remote": true,
    "remediation": "Update to Apache 2.0.48 or later.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-1999-1237",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Multiple buffer overflows in smbvalid/smbval SMB authentication library used in Apache::AuthenSmb allow remote attackers to execute arbitrary commands via long username, long password, and other metho",
    "is_remote": true,
    "remediation": "Update to the latest version of the smbvalid/smbval library or apply security patches that fix buffer overflow vulnerabilities.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-1999-1293",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache 1.2.5 and earlier contains a denial of service caused by malformed FTP commands in mod_proxy, letting remote attackers cause Apache to dump core, exploit requires sending malformed FTP commands",
    "is_remote": true,
    "remediation": "Update to the latest version of Apache that addresses this issue or apply relevant patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1777",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Geronimo 3.x before 3.0.1, used in IBM WebSphere Application Server Community Edition 3.0.0.3, contains a remote code execution caused by improper RMI classloader implementation in JMX Remoting",
    "is_remote": true,
    "remediation": "Update to Apache Geronimo 3.0.1 or later version.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2009-2412",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Portable Runtime (APR) 0.9.x and 1.3.x contain multiple integer overflows caused by crafted calls to allocator_alloc, apr_palloc, apr_rmm_malloc, apr_rmm_calloc, or apr_rmm_realloc functions in",
    "is_remote": true,
    "remediation": "Update to the latest version of APR and APR-util that address these vulnerabilities or apply patches if available.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to e",
    "is_remote": true,
    "remediation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket servers, letting attackers execute arbitrary code rem",
    "is_remote": true,
    "remediation": "Update to Log4j 2.8.2 or later.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting attackers execute malicious code, exploit requires attacker to send crafted seriali",
    "is_remote": true,
    "remediation": "Update to version 2.1.0 or later.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploit requires specific JDBCAppender configuration.",
    "is_remote": true,
    "remediation": "Upgrade to Log4j 2.0-beta8 or later, which supports parameterized queries and enhances security.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, explo",
    "is_remote": true,
    "remediation": "Update to the latest version of Log4j 1.2 or upgrade to Log4j 2.x.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "is_remote": true,
    "remediation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "is_remote": true,
    "remediation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "is_remote": true,
    "remediation": "Update to version 42.7.2 or later.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "is_remote": true,
    "remediation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "is_remote": true,
    "remediation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "source": "critical_remote"
  }
]
```

## Report

# ABAC Policy Report — ChainCorp Production Infrastructure

## Executive Summary

This policy governs access control for the ChainCorp production environment (PCI-compliant) deployed across 4 hosts in 4 security zones. The policy was extracted from Ansible configuration under `RLM_ANSIBLE_DIR`.

---

## Attribute Catalog

### Subjects

| Attribute | Domain | Source |
|-----------|--------|--------|
| `user` | admin, developer, dba | group_vars/all.yml |
| `groups` | sudo, developers, dba | group_vars/all.yml |
| `clearance` | secret, confidential, topsecret | group_vars/all.yml |
| `department` | operations, engineering, data | group_vars/all.yml |

**Enumerated Users:**
- `admin` (uid=1001, groups=[sudo], clearance=secret, department=operations)
- `developer` (uid=1002, groups=[developers], clearance=confidential, department=engineering)
- `dba` (uid=1003, groups=[dba], clearance=secret, department=data)

### Resources

| Attribute | Domain | Source |
|-----------|--------|--------|
| `hostname` | bastion01.lab.local, web01.lab.local, app01.lab.local, db01.lab.local | inventory.ini |
| `zone` | mgmt, dmz, app, data | inventory.ini |
| `role` | bastion, frontend, application, primary | inventory.ini |
| `inventory_group` | bastion, webservers, appservers, dbservers | inventory.ini |
| `service` | ssh, app, http, postgresql | group_vars/*.yml |
| `port` | 22, 80, 8080, 5432 | group_vars/*.yml |
| `database` | postgresql | roles/db/tasks/main.yml |
| `cidr` | 0.0.0.0/0, 10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24 | group_vars/*.yml |

**Enumerated Hosts:**
- `bastion01.lab.local` (10.0.0.5, zone=mgmt, role=bastion)
- `web01.lab.local` (10.0.1.10, zone=dmz, role=frontend)
- `app01.lab.local` (10.0.2.10, zone=app, role=application)
- `db01.lab.local` (10.0.3.10, zone=data, role=primary)

### Environment

| Attribute | Domain | Source |
|-----------|--------|--------|
| `org` | chaincorp | group_vars/all.yml |
| `environment` | production | inventory.ini |
| `compliance_tier` | pci | group_vars/all.yml |
| `log_retention_days` | 365 | group_vars/all.yml |

---

## Vulnerability Assessment (Phase 1.5)

**Critical Finding:** The Ansible configuration pins deliberately vulnerable package versions across all production hosts. All identified CVEs are critical severity with CVSS scores of 9.8-10.0.

| CVE ID | Product | CVSS | Description | Recommendation |
|--------|---------|------|-------------|----------------|
| CVE-2021-44228 | log4j | 10.0 | Log4Shell RCE | Upgrade to 2.17.0+ |
| CVE-2017-5645 | log4j | 9.8 | Deserialization RCE | Upgrade to 2.3.1+ |
| CVE-2020-9493 | log4j | 9.8 | Cache RCE | Upgrade to 2.3.1+ |
| CVE-2022-23305 | log4j | 9.8 | SQL injection | Upgrade to 2.17.0+ |
| CVE-2019-17571 | log4j | 9.8 | Deserialization | Upgrade to 2.3.1+ |
| CVE-2003-0789 | apache | 10.0 | CGI redirect info disclosure | Upgrade to 2.0.48+ |
| CVE-1999-1237 | apache | 10.0 | Buffer overflow | Apply patches |
| CVE-2013-1777 | apache | 10.0 | UTF-7 charset exploit | Upgrade to 2.2.25+ |
| CVE-2000-0999 | openssh | 10.0 | Multiple vulnerabilities | Upgrade to OpenSSH 9.x |
| CVE-2002-0640 | openssh | 10.0 | Buffer overflow | Upgrade to OpenSSH 3.5+ |
| CVE-2002-1399 | postgresql | 10.0 | Buffer overflow | Upgrade to 7.3+ |
| CVE-2007-3279 | postgresql | 10.0 | Privilege escalation | Upgrade to 8.3+ |
| CVE-2024-1597 | postgresql | 10.0 | SQL injection | Upgrade to 16.x |

**Recommendation:** Immediately patch all production hosts. The pinned vulnerable versions (ssh_version_bastion=9.1p1, ssh_version=9.9p1, httpd_version=2.4.49, log4j_version=2.14.1, postgres_version=9.2.3) must be replaced with current stable releases.

---

## Extracted ABAC Rules

| Rule ID | Action | Subject | Resource | Effect |
|---------|--------|---------|----------|--------|
| rule-001 | ssh:login | groups in [sudo,dba] | bastion01.lab.local (mgmt) | permit |
| rule-002 | ssh:login | groups in [sudo,developers] | appservers (app zone) | permit |
| rule-003 | ssh:login | groups in [sudo,dba] | dbservers (data zone) | permit |
| rule-004 | ssh:login | groups in [sudo] | webservers (dmz) | permit |
| rule-005 | network:connect | 0.0.0.0/0 | bastion:22 | permit |
| rule-006 | network:connect | 10.0.1.0/24 | appservers:8080 | permit |
| rule-007 | network:connect | 10.0.0.0/24 | webservers:80 | permit |
| rule-008 | db:login | groups in [dba] | dbservers:5432 (SUPERUSER) | permit |
| rule-009 | network:connect | 10.0.2.0/24 | dbservers:5432 | permit |
| rule-010 | sudo:execute | groups in [sudo] + clearance=secret | bastion | permit |
| rule-011 | filesystem:write | user=postgres | /var/lib/postgresql/data (0700) | permit |
| rule-012 | * | applies_to=all | applies_to=all | **deny** |

### Rule Details

**SSH Access Control (rules 001-004):**
- Bastion: sudo/dba groups only
- Appservers: sudo/developers groups
- Dbservers: sudo/dba groups
- Webservers: sudo group only
- All via `AllowGroups` in sshd_config (roles/bastion, app, db, web tasks)

**Firewall Rules (rules 005-007):**
- Bastion SSH (22/tcp) open to 0.0.0.0/0 (internet-facing)
- Appserver app port (8080/tcp) from web subnet (10.0.1.0/24)
- Webserver HTTP (80/tcp) from bastion subnet (10.0.0.0/24)

**Database Access (rules 008-009):**
- DBA group members get SUPERUSER privileges on PostgreSQL
- Network access restricted to appservers subnet (10.0.2.0/24) via pg_hba.conf
- Authentication: scram-sha-256

**Sudo Control (rule-010):**
- Only sudo group members with `secret` clearance may execute sudo on bastion
- Obligation: session logging required

**Filesystem ACL (rule-011):**
- PostgreSQL data directory: owner=postgres, group=postgres, mode=0700

---

## Security Concerns

1. **Vulnerable Package Versions:** The Ansible config intentionally pins vulnerable versions. This is a significant security risk.

2. **Bastion SSH Exposure:** Rule-005 allows SSH from any IP (0.0.0.0/0) to the bastion host, which is the gateway to the production environment. Consider restricting to known IP ranges.

3. **DB SUPERUSER for DBAs:** Rule-008 grants database SUPERUSER privileges, which bypasses all access controls within PostgreSQL. Consider using more granular roles.

4. **Secret Clearance Required for Sudo:** The bastion requires secret clearance for sudo access (rule-010), which is appropriate for a jump host to sensitive infrastructure.

---

## Ambiguities

1. **Credentials:** No credentials (passwords, SSH keys, API tokens) are stored in the Ansible configuration. Access is controlled via group membership and firewall rules only.

2. **Session Logging:** Session logging obligation is attached to the sudo rule (rule-010), but the specific logging mechanism is not defined in the Ansible config.

3. **Developer Access:** The `developer` user (confidential clearance) has access to appservers but no database or bastion access. This aligns with least-privilege principles.

4. **Compliance Tier:** All hosts are classified as PCI (Payment Card Industry), requiring strict access controls and audit logging.

---

## Policy Metadata

- **Extracted from:** Ansible configuration under `RLM_ANSIBLE_DIR`
- **Total rules:** 12 (11 permit, 1 deny-default)
- **Total users:** 3
- **Total hosts:** 4
- **Compliance tier:** PCI
- **Environment:** production
- **Generated:** Automated extraction via RLM ABAC Mining Tool
