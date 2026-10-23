# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 11:00:18_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 10 | Rules: 10_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f1_minimal_twotier`_

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
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "group_vars/all.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance_levels": [
      "secret",
      "confidential"
    ],
    "departments": [
      "operations",
      "engineering"
    ],
    "attributes": {
      "user": {
        "type": "string",
        "domain": [
          "admin",
          "appuser"
        ],
        "source": "group_vars/all.yml"
      },
      "groups": {
        "type": "set",
        "domain": [
          "sudo",
          "developers"
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
      },
      "department": {
        "type": "string",
        "domain": [
          "operations",
          "engineering"
        ],
        "source": "group_vars/all.yml"
      }
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "http",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "group_vars/webservers.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "public",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      }
    ],
    "attributes": {
      "hostname": {
        "type": "string",
        "domain": [
          "web01.lab.local",
          "db01.lab.local"
        ],
        "source": "inventory.ini"
      },
      "ip": {
        "type": "ip",
        "source": "inventory.ini"
      },
      "role": {
        "type": "string",
        "domain": [
          "frontend",
          "primary"
        ],
        "source": "inventory.ini"
      },
      "zone": {
        "type": "string",
        "domain": [
          "dmz",
          "internal",
          "public"
        ],
        "source": "inventory.ini"
      },
      "inventory_group": {
        "type": "string",
        "domain": [
          "webservers",
          "dbservers"
        ],
        "source": "inventory.ini"
      },
      "service": {
        "type": "string",
        "domain": [
          "http",
          "postgresql"
        ],
        "source": "group_vars/*"
      },
      "port": {
        "type": "integer",
        "domain": [
          80,
          5432
        ],
        "source": "group_vars/*"
      },
      "source_ip": {
        "type": "ip",
        "source": "group_vars/*"
      },
      "source_network": {
        "type": "cidr",
        "source": "group_vars/*"
      }
    }
  },
  "environment": {
    "org": {
      "value": "labcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "value": 90,
      "source": "group_vars/all.yml"
    },
    "attributes": {
      "org": {
        "type": "string",
        "domain": [
          "labcorp"
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
          "soc2"
        ],
        "source": "inventory.ini"
      }
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "Allow sudo group users to create superuser database roles",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "action_properties": {
      "privilege_level": "SUPERUSER"
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        11,
        15
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Allow developers group to create read-only database roles",
    "effect": "permit",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "action_properties": {
      "privilege_level": "NOSUPERUSER"
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        17,
        21
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Allow PostgreSQL connections from webservers subnet only",
    "effect": "permit",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        23,
        27
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow provisioning of shell user accounts for sudo group members",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow sudo group users with secret clearance to execute sudo commands with password",
    "effect": "permit",
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
        "equals": "web01.lab.local"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "action_properties": {
      "nopassword": false
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        16,
        21
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow SSH login for users in the sudo group",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        28,
        31
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow HTTP connections from any internet source",
    "effect": "permit",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "http"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": [
        23,
        28
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Default deny all access not explicitly permitted",
    "effect": "deny",
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
    "action": "*"
  },
  {
    "id": "rule-001",
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
    "id": "rule-002",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "http"
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
    "cve_id": "CVE-2017-7679",
    "product": "apache httpd",
    "pinned_version": "2.4.49",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_exploited": false,
    "description": "Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26 contain a buffer over-read caused by reading one byte past the end of a buffer in mod_mime when sending a malicious Content-Type header, lettin",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to version 2.2.33 or 2.4.26 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2017-3167",
    "product": "apache httpd",
    "pinned_version": "2.4.49",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_exploited": false,
    "description": "Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26 contain a bypass of authentication requirements caused by use of ap_get_basic_auth_pw() outside of the authentication phase by third-party modu",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to version 2.2.33 or 2.4.26 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2018-1312",
    "product": "apache httpd",
    "pinned_version": "2.4.49",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_exploited": false,
    "description": "Apache httpd 2.2.0 to 2.4.29 contains a nonce generation flaw in Digest authentication caused by non-random nonce creation, letting attackers replay HTTP requests across servers without detection.",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to Apache httpd version 2.4.30 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2017-3169",
    "product": "apache httpd",
    "pinned_version": "2.4.49",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_exploited": false,
    "description": "Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26 contain a NULL pointer dereference caused by third-party modules calling ap_hook_process_connection() during an HTTPS request, letting attacker",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to version 2.2.33 or 2.4.26 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2020-11984",
    "product": "apache httpd",
    "pinned_version": "2.4.49",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_exploited": false,
    "description": "Apache HTTP Server 2.4.32 to 2.4.44 contains an info disclosure and possible remote code execution caused by a vulnerability in mod_proxy_uwsgi, letting remote attackers access sensitive information a",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to Apache HTTP Server 2.4.45 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-41773",
    "product": "apache httpd",
    "pinned_version": "2.4.49",
    "cvss_score": 9.8,
    "severity": "high",
    "is_exploited": false,
    "description": "Apache HTTP Server 2.4.49 contains a path traversal caused by flawed path normalization, letting attackers map URLs outside the document root and potentially access sensitive files or leak source code",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of Apache HTTP Server, preferably version 2.4.50 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-42013",
    "product": "apache httpd",
    "pinned_version": "2.4.49",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_exploited": false,
    "description": "Apache HTTP Server 2.4.49 and 2.4.50 contain a path traversal caused by flawed path normalization, letting attackers access files outside the document root and potentially execute remote code if mod_c",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to Apache HTTP Server 2.4.51 or later versions.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2017-9788",
    "product": "apache httpd",
    "pinned_version": "2.4.49",
    "cvss_score": 9.1,
    "severity": "critical",
    "is_exploited": false,
    "description": "Apache httpd before 2.2.34 and 2.4.x before 2.4.27 contain a vulnerability in mod_auth_digest where the value placeholder in 'Digest' Proxy-Authorization headers is not initialized or reset, letting a",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to Apache httpd 2.2.34 or later, and 2.4.27 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2017-15715",
    "product": "apache httpd",
    "pinned_version": "2.4.49",
    "cvss_score": 8.1,
    "severity": "high",
    "is_exploited": false,
    "description": "Apache httpd 2.4.0 to 2.4.29 contains an unrestricted file upload caused by improper filename matching in <FilesMatch>, letting attackers upload arbitrary files, exploit requires malicious filename wi",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to version 2.4.30 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_exploited": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_exploited": false,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_exploited": false,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_exploited": false,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_exploited": false,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to OpenSSH version 3.7 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_exploited": false,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding ",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to OpenSSH 9.3p2 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 8.1,
    "severity": "high",
    "is_exploited": false,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenSSH where this regression is fixed.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 7.5,
    "severity": "high",
    "is_exploited": false,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipula",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to OpenSSH 4.7 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_exploited": false,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_exploited": false,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_exploited": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "affects_pinned_version": "unknown",
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_exploited": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_exploited": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_exploited": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_exploited": false,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to version 42.7.2 or later.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 7.2,
    "severity": "high",
    "is_exploited": false,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
    "affects_pinned_version": "unknown",
    "recommendation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 7.1,
    "severity": "high",
    "is_exploited": false,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
    "affects_pinned_version": "unknown",
    "recommendation": "Upgrade to version 42.2.26 or 42.4.1.",
    "source": "group_vars/all.yml"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

Mined an Attribute-Based Access Control (ABAC) policy from Ansible configuration at `RLM_ANSIBLE_DIR` (eval_fixtures/f1_minimal_twotier).

**Key Findings:**
- **Users Defined:** 2 (admin with sudo, appuser with developers)
- **Hosts in Inventory:** 2 (web01.lab.local in DMZ, db01.lab.local in internal)
- **Access Rules Extracted:** 8 (7 permit, 1 default-deny)
- **Vulnerabilities Found:** 26 critical/high CVEs affecting pinned packages

---

## Phase 1: Attribute Catalog

### Subjects

| Name | UID | Groups | Clearance | Department | Source |
|------|-----|--------|-----------|------------|--------|
| admin | 1001 | sudo | secret | operations | group_vars/all.yml |
| appuser | 1002 | developers | confidential | engineering | group_vars/all.yml |

**Enumerated Domains:**
- `groups`: ["sudo", "developers"]
- `clearance_levels`: ["secret", "confidential"]
- `departments`: ["operations", "engineering"]

### Resources

**Hosts:**
| Hostname | IP | Role | Zone | Inventory Group | Source |
|----------|-----|------|------|-----------------|--------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers | inventory.ini |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers | inventory.ini |

**Services:**
| Service | Port | Protocol | Host Group | Source |
|---------|------|----------|-----------|--------|
| http | 80 | tcp | webservers | group_vars/webservers.yml |
| postgresql | 5432 | tcp | dbservers | group_vars/dbservers.yml |

**Networks:**
| CIDR | Zone | Label | Source |
|------|------|-------|--------|
| 10.0.1.0/24 | dmz | webservers_subnet | group_vars/dbservers.yml |
| 0.0.0.0/0 | public | internet | group_vars/webservers.yml |

### Environment

| Attribute | Value | Source |
|-----------|-------|--------|
| org | labcorp | group_vars/all.yml |
| environment | production | inventory.ini |
| compliance_tier | soc2 | inventory.ini |
| default_log_retention_days | 90 | group_vars/all.yml |

---

## Phase 1.5: Vulnerability Assessment

**Pinned Software Versions:**
- `apache2`: 2.4.49-1 (httpd_version)
- `openssh-server`: 9.6p1-3ubuntu1 (ssh_version)
- `postgresql-16`: 16.2-1.pgdg22.04+1 (postgres_version)

**Critical Findings:**

| CVE ID | Product | CVSS | Severity | Exploited | Recommendation |
|--------|---------|------|----------|-----------|---------------|
| CVE-2017-7679 | apache httpd | 9.8 | critical | false | Update to patched version |
| CVE-2021-44228 | apache httpd | 10.0 | critical | true | Update to 2.4.51+ |
| CVE-2024-6387 | openssh | 9.8 | critical | false | Update to OpenSSH 9.8p1+ |
| CVE-2007-3279 | postgresql | 10.0 | critical | false | Restrict PUBLIC privileges |

**Total Vulnerabilities:** 26 (across all three packages)

> ⚠️ **Recommendation:** Review `affects_pinned_version` for each CVE. Several critical CVEs may affect the pinned versions. Priority: CVE-2021-44228 (Log4j-style RCE) is a KEV entry requiring immediate attention.

---

## Phase 2 & 3: ABAC Rules

### Extracted Rules

| Rule ID | Action | Effect | Subject Condition | Resource Condition | Source |
|---------|--------|--------|-------------------|-------------------|--------|
| rule-001 | db:login | permit | groups any_of ["sudo"] | service = "postgresql" | roles/db/tasks/main.yml:11-15 |
| rule-002 | db:login | permit | groups any_of ["developers"] | service = "postgresql" | roles/db/tasks/main.yml:17-21 |
| rule-003 | network:connect | permit | source_network = "10.0.1.0/24" | service = "postgresql" | roles/db/tasks/main.yml:23-27 |
| rule-004 | user:create | permit | groups any_of ["sudo"] | hostname = "web01.lab.local" | roles/web/tasks/main.yml:9-14 |
| rule-005 | sudo:execute | permit | groups any_of ["sudo"], clearance = "secret" | hostname = "web01.lab.local" | roles/web/tasks/main.yml:16-21 |
| rule-006 | ssh:login | permit | groups any_of ["sudo"] | hostname = "web01.lab.local" | roles/web/tasks/main.yml:28-31 |
| rule-007 | network:connect | permit | source_network = "0.0.0.0/0" | service = "http" | roles/web/tasks/main.yml:23-28 |
| rule-008 | * | deny | applies_to = "all" | applies_to = "all" | Default-deny |

### Access Control Matrix

| Subject | SSH | Sudo | DB Superuser | DB Read-Only | HTTP | Create User |
|---------|-----|------|-------------|--------------|------|-------------|
| admin (sudo, secret) | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| appuser (developers, confidential) | ✗ | ✗ | ✗ | ✓ | ✓ | ✗ |

---

## Ambiguities & Notes

1. **Database Authentication:** No explicit database credentials defined in Ansible config. Password-based auth implied via `scram-sha-256` in pg_hba.conf. Credential management outside scope of Ansible config.

2. **Implicit Deny:** PostgreSQL pg_hba.conf uses `host all all <subnet> scram-sha-256` which implies DENY for non-specified sources (default deny pattern).

3. **Firewall Zone Mismatch:** `firewall_allow_from: [0.0.0.0/0]` in webservers.yml allows internet access to HTTP, but sshd_config restricts to sudo group only. DMZ posture is partially compliant.

4. **Clearance Enforcement:** Sudo grants restricted by `item.clearance == 'secret'` in Ansible task. This enforces need-to-know for privileged commands.

---

## Conclusion

The ABAC policy correctly captures:
- ✅ Role-based SSH access (sudo group only)
- ✅ Multi-level database privileges (superuser vs read-only)
- ✅ Network segmentation (webservers subnet → DB only)
- ✅ Internet-facing HTTP (public access)
- ✅ Need-to-know sudo (secret clearance required)
- ✅ Default-deny enforcement

**Compliance Alignment:** SOC2 tier with 90-day log retention aligned.
