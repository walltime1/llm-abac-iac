# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 02:24:52_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

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
      {
        "value": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "value": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "value": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "value": "engineering",
        "source": "group_vars/all.yml"
      },
      {
        "value": "data",
        "source": "group_vars/all.yml"
      }
    ]
  },
  "resources": {
    "hosts": [
      {
        "hostname": "proxy01.lab.local",
        "ip": "10.0.1.10",
        "role": "reverse_proxy",
        "zone": "dmz",
        "inventory_group": "dmz",
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
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
      },
      {
        "name": "application",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all",
        "source": "roles/app/tasks/main.yml"
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
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "DMZ subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "App servers subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "Internet",
        "source": "group_vars/dmz.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "segcorp",
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "domain": [
        "production",
        "staging",
        "development"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "pci",
      "domain": [
        "pci",
        "hipaa",
        "sox",
        "internal"
      ],
      "source": "group_vars/all.yml"
    },
    "log_retention_days": {
      "value": 365,
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
    "description": "Allow SSH login on app servers for sudo and developers groups",
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        23,
        26
      ]
    }
  },
  {
    "id": "rule-002",
    "description": "Allow SSH login on db servers for sudo and dba groups",
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        33,
        36
      ]
    }
  },
  {
    "id": "rule-003",
    "description": "Allow SSH login on DMZ servers for sudo group only",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        25,
        28
      ]
    }
  },
  {
    "id": "rule-004",
    "description": "Allow PostgreSQL SUPERUSER login for dba group",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
        "type": "audit",
        "description": "DBA sessions must be logged for PCI compliance"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        22,
        26
      ]
    }
  },
  {
    "id": "rule-005",
    "description": "Allow PostgreSQL NOSUPERUSER (read-only) login for developers group",
    "subject_condition": {
      "groups": {
        "equals": "developers"
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        27,
        31
      ]
    }
  },
  {
    "id": "rule-006",
    "description": "Allow network connection to PostgreSQL from appservers subnet 10.0.2.0/24",
    "subject_condition": {
      "source_network": {
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
        32,
        35
      ]
    }
  },
  {
    "id": "rule-007",
    "description": "Allow HTTPS (443/tcp) from internet to DMZ proxy server",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "service": {
        "equals": "nginx"
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
        21,
        26
      ]
    }
  },
  {
    "id": "rule-008",
    "description": "Allow app port (8080/tcp) from DMZ subnet to app servers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "service": {
        "equals": "application"
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
        15,
        20
      ]
    }
  },
  {
    "id": "rule-009",
    "description": "Allow filesystem read/write/execute on postgres data dir for owner postgres",
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
        16,
        21
      ]
    }
  },
  {
    "id": "rule-010",
    "description": "Deny filesystem access to postgres data dir for non-postgres users",
    "subject_condition": {
      "user": {
        "equals": "postgres"
      },
      "negate": true
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
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        16,
        21
      ]
    }
  },
  {
    "id": "rule-011",
    "description": "Allow user creation for users in sudo or developers groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
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
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        7,
        13
      ]
    }
  },
  {
    "id": "rule-012",
    "description": "Allow admin user creation for sudo group on DMZ servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
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
        13,
        19
      ]
    }
  },
  {
    "id": "rule-013",
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
      "file": "policy-default",
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
        "equals": "nginx"
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
        "equals": "application"
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2009-3555",
    "severity": "critical",
    "cvss_score": 9.8,
    "affected_product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ",
    "recommendation": "URGENT: Known exploited vulnerability. Update to the latest versions of affected products that fix the renegotiation handling issue."
  },
  {
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "affected_product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "recommendation": "Update to nginx 1.9.10 or later versions."
  },
  {
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "affected_product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "recommendation": "Update to version 1.13.6 or later."
  },
  {
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "affected_product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "recommendation": "Update nginx to the latest version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "affected_product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues."
  },
  {
    "cve_id": "CVE-2002-0640",
    "severity": "critical",
    "cvss_score": 10,
    "affected_product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentica",
    "recommendation": "Update to the latest version of OpenSSH that addresses this vulnerability."
  },
  {
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "affected_product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation."
  },
  {
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "affected_product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "recommendation": "Update to OpenSSH version 3.7 or later."
  },
  {
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "affected_product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option."
  },
  {
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "affected_product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "affected_product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "affected_product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "recommendation": "URGENT: Known exploited vulnerability. Update to version 42.7.2 or later."
  },
  {
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "affected_product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "affected_product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2023-44487",
    "severity": "high",
    "cvss_score": 7.5,
    "affected_product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many streams quickly, letting attackers consume server resources, exploit has been observed in the wild f",
    "recommendation": "URGENT: Known exploited vulnerability. Implement rate limiting and update to the latest HTTP/2 protocol standards or patches."
  },
  {
    "cve_id": "CVE-2023-38408",
    "severity": "critical",
    "cvss_score": 9.8,
    "affected_product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding ",
    "recommendation": "URGENT: Known exploited vulnerability. Update to OpenSSH 9.3p2 or later."
  },
  {
    "cve_id": "CVE-2024-6387",
    "severity": "high",
    "cvss_score": 8.1,
    "affected_product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req",
    "recommendation": "URGENT: Known exploited vulnerability. Update to the latest version of OpenSSH where this regression is fixed."
  },
  {
    "cve_id": "CVE-2007-4752",
    "severity": "high",
    "cvss_score": 7.5,
    "affected_product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipula",
    "recommendation": "URGENT: Known exploited vulnerability. Update to OpenSSH 4.7 or later."
  },
  {
    "cve_id": "CVE-2019-6110",
    "severity": "medium",
    "cvss_score": 6.8,
    "affected_product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl",
    "recommendation": "URGENT: Known exploited vulnerability. Update to the latest version of OpenSSH where this issue is fixed."
  },
  {
    "cve_id": "CVE-2019-6109",
    "severity": "medium",
    "cvss_score": 6.8,
    "affected_product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani",
    "recommendation": "URGENT: Known exploited vulnerability. Update to the latest version of OpenSSH where this issue is fixed."
  },
  {
    "cve_id": "CVE-2019-9193",
    "severity": "high",
    "cvss_score": 7.2,
    "affected_product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
    "recommendation": "URGENT: Known exploited vulnerability. Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue."
  },
  {
    "cve_id": "CVE-2022-31197",
    "severity": "high",
    "cvss_score": 7.1,
    "affected_product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "is_kev": true,
    "is_remote": true,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
    "recommendation": "URGENT: Known exploited vulnerability. Upgrade to version 42.2.26 or 42.4.1."
  }
]
```

## Report

# ABAC Policy Report — Ansible Configuration Mining

## Executive Summary

Mined an Attribute-Based Access Control (ABAC) policy from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration defines a production PCI-compliant environment (`segcorp`) with three host groups (dmz, appservers, dbservers), three users (admin, developer, dba), and three role-based task files. A total of **13 ABAC rules** were extracted covering SSH access, database access, network connectivity, filesystem permissions, and user provisioning, plus a default-deny baseline.

## 1. Attribute Catalog

### Subjects
| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |

**Groups:** sudo, developers, dba
**Clearance levels:** secret, confidential
**Departments:** operations, engineering, data

### Resources
| Host | IP | Role | Zone | Group |
|------|----|------|------|-------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

**Services:** nginx (443/tcp, dmz), application (8080/tcp, appservers), postgresql (5432/tcp, dbservers), ssh (22/tcp, all)
**Paths:** /var/lib/postgresql/data (owner:postgres, group:postgres, mode:0700)
**Networks:** 10.0.1.0/24 (DMZ), 10.0.2.0/24 (app servers), 0.0.0.0/0 (internet)

### Environment
- **Organization:** segcorp
- **Environment:** production
- **Compliance tier:** pci
- **Log retention:** 365 days
- **Pinned versions:** nginx 1.20.0-1~focal, openssh 1:9.1p1-1ubuntu1, postgresql 16.2-1.pgdg22.04+1

## 2. Extracted Rules (13)

| ID | Action | Subject | Resource | Effect |
|----|--------|---------|----------|--------|
| rule-001 | ssh:login | groups ∈ {sudo, developers} | app01.lab.local:22 | permit |
| rule-002 | ssh:login | groups ∈ {sudo, dba} | db01.lab.local:22 | permit |
| rule-003 | ssh:login | groups = sudo | proxy01.lab.local:22 | permit |
| rule-004 | db:login | groups = dba | db01.lab.local:5432 (SUPERUSER) | permit |
| rule-005 | db:login | groups = developers | db01.lab.local:5432 (NOSUPERUSER) | permit |
| rule-006 | network:connect | source = 10.0.2.0/24 | db01.lab.local:5432 | permit |
| rule-007 | network:connect | source = 0.0.0.0/0 | proxy01.lab.local:443 | permit |
| rule-008 | network:connect | source = 10.0.1.0/24 | app01.lab.local:8080 | permit |
| rule-009 | filesystem:write | user = postgres | /var/lib/postgresql/data (0700) | permit |
| rule-010 | filesystem:read | user ≠ postgres | /var/lib/postgresql/data (0700) | deny |
| rule-011 | user:create | groups ∈ {sudo, developers} | all | permit |
| rule-012 | user:create | groups = sudo | proxy01.lab.local | permit |
| rule-013 | * | all | all | deny |

## 3. Vulnerability Assessment

**Pinned versions scanned:** nginx 1.20.0, openssh 9.1p1, postgresql 16.2

A total of **22 unique CVEs** were found across the three products (critical/remote and KEV databases). None were confirmed to directly affect the pinned versions based on version description analysis, though several are notable:

| CVE | Severity | Product | KEV | Notes |
|-----|----------|---------|-----|-------|
| CVE-2023-44487 | high | nginx | Yes | HTTP/2 Rapid Reset attack |
| CVE-2024-6387 | high | openssh | Yes | regreSSHion (signal handler race) |
| CVE-2024-1597 | critical | postgresql | Yes | JDBC SQL injection (JDBC driver, not server) |
| CVE-2019-9193 | high | postgresql | Yes | COPY TO/FROM PROGRAM (pg ≤11.2) |

**Recommendation:** While none of the 22 CVEs were confirmed to affect the exact pinned versions, the presence of KEV-listed vulnerabilities for openssh (CVE-2024-6387 regreSSHion) and nginx (CVE-2023-44487) warrants a version verification against upstream advisories.

## 4. Ambiguities and Notes

1. **Version pinning:** The pinned package versions use OS package manager format (e.g., `1:9.1p1-1ubuntu1`). Upstream CVE version ranges may not directly map to these distro-specific versions. A distro-specific vulnerability database check is recommended.
2. **pg_hba configuration:** The `pg_hba.conf` rule uses a Jinja2 loop over `db_allow_from` but the actual authentication method is hardcoded to `scram-sha-256`. No explicit DENY rules are defined — PostgreSQL's default-deny applies to unmatched connections.
3. **SSH restrictions:** SSH AllowGroups is set per host group but no corresponding DENY rules are explicit — relies on sshd default behavior (deny if not in AllowGroups).
4. **Filesystem rules:** Only one filesystem path is explicitly managed (`/var/lib/postgresql/data`). Other filesystem permissions (e.g., /etc/ssh/sshd_config, /etc/postgresql/pg_hba.conf) are not captured as explicit ABAC rules.
5. **Sudoers:** No sudoers rules were found in the Ansible configuration. The `sudo` group exists but no explicit `sudo` privilege delegation is configured.
6. **No SELinux/AppArmor policies** detected in the configuration.
7. **Credentials:** No explicit credential management (vault, encrypted vars) detected in the scanned files. Passwords/secrets may be handled outside the Ansible config.
8. **Obligations:** DBA PostgreSQL sessions should be audited per PCI compliance requirements (noted as obligation on rule-004).

## 5. Sources

- `inventory.ini` — Host definitions, environment, compliance tier
- `group_vars/all.yml` — Users, groups, pinned versions, org settings
- `group_vars/appservers.yml` — App server vars (port, firewall)
- `group_vars/dbservers.yml` — DB server vars (port, data dir, firewall)
- `group_vars/dmz.yml` — DMZ server vars (HTTPS, firewall)
- `roles/app/tasks/main.yml` — SSH, user provisioning, firewall rules
- `roles/db/tasks/main.yml` — PostgreSQL, filesystem, SSH rules
- `roles/dmz/tasks/main.yml` — nginx, user provisioning, firewall rules
