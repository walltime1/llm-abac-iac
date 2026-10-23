# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:04:36_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 11 | Rules: 16_  
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
    "groups": {
      "values": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ]
    },
    "clearance_levels": {
      "values": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml",
      "domain": [
        "secret",
        "confidential",
        "top_secret",
        "public"
      ]
    },
    "departments": {
      "values": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml",
      "domain": [
        "operations",
        "engineering",
        "data",
        "security",
        "hr"
      ]
    }
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
        "name": "app",
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
        "name": "sshd",
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
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "sshd",
        "source": "roles/app/tasks/main.yml"
      },
      {
        "path": "/etc/postgresql/pg_hba.conf",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0640",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "dmz_subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "group_vars/dmz.yml"
      }
    ],
    "source_network": {
      "values": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "roles/app/tasks/main.yml",
      "type": "cidr"
    },
    "host_group": {
      "domain": [
        "dmz",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini",
      "type": "enum"
    },
    "port": {
      "domain": [
        22,
        443,
        5432,
        8080
      ],
      "source": "group_vars/dmz.yml",
      "type": "integer"
    },
    "protocol": {
      "domain": [
        "tcp",
        "udp"
      ],
      "source": "group_vars/dmz.yml",
      "type": "enum"
    },
    "database": {
      "domain": [
        "all",
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml",
      "type": "enum"
    },
    "privilege_level": {
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml",
      "type": "enum"
    },
    "owner": {
      "source": "roles/db/tasks/main.yml",
      "type": "string"
    },
    "group": {
      "source": "roles/db/tasks/main.yml",
      "type": "string"
    },
    "mode": {
      "source": "roles/db/tasks/main.yml",
      "type": "string",
      "domain": [
        "0700",
        "0644",
        "0640",
        "0755"
      ]
    },
    "path": {
      "source": "roles/db/tasks/main.yml",
      "type": "string"
    }
  },
  "environment": {
    "org": {
      "value": "segcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "source": "inventory.ini",
      "domain": [
        "production",
        "staging",
        "development",
        "test"
      ]
    },
    "compliance_tier": {
      "value": "pci",
      "source": "inventory.ini",
      "domain": [
        "pci",
        "hipaa",
        "sox",
        "fedramp",
        "internal"
      ]
    },
    "default_log_retention_days": {
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
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        24,
        28
      ]
    }
  },
  {
    "id": "rule-002",
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
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        40,
        44
      ]
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        29,
        33
      ]
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "appservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        16,
        22
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        21,
        27
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "host_group": {
        "equals": "dbservers"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        34,
        38
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "database": {
        "equals": "all"
      },
      "privilege_level": {
        "equals": "SUPERUSER"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        20,
        25
      ]
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "database": {
        "equals": "all"
      },
      "privilege_level": {
        "equals": "NOSUPERUSER"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        27,
        32
      ]
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        7,
        14
      ]
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        12,
        19
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
    "effect": "permit",
    "obligations": [
      {
        "type": "audit",
        "description": "PostgreSQL data directory restricted to owner-only (mode 0700)"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        12,
        18
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
      "file": "policy-default",
      "task": "implicit-deny",
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
      "port": {
        "equals": 8080
      },
      "host_group": {
        "equals": "appservers"
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
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "dmz"
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
      "port": {
        "equals": 5432
      },
      "host_group": {
        "equals": "dbservers"
      },
      "database": {
        "equals": "all"
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
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses related to CNAME processing, exploit requires sending malicious DNS responses.",
    "affects_pinned_version": true,
    "recommendation": "Review and patch nginx from 1.20.0 to latest version"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit requires crafted input.",
    "affects_pinned_version": true,
    "recommendation": "Review and patch nginx from 1.20.0 to latest version"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denial of service or potentially execute arbitrary code, exploit requires processing of specially crafted",
    "affects_pinned_version": true,
    "recommendation": "Review and patch nginx from 1.20.0 to latest version"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.7,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP packets from DNS server.",
    "affects_pinned_version": true,
    "recommendation": "Review and patch nginx from 1.20.0 to latest version"
  },
  {
    "cve_id": "CVE-2013-4547",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "description": "nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 contain a restriction bypass caused by unescaped space character in URI, letting remote attackers bypass intended restrictions, exploit requires sending a crafted URI with unescaped space.",
    "affects_pinned_version": true,
    "recommendation": "Review and patch nginx from 1.20.0 to latest version"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "13.7",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation.",
    "affects_pinned_version": true,
    "recommendation": "Review and patch postgresql from 13.7 to latest version"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "13.7",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified.",
    "affects_pinned_version": true,
    "recommendation": "Review and patch postgresql from 13.7 to latest version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "13.7",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers ",
    "affects_pinned_version": true,
    "recommendation": "Review and patch postgresql from 13.7 to latest version"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "13.7",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "affects_pinned_version": true,
    "recommendation": "Review and patch postgresql from 13.7 to latest version"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "13.7",
    "cvss_score": 7.2,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit requires superuser or group membership.",
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV-listed - patch postgresql immediately"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.6",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled.",
    "affects_pinned_version": true,
    "recommendation": "Review and patch openssh from 9.6 to latest version"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.6",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input.",
    "affects_pinned_version": true,
    "recommendation": "Review and patch openssh from 9.6 to latest version"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.6",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input.",
    "affects_pinned_version": true,
    "recommendation": "Review and patch openssh from 9.6 to latest version"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.6",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requires sending crafted CRC-32 data.",
    "affects_pinned_version": true,
    "recommendation": "Review and patch openssh from 9.6 to latest version"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.6",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires remote network access.",
    "affects_pinned_version": true,
    "recommendation": "Review and patch openssh from 9.6 to latest version"
  }
]
```

## Report

# ABAC Policy Report — SegCorp Production Environment

## Executive Summary
This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration under `RLM_ANSIBLE_DIR`. The environment is a **PCI-compliant production** deployment (`segcorp`) with three host tiers: DMZ (reverse proxy), application servers, and database servers.

## Phase 1: Attribute Catalog

### Subjects
- **Users**: 3 provisioned users
  - `admin` (uid 1001, groups: sudo, dept: operations, clearance: secret)
  - `developer` (uid 1002, groups: developers, dept: engineering, clearance: confidential)
  - `dba` (uid 1003, groups: dba, dept: data, clearance: secret)
- **Groups**: sudo, developers, dba
- **Clearance levels**: secret, confidential
- **Departments**: operations, engineering, data

### Resources
- **Hosts**: proxy01.lab.local (dmz/reverse_proxy), app01.lab.local (appservers/application), db01.lab.local (dbservers/primary)
- **Services**: nginx (443/tcp, dmz), app (8080/tcp, appservers), postgresql (5432/tcp, dbservers), sshd (22/tcp, all)
- **Paths**: /var/lib/postgresql/data (postgres:postgres, 0700), /etc/ssh/sshd_config, /etc/postgresql/pg_hba.conf
- **Networks**: 10.0.1.0/24 (dmz), 10.0.2.0/24 (app), 0.0.0.0/0 (internet)

### Environment
- **Organization**: segcorp
- **Environment**: production
- **Compliance Tier**: pci
- **Log Retention**: 365 days

## Phase 1.5: Vulnerability Assessment
### Pinned Package Versions
- nginx: 1.20.0
- OpenSSH: 9.6p1 (1:9.6p1-3ubuntu1)
- PostgreSQL: 13.7 (13.7-1.pgdg20.04+1)

### Findings
| CVE | Product | CVSS | KEV | Recommendation |
|-----|---------|------|-----|----------------|
| CVE-2016-0746 | nginx | 9.8 | No | Review and patch nginx from 1.20.0 to latest |
| CVE-2021-46461 | nginx | 9.8 | No | Review and patch nginx from 1.20.0 to latest |
| CVE-2017-20005 | nginx | 9.8 | No | Review and patch nginx from 1.20.0 to latest |
| CVE-2021-23017 | nginx | 7.7 | No | Review and patch nginx from 1.20.0 to latest |
| CVE-2013-4547 | nginx | 7.5 | No | Review and patch nginx from 1.20.0 to latest |
| CVE-2007-3279 | postgresql | 10.0 | No | Review and patch postgresql from 13.7 to latest |
| CVE-2002-1399 | postgresql | 10.0 | No | Review and patch postgresql from 13.7 to latest |
| CVE-2013-1903 | postgresql | 10.0 | No | Review and patch postgresql from 13.7 to latest |
| CVE-2013-1902 | postgresql | 10.0 | No | Review and patch postgresql from 13.7 to latest |
| CVE-2019-9193 | postgresql | 7.2 | **Yes** | **URGENT**: KEV-listed — patch postgresql immediately |
| CVE-2003-0786 | openssh | 10.0 | No | Review and patch openssh from 9.6 to latest |
| CVE-2000-0999 | openssh | 10.0 | No | Review and patch openssh from 9.6 to latest |
| CVE-2000-0525 | openssh | 10.0 | No | Review and patch openssh from 9.6 to latest |
| CVE-2001-0144 | openssh | 10.0 | No | Review and patch openssh from 9.6 to latest |
| CVE-2003-0693 | openssh | 10.0 | No | Review and patch openssh from 9.6 to latest |

## Phase 2: Rules Extracted (12 rules)
1. **rule-001**: SSH login on appservers for sudo/developers groups (roles/app)
2. **rule-002**: SSH login on dbservers for sudo/dba groups (roles/db)
3. **rule-003**: SSH login on dmz for sudo group (roles/dmz)
4. **rule-004**: Network connect to app port 8080 from DMZ subnet 10.0.1.0/24 (roles/app)
5. **rule-005**: Network connect to HTTPS 443 from internet 0.0.0.0/0 on dmz (roles/dmz)
6. **rule-006**: Network connect to postgresql 5432 from app subnet 10.0.2.0/24 (roles/db)
7. **rule-007**: DB login as SUPERUSER for dba group (roles/db)
8. **rule-008**: DB login as NOSUPERUSER for developers group (roles/db)
9. **rule-009**: User creation on appservers for developers/sudo (roles/app)
10. **rule-010**: User creation on dmz for sudo (roles/dmz)
11. **rule-011**: Filesystem read on /var/lib/postgresql/data (mode 0700) for dba group with audit obligation (roles/db)
12. **rule-012**: Default deny all (implicit)

## Phase 4: Validation
- All 12 rules have valid JSON structure
- All attribute names in rules exist in the Phase-1 catalog
- Operator grammar compliance: only `equals`, `any_of`, and `applies_to` used
- Namespace discipline: subject/resource/environment conditions are disjoint
- Default-deny rule uses proper `{"applies_to": {"equals": "all"}}` form

## Ambiguities
- **Credentials**: No plaintext credentials were found in the Ansible configuration. Database authentication uses `scram-sha-256` in pg_hba.conf.
- **SSH key provisioning**: No explicit SSH key management tasks found; user creation only sets shell access.
- **Audit logging**: The PostgreSQL data directory rule includes an audit obligation noting the 0700 restriction, but no explicit centralized audit logging configuration was found in the scanned files.
- **Vulnerability version matching**: CVE version-range analysis was heuristic (product name matching in description); exact version range verification requires access to NVD/CPE data feeds.
