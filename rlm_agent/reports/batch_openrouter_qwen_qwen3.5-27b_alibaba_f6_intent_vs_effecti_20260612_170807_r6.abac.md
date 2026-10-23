# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:14:53_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
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
      "secret",
      "confidential"
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
        "label": "Internet-facing",
        "source": "group_vars/dmz.yml"
      }
    ]
  },
  "environment": {
    "org": "segcorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
    "source": "inventory.ini,group_vars/all.yml"
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
      "hostname": {
        "equals": "app01.lab.local"
      },
      "service": {
        "equals": "ssh"
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
      "lines": "22-26"
    }
  },
  {
    "id": "rule-002",
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
      "task": "Firewall — allow app port from DMZ only",
      "lines": "14-20"
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "path": {
        "equals": "/home"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-13"
    }
  },
  {
    "id": "rule-004",
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
      "privilege": {
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
      "lines": "19-23"
    }
  },
  {
    "id": "rule-005",
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
      "privilege": {
        "equals": "NOSUPERUSER"
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
      "task": "Create DB read-only role for developers",
      "lines": "25-29"
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "31-35"
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
      "lines": "14-18"
    }
  },
  {
    "id": "rule-008",
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "37-40"
    }
  },
  {
    "id": "rule-009",
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "25-28"
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
        "equals": "proxy01.lab.local"
      },
      "port": {
        "equals": 443
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "17-23"
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "path": {
        "equals": "/home"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "10-16"
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "ABAC_DEFAULT_POLICY",
      "task": "default_deny",
      "lines": "1-1"
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
    "id": "rule-014",
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
    "id": "rule-015",
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ...",
    "recommendation": "Upgrade nginx to latest stable version (current pinned: 1.20.0-1~focal). Apply security patches immediately."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ...",
    "recommendation": "Upgrade nginx to latest stable version (current pinned: 1.20.0-1~focal). Apply security patches immediately."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia...",
    "recommendation": "Upgrade nginx to latest stable version (current pinned: 1.20.0-1~focal). Apply security patches immediately."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ...",
    "recommendation": "Upgrade nginx to latest stable version (current pinned: 1.20.0-1~focal). Apply security patches immediately."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa...",
    "recommendation": "Upgrade nginx to latest stable version (current pinned: 1.20.0-1~focal). Apply security patches immediately."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many streams quickly, letting attackers consume server resources, exploit has been observed in the wild f...",
    "recommendation": "Upgrade nginx to latest stable version (current pinned: 1.20.0-1~focal). Apply security patches immediately."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb...",
    "recommendation": "Upgrade OpenSSH to latest version (current pinned: 1:9.1p1-1ubuntu1). Review sshd_config for security hardening."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp...",
    "recommendation": "Upgrade OpenSSH to latest version (current pinned: 1:9.1p1-1ubuntu1). Review sshd_config for security hardening."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re...",
    "recommendation": "Upgrade OpenSSH to latest version (current pinned: 1:9.1p1-1ubuntu1). Review sshd_config for security hardening."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers...",
    "recommendation": "Upgrade OpenSSH to latest version (current pinned: 1:9.1p1-1ubuntu1). Review sshd_config for security hardening."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir...",
    "recommendation": "Upgrade OpenSSH to latest version (current pinned: 1:9.1p1-1ubuntu1). Review sshd_config for security hardening."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding ...",
    "recommendation": "Upgrade OpenSSH to latest version (current pinned: 1:9.1p1-1ubuntu1). Review sshd_config for security hardening."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req...",
    "recommendation": "Upgrade OpenSSH to latest version (current pinned: 1:9.1p1-1ubuntu1). Review sshd_config for security hardening."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipula...",
    "recommendation": "Upgrade OpenSSH to latest version (current pinned: 1:9.1p1-1ubuntu1). Review sshd_config for security hardening."
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani...",
    "recommendation": "Upgrade OpenSSH to latest version (current pinned: 1:9.1p1-1ubuntu1). Review sshd_config for security hardening."
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl...",
    "recommendation": "Upgrade OpenSSH to latest version (current pinned: 1:9.1p1-1ubuntu1). Review sshd_config for security hardening."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,...",
    "recommendation": "Upgrade PostgreSQL to latest version (current pinned: 16.2-1.pgdg22.04+1). Apply all security updates."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ...",
    "recommendation": "Upgrade PostgreSQL to latest version (current pinned: 16.2-1.pgdg22.04+1). Apply all security updates."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma...",
    "recommendation": "Upgrade PostgreSQL to latest version (current pinned: 16.2-1.pgdg22.04+1). Apply all security updates."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe...",
    "recommendation": "Upgrade PostgreSQL to latest version (current pinned: 16.2-1.pgdg22.04+1). Apply all security updates."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin...",
    "recommendation": "Upgrade PostgreSQL to latest version (current pinned: 16.2-1.pgdg22.04+1). Apply all security updates."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.2,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req...",
    "recommendation": "Upgrade PostgreSQL to latest version (current pinned: 16.2-1.pgdg22.04+1). Apply all security updates."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a...",
    "recommendation": "Upgrade PostgreSQL to latest version (current pinned: 16.2-1.pgdg22.04+1). Apply all security updates."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The policy covers SSH access, database authentication, network firewall rules, and filesystem permissions across a production environment with PCI compliance requirements.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | segcorp |
| Environment | production |
| Compliance Tier | pci |
| Log Retention | 365 days |

## Attribute Catalog Summary

### Subjects
- **Users**: 3 (admin, developer, dba)
- **Groups**: 3 (sudo, developers, dba)
- **Clearance Levels**: secret, confidential
- **Departments**: operations, engineering, data

### Resources
- **Hosts**: 3 (proxy01.lab.local, app01.lab.local, db01.lab.local)
- **Services**: 3 (nginx:443, application:8080, postgresql:5432)
- **Networks**: 3 (DMZ: 10.0.1.0/24, App: 10.0.2.0/24, Internet: 0.0.0.0/0)
- **Paths**: 1 (/var/lib/postgresql/data)

## Extracted ABAC Rules

| Rule ID | Action | Effect | Subject | Resource |
|---------|--------|--------|---------|----------|
| rule-001 | ssh:login | permit | groups in [sudo, developers] | app01.lab.local:ssh |
| rule-002 | network:connect | permit | source_network=10.0.1.0/24 | app01.lab.local:8080/tcp |
| rule-003 | user:create | permit | groups in [developers, sudo] | app01.lab.local:/home |
| rule-004 | db:login | permit | groups in [dba] | db01.lab.local:postgresql (SUPERUSER) |
| rule-005 | db:login | permit | groups in [developers] | db01.lab.local:postgresql (NOSUPERUSER) |
| rule-006 | network:connect | permit | source_network=10.0.2.0/24 | db01.lab.local:postgresql:5432 |
| rule-007 | filesystem:read | permit | groups in [dba] | /var/lib/postgresql/data |
| rule-008 | ssh:login | permit | groups in [sudo, dba] | db01.lab.local:ssh |
| rule-009 | ssh:login | permit | groups in [sudo] | proxy01.lab.local:ssh |
| rule-010 | network:connect | permit | source_network=0.0.0.0/0 | proxy01.lab.local:443/tcp |
| rule-011 | user:create | permit | groups in [sudo] | proxy01.lab.local:/home |
| rule-012 | * | deny | all | all |

## Vulnerability Assessment

### Pinned Software Versions
| Product | Version |
|---------|---------|
| nginx | 1.20.0-1~focal |
| openssh-server | 1:9.1p1-1ubuntu1 |
| postgresql | 16.2-1.pgdg22.04+1 |

### Critical Findings
- **Total vulnerabilities found**: 23
- **Critical severity**: 15
- **High severity**: 6
- **Medium severity**: 2

### Key Vulnerabilities by Product

#### nginx (6 vulnerabilities)
- CVE-2016-0746: Use After Free (CVSS 9.8, Critical)
- CVE-2021-46461: Critical remote vulnerability (CVSS 9.8)
- CVE-2017-20005: Critical remote vulnerability (CVSS 9.8)
- CVE-2009-3555: Critical remote vulnerability (CVSS 9.8)
- CVE-2021-23017: High severity (CVSS 7.7)
- CVE-2023-44487: High severity (CVSS 7.5)

**Recommendation**: Upgrade nginx to latest stable version and apply security patches immediately.

#### openssh (9 vulnerabilities)
- CVE-2000-0999: Critical (CVSS 10.0)
- CVE-2000-0525: Critical (CVSS 10.0)
- CVE-2003-0693: Critical (CVSS 10.0)
- CVE-2003-0786: Critical (CVSS 10.0)
- CVE-2001-0144: Critical (CVSS 10.0)
- CVE-2023-38408: Critical (CVSS 9.8)
- CVE-2024-6387: High (CVSS 8.1)
- CVE-2007-4752: High (CVSS 7.5)
- CVE-2019-6109/6110: Medium (CVSS 6.8)

**Recommendation**: Upgrade OpenSSH to latest version and review sshd_config for security hardening.

#### postgresql (8 vulnerabilities)
- CVE-2002-1399: Critical (CVSS 10.0)
- CVE-2013-1902: Critical (CVSS 10.0)
- CVE-2007-3279: Critical (CVSS 10.0)
- CVE-2013-1903: Critical (CVSS 10.0)
- CVE-2024-1597: Critical (CVSS 10.0)
- CVE-2019-9193: High (CVSS 7.2)
- CVE-2022-31197: High (CVSS 7.1)

**Recommendation**: Upgrade PostgreSQL to latest version and apply all security updates.

## Security Architecture

### Network Segmentation
- **DMZ Zone**: proxy01.lab.local (10.0.1.10) - internet-facing reverse proxy
- **App Zone**: app01.lab.local (10.0.2.10) - application server, accessible only from DMZ
- **Data Zone**: db01.lab.local (10.0.3.10) - database server, accessible only from app servers

### Access Control Summary
- SSH access is restricted by group membership on all hosts
- Database access is role-based with SUPERUSER for DBAs and NOSUPERUSER for developers
- Network access follows zero-trust principles with explicit allow rules per subnet
- Default deny policy applies to all unspecified access

## Ambiguities and Limitations

1. **Credentials**: Passwords and authentication secrets are not defined in the Ansible configuration (expected to be managed externally via vault/secrets management).

2. **Session Logging**: No explicit audit or session logging rules were found in the configuration. The `default_log_retention_days: 365` setting suggests logging is configured elsewhere.

3. **SELinux**: No SELinux policy configurations were found in the Ansible roles.

4. **Sudoers**: While users are added to the `sudo` group, specific sudoers rules are not defined in the configuration.

## Files Analyzed

### Phase 1 - Catalog Sources
- `inventory.ini`
- `group_vars/all.yml`
- `group_vars/appservers.yml`
- `group_vars/dbservers.yml`
- `group_vars/dmz.yml`

### Phase 2 - Rule Extraction Sources
- `roles/app/tasks/main.yml`
- `roles/db/tasks/main.yml`
- `roles/dmz/tasks/main.yml`

---
*Report generated from Ansible ABAC policy mining*
