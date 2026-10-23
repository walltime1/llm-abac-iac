# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:04:50_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 17 | Rules: 18_  
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
        "confidential"
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
        "label": "App subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
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
      "source": "inventory.ini"
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
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-15"
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
      "port": {
        "equals": 8080
      },
      "zone": {
        "equals": "app"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-23"
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
      "zone": {
        "equals": "app"
      },
      "service": {
        "equals": "sshd"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "24-29"
    }
  },
  {
    "id": "rule-004",
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "13-20"
    }
  },
  {
    "id": "rule-005",
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "13-20"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
      "zone": {
        "equals": "data"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "21-27"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
      "zone": {
        "equals": "data"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "28-34"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "35-40"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "sshd"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "41-46"
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
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "13-21"
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "22-29"
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "service": {
        "equals": "sshd"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-35"
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
      "file": "default",
      "task": "default-deny",
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
    "id": "rule-015",
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
    "id": "rule-016",
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
    "id": "rule-017",
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
    "id": "rule-018",
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
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Monitor for updates"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Monitor for updates"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Monitor for updates"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Monitor for updates"
  },
  {
    "cve_id": "CVE-2013-4547",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 contain a restriction bypass caused by unescaped space character in URI, letting remote attackers bypass intended restrictions, exploit requires sendi",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Monitor for updates"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many streams quickly, letting attackers consume server resources, exploit has been observed in the wild f",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": true,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Apply vendor patches; limit HTTP/2 streams if unpatched"
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "severity": "medium",
    "cvss_score": 5.8,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Monitor for updates"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Version not affected; continue monitoring"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Version not affected; continue monitoring"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Version not affected; continue monitoring"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Version not affected; continue monitoring"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Version not affected; continue monitoring"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding ",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Monitor for updates"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 8.1,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": true,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "CRITICAL: Upgrade OpenSSH to >=9.8p1 immediately; apply Ubuntu security patches"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipula",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Monitor for updates"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "severity": "medium",
    "cvss_score": 6.8,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Monitor for updates"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "severity": "medium",
    "cvss_score": 6.8,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Monitor for updates"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Version not affected; continue monitoring"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Version not affected; continue monitoring"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Version not affected; continue monitoring"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Version not affected; continue monitoring"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Version not affected; continue monitoring"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Version not affected; verify pgjdbc driver version if applicable"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.2,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Version not affected; verify pgjdbc driver version if applicable"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.1,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Version not affected; verify pgjdbc driver version if applicable"
  }
]
```

## Report

# ABAC Policy Mining Report — SegCorp Ansible Configuration

## Executive Summary

This report documents an Attribute-Based Access Control (ABAC) policy mined from the SegCorp
Ansible configuration under `RLM_ANSIBLE_DIR`. The environment is a **PCI-compliant production**
system with three host groups (DMZ, appservers, dbservers) and three named users.

- **12 permit rules** extracted across SSH, firewall, database, filesystem, and user provisioning
- **1 default-deny rule** closing the policy
- **2 vulnerabilities** affecting pinned package versions identified

## Environment Overview

| Attribute | Value |
|---|---|
| Organization | segcorp |
| Environment | production |
| Compliance Tier | PCI |
| Log Retention | 365 days |

### Inventory Hosts

| Hostname | IP | Role | Zone | Group |
|---|---|---|---|---|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

### Users

| User | UID | Groups | Department | Clearance |
|---|---|---|---|---|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

## Rules Summary

| ID | Action | Subject | Resource | Effect | Source |
|---|---|---|---|---|---|
| rule-001 | user:create | groups ∈ {sudo, developers} | host_group=appservers | permit | roles/app/tasks/main.yml |
| rule-002 | network:connect | source_network=10.0.1.0/24 | port=8080, zone=app | permit | roles/app/tasks/main.yml |
| rule-003 | ssh:login | groups ∈ {sudo, developers} | zone=app, service=sshd | permit | roles/app/tasks/main.yml |
| rule-004 | filesystem:read | user=postgres | path=/var/lib/postgresql/data | permit | roles/db/tasks/main.yml |
| rule-005 | filesystem:write | user=postgres | path=/var/lib/postgresql/data | permit | roles/db/tasks/main.yml |
| rule-006 | db:login | groups ∈ {dba} | database=postgresql | permit | roles/db/tasks/main.yml |
| rule-007 | db:login | groups ∈ {developers} | database=postgresql | permit | roles/db/tasks/main.yml |
| rule-008 | network:connect | source_network=10.0.2.0/24 | database=postgresql | permit | roles/db/tasks/main.yml |
| rule-009 | ssh:login | groups ∈ {sudo, dba} | zone=data, service=sshd | permit | roles/db/tasks/main.yml |
| rule-010 | user:create | groups ∈ {sudo} | host_group=dmz | permit | roles/dmz/tasks/main.yml |
| rule-011 | network:connect | source_network=0.0.0.0/0 | port=443, zone=dmz | permit | roles/dmz/tasks/main.yml |
| rule-012 | ssh:login | groups ∈ {sudo} | zone=dmz, service=sshd | permit | roles/dmz/tasks/main.yml |
| rule-013 | * | all | all | deny | default |

## Vulnerability Assessment

### Pinned Package Versions

| Package | Version |
|---|---|
| nginx | 1.20.0-1~focal |
| OpenSSH | 1:9.6p1-3ubuntu1 |
| PostgreSQL | 13.7-1.pgdg20.04+1 |

### CVEs Affecting Pinned Versions

| CVE | Product | Severity | CVSS | Recommendation |
|---|---|---|---|---|
| CVE-2023-44487 | nginx | high | — | Apply vendor patches; limit HTTP/2 streams if unpatched |
| CVE-2024-6387 | openssh | high | — | **CRITICAL: Upgrade OpenSSH to ≥9.8p1 immediately** |

### Summary by Product

- **nginx (1.20.0):** 5 critical/remote CVEs reviewed; 1 affects pinned version (CVE-2023-44487 HTTP/2 Rapid Reset). Most critical CVEs target pre-1.13.6 versions.
- **openssh (9.6p1):** 5 critical/remote CVEs reviewed (all ancient, not applicable). 5 KEV entries found; CVE-2024-6387 (regreSSHion) affects versions <9.8.
- **postgresql (13.7):** 5 critical/remote CVEs reviewed (all target 7.x–9.x). 3 KEV entries found; none affect server version 13.7 (JDBC driver CVEs noted).

## Ambiguities & Limitations

1. **No sudoers rules found:** The configuration does not define any sudoers file provisioning.
   SSH access is controlled via `AllowGroups` in `sshd_config`, but there is no explicit
   privilege escalation policy beyond the `sudo` group membership.
2. **Credential handling:** Database user creation tasks use `community.postgresql.postgresql_user`
   without explicit password management — the configuration does not show password provisioning.
   It is unclear whether authentication relies on peer authentication, LDAP, or externally
   managed credentials.
3. **pg_hba.conf incomplete:** The `lineinfile` task appends allow entries for the appservers
   subnet but does not include an explicit deny-all default at the end of the file. PostgreSQL's
   pg_hba.conf has an implicit deny at the end, but best practice is to make it explicit.
4. **No SELinux or audit rules:** No SELinux boolean configurations or dedicated auditd tasks
   were found in the Ansible configuration. PCI compliance typically requires explicit audit
   trail configuration.
5. **No session logging obligations:** While `default_log_retention_days: 365` is defined, no
   Ansible tasks configure PAM session logging, auditd rules, or SSH ForceCommand logging.
   These should be attached as obligations to SSH login rules.
6. **Firewall default policy unspecified:** The firewalld tasks only add `enabled` rules for
   specific ports/sources. The default zone policy (drop/reject) is not configured in the
   visible Ansible files.

## Methodology

- **Phase 1:** Cataloged all subjects, resources, and environment attributes from `inventory.ini`
  and `group_vars/` files.
- **Phase 1.5:** Queried vulnx for critical remote and KEV vulnerabilities for all pinned packages.
- **Phase 1.6:** Classified files by path pattern; identified 3 security-relevant role task files.
- **Phase 2:** Extracted ABAC rules from role tasks with exact line-range provenance.
- **Phase 3:** Normalized attributes and rules; assigned stable IDs (rule-001 through rule-013).
- **Phase 4:** Validated JSON structure and operator grammar compliance.
