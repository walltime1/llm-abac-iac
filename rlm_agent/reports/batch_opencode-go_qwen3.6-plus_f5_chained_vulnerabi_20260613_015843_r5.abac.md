# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 02:07:55_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 15 | Rules: 19_  
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
    ],
    "groups": {
      "values": [
        "sudo",
        "developers",
        "dba"
      ],
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "values": [
        "secret",
        "confidential"
      ],
      "domain": [
        "secret",
        "confidential",
        "top_secret",
        "public"
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
    ],
    "host_groups": {
      "values": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers"
      ],
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "services": [
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "bastion"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "appservers"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "dbservers"
      },
      {
        "name": "http",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers"
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
      }
    ],
    "ports": {
      "values": [
        22,
        80,
        8080,
        5432
      ],
      "domain": [
        22,
        80,
        443,
        8080,
        5432
      ],
      "source": "group_vars/webservers.yml,group_vars/appservers.yml,group_vars/dbservers.yml"
    },
    "paths": [
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql"
      }
    ],
    "zones": {
      "values": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data",
        "external"
      ],
      "source": "inventory.ini"
    }
  },
  "environment": {
    "org": "chaincorp",
    "environment": "production",
    "compliance_tier": "pci",
    "log_retention_days": 365
  }
}
```

## Rules

```json
[
  {
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "appservers"
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
        31,
        35
      ]
    },
    "id": "rule-001"
  },
  {
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "bastion"
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
        12
      ]
    },
    "id": "rule-002"
  },
  {
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "webservers"
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
        21,
        25
      ]
    },
    "id": "rule-003"
  },
  {
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "dbservers"
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
        29,
        33
      ]
    },
    "id": "rule-004"
  },
  {
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
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        22,
        29
      ]
    },
    "id": "rule-005"
  },
  {
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
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
        23,
        29
      ]
    },
    "id": "rule-006"
  },
  {
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "bastion"
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
        14,
        20
      ]
    },
    "id": "rule-007"
  },
  {
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
      },
      "host_group": {
        "equals": "webservers"
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
        13,
        19
      ]
    },
    "id": "rule-008"
  },
  {
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
      "schema": {
        "equals": "all"
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
        16,
        21
      ]
    },
    "id": "rule-009"
  },
  {
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
        23,
        27
      ]
    },
    "id": "rule-010"
  },
  {
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
      ]
    },
    "id": "rule-011"
  },
  {
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
      ]
    },
    "id": "rule-012"
  },
  {
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "policy",
      "task": "default-deny",
      "lines": [
        0,
        0
      ]
    },
    "id": "rule-013"
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
    "id": "rule-016",
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
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "bastion"
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
    "id": "rule-018",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
      },
      "host_group": {
        "equals": "webservers"
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
    "id": "rule-019",
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
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 9.1p1 to latest stable version"
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentica",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 9.1p1 to latest stable version"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 9.1p1 to latest stable version"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 9.1p1 to latest stable version"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 9.1p1 to latest stable version"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding ",
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV - Upgrade openssh from 9.1p1 to latest stable version"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "high",
    "cvss_score": 8.1,
    "is_kev": true,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req",
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV - Upgrade openssh from 9.1p1 to latest stable version"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipula",
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV - Upgrade openssh from 9.1p1 to latest stable version"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl",
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV - Upgrade openssh from 9.1p1 to latest stable version"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani",
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV - Upgrade openssh from 9.1p1 to latest stable version"
  },
  {
    "cve_id": "CVE-2003-0789",
    "product": "apache",
    "pinned_version": "2.4.49",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "Apache before 2.0.48 with threaded MPM contains a CGI redirect path handling issue caused by improper handling in mod_cgid, letting Apache send CGI output to the wrong client, exploit requires specifi",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49 to latest stable version"
  },
  {
    "cve_id": "CVE-1999-1237",
    "product": "apache",
    "pinned_version": "2.4.49",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "Multiple buffer overflows in smbvalid/smbval SMB authentication library used in Apache::AuthenSmb allow remote attackers to execute arbitrary commands via long username, long password, and other metho",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49 to latest stable version"
  },
  {
    "cve_id": "CVE-1999-1293",
    "product": "apache",
    "pinned_version": "2.4.49",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "Apache 1.2.5 and earlier contains a denial of service caused by malformed FTP commands in mod_proxy, letting remote attackers cause Apache to dump core, exploit requires sending malformed FTP commands",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49 to latest stable version"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to e",
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest stable version"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket servers, letting attackers execute arbitrary code rem",
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest stable version"
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting attackers execute malicious code, exploit requires attacker to send crafted seriali",
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest stable version"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploit requires specific JDBCAppender configuration.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest stable version"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, explo",
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest stable version"
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9,
    "is_kev": true,
    "description": "Apache Log4j2 contains a remote code execution caused by vulnerable thread context lookup pattern in certain non-default configurations, letting remote attackers execute arbitrary code, exploit requir",
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV - Upgrade log4j from 2.14.1 to latest stable version"
  },
  {
    "cve_id": "CVE-2021-4104",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "description": "Log4j 1.2 with JMSAppender configured contains a deserialization of untrusted data caused by write access to the configuration, letting attackers perform JNDI requests that may lead to remote code exe",
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV - Upgrade log4j from 2.14.1 to latest stable version"
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "description": "Log4j 1.x on JRE less than 1.7 contains a denial of service caused by deserialization of specially-crafted nested hashmaps or hashtables, letting attackers exhaust memory, exploit requires attacker to",
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV - Upgrade log4j from 2.14.1 to latest stable version"
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "medium",
    "cvss_score": 6.6,
    "is_kev": true,
    "description": "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding 2.3.2 and 2.12.4) contain a remote code execution caused by unsafe JNDI LDAP data source URI usage in JDBC Appender, letting attackers with c",
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV - Upgrade log4j from 2.14.1 to latest stable version"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 9.2.3 to latest stable version"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 9.2.3 to latest stable version"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 9.2.3 to latest stable version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 9.2.3 to latest stable version"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 9.2.3 to latest stable version"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "high",
    "cvss_score": 7.2,
    "is_kev": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV - Upgrade postgresql from 9.2.3 to latest stable version"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "high",
    "cvss_score": 7.1,
    "is_kev": true,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV - Upgrade postgresql from 9.2.3 to latest stable version"
  }
]
```

## Report

# ABAC Policy Report — ChainCorp Production (PCI)

## Executive Summary

Mined an Attribute-Based Access Control (ABAC) policy from the Ansible configuration at `$RLM_ANSIBLE_DIR`.
The infrastructure consists of 4 hosts across 4 zones (mgmt, dmz, app, data) in the `production` environment
with PCI compliance tier. 3 users are defined across 3 groups (sudo, developers, dba).

**Policy statistics:**
- 13 total rules (12 permit + 1 default-deny)
- 4 SSH login rules (one per host group)
- 1 sudo:execute rule (bastion, secret clearance required)
- 3 network:connect firewall rules
- 1 database login rule (postgresql, DBA group)
- 2 filesystem ACL rules (postgres data dir, read + write)
- 29 vulnerabilities identified across pinned packages

## Subjects

| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

**Groups:** sudo, developers, dba
**Clearance levels:** secret, confidential

## Resources

**Hosts:**
| Hostname | IP | Role | Zone | Group |
|----------|----|------|------|-------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt | bastion |
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

**Services:** ssh:22, http:80, app:8080, postgresql:5432

## Security Rules Summary

### SSH Access (ssh:login)
- **Appservers:** groups sudo, developers
- **Bastion:** groups sudo, dba
- **Webservers:** group sudo only
- **Dbservers:** groups sudo, dba

### Privilege Escalation (sudo:execute)
- **Bastion:** groups sudo AND clearance=secret (nopassword=false)

### Network Access (network:connect)
- **Appservers (8080/tcp):** from 10.0.1.0/24 (web subnet)
- **Bastion (22/tcp):** from 0.0.0.0/0 (internet — HIGH RISK)
- **Webservers (80/tcp):** from 10.0.0.0/24 (bastion subnet)
- **Dbservers (5432/tcp):** from 10.0.2.0/24 (app subnet)

### Database Access (db:login)
- **PostgreSQL:** group dba, SUPERUSER role, all schemas

### Filesystem ACL
- **/var/lib/postgresql/data:** owner=postgres, group=postgres, mode=0700

### Default Deny
- Catch-all deny for all subjects/resources/actions in production environment

## Vulnerability Assessment

### Pinned Package Versions
| Package | Version | Risk |
|---------|---------|------|
| openssh-server (bastion) | 9.1p1 | CRITICAL — CVE-2024-6387 (regreSSHion, KEV) |
| openssh-server (others) | 9.9p1 | Lower risk but still monitored |
| apache2 | 2.4.49 | CRITICAL — multiple CVEs |
| log4j-core | 2.14.1 | CRITICAL — CVE-2021-44228 (Log4Shell), CVE-2021-45046 (KEV) |
| postgresql | 9.2.3 | CRITICAL — multiple CVEs including KEV |

### Critical Findings
- **CVE-2024-6387 (OpenSSH regreSSHion):** CVSS 8.1, KEV. Affects bastion running 9.1p1. Remote RCE.
- **CVE-2023-38408 (OpenSSH pkcs11):** CVSS 9.8, KEV. Remote code execution via agent forwarding.
- **CVE-2021-44228 (Log4Shell):** CVSS 10. RCE via JNDI lookup. Affects log4j 2.14.1 on appservers.
- **CVE-2021-45046 (Log4j):** CVSS 9.0, KEV. Incomplete fix for Log4Shell.
- **Bastion SSH open to internet (0.0.0.0/0):** Combined with vulnerable OpenSSH, this is a critical exposure.

## Ambiguities & Observations

1. **Hardcoded SSH groups in db role:** The `roles/db/tasks/main.yml` task "Restrict SSH to sudo and dba groups" uses a literal string `AllowGroups sudo dba` instead of the `allowed_ssh_groups` variable used by other roles. This may indicate a deliberate override or an oversight.

2. **No explicit SSH DENY rules:** The `AllowGroups` directive implicitly denies all other groups. This implicit deny is captured as the default-deny rule, but no explicit deny rules for non-allowed groups were emitted.

3. **Filesystem ACL scope:** The postgres data directory rule (mode 0700) is emitted with `applies_to: all` for the subject condition. The actual effective access is limited to the `postgres` OS user (owner) and group members, but the ABAC catalog does not enumerate OS-level users as subjects — only the Ansible `users` list.

4. **No HTTPS/443 rule:** The webservers group only exposes HTTP (port 80). No TLS termination or HTTPS rule was found in the configuration.

5. **Credentials in configuration:** The Ansible configuration references user creation and database roles but does not explicitly handle password/credential provisioning in the visible task files. Credential management (vault, secrets manager) should be verified outside this policy scope.

6. **Session logging obligations:** No audit logging or session recording tasks were found in the role files. For a PCI environment, session logging should be attached as obligations to the SSH and sudo rules.

## Recommendations

1. **IMMEDIATE:** Upgrade OpenSSH on bastion from 9.1p1 to ≥ 9.8p1 to mitigate regreSSHion (CVE-2024-6387).
2. **IMMEDIATE:** Replace Log4j 2.14.1 with ≥ 2.17.1 on appservers.
3. **IMMEDIATE:** Upgrade PostgreSQL from 9.2.3 to a supported version (≥ 16.x).
4. **HIGH:** Restrict bastion SSH firewall from 0.0.0.0/0 to known management CIDRs.
5. **MEDIUM:** Add explicit deny rules for non-allowed SSH groups per host for clarity.
6. **MEDIUM:** Attach session logging obligations to all SSH login and sudo execute rules.
7. **LOW:** Standardize the db role to use `allowed_ssh_groups` variable instead of hardcoded groups.
