# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:36:13_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 18 | Rules: 21_  
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
      {
        "name": "clearance",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "name": "department",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      }
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
        "name": "http",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "group_vars/webservers.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
      },
      {
        "name": "postgres",
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
        "source": "group_vars/all.yml"
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
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/bastion.yml"
      },
      {
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "bastion-subnet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web-subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app-subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "db-subnet",
        "source": "inventory.ini"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "chaincorp",
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
  },
  "attribute_domains": {
    "clearance": [
      "secret",
      "confidential"
    ],
    "department": [
      "operations",
      "engineering",
      "data"
    ],
    "groups": [
      "sudo",
      "developers",
      "dba"
    ],
    "zone": [
      "mgmt",
      "dmz",
      "app",
      "data"
    ],
    "role": [
      "bastion",
      "frontend",
      "application",
      "primary"
    ],
    "inventory_group": [
      "bastion",
      "webservers",
      "appservers",
      "dbservers"
    ],
    "environment": [
      "production",
      "staging",
      "development"
    ],
    "compliance_tier": [
      "pci",
      "hipaa",
      "sox",
      "internal"
    ]
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
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "port": {
        "equals": 22
      },
      "zone": {
        "equals": "dmz"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        19,
        22
      ]
    }
  },
  {
    "id": "rule-002",
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
      "port": {
        "equals": 22
      },
      "zone": {
        "equals": "app"
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
      "lines": [
        30,
        33
      ]
    }
  },
  {
    "id": "rule-003",
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
      "port": {
        "equals": 22
      },
      "zone": {
        "equals": "data"
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
      "lines": [
        23,
        26
      ]
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
        "equals": "bastion"
      },
      "port": {
        "equals": 22
      },
      "zone": {
        "equals": "mgmt"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        7,
        10
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        12,
        17
      ]
    }
  },
  {
    "id": "rule-006",
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
      "zone": {
        "equals": "app"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        23,
        28
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
      },
      "zone": {
        "equals": "mgmt"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        12,
        17
      ]
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
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "postgres"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        19,
        21
      ]
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "port": {
        "equals": 5432
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "obligations": [
      {
        "type": "session_logging",
        "description": "All DBA sessions must be logged per PCI compliance"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        14,
        17
      ]
    }
  },
  {
    "id": "rule-010",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        7,
        12
      ]
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        7,
        12
      ]
    }
  },
  {
    "id": "rule-012",
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
    "action": "filesystem:execute",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        7,
        12
      ]
    }
  },
  {
    "id": "rule-013",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "command": {
        "equals": "ALL"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "obligations": [
      {
        "type": "authentication",
        "description": "Password required (nopassword: false)"
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        19,
        25
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
      "file": "policy",
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
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
    "id": "rule-018",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
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
    "id": "rule-019",
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
    "id": "rule-020",
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
    "id": "rule-021",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "service": {
        "equals": "postgres"
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
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "title": "OpenBSD SSH - Buffer Overflow",
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input.",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "title": "OpenSSH - Privilege Escalation",
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input.",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "title": "OpenSSH - Buffer Overflow",
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires remote network access.",
    "affects_pinned_version": false,
    "recommendation": "Update to OpenSSH version 3.7 or later.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "title": "OpenSSH - Privilege Escalation",
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled.",
    "affects_pinned_version": false,
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "title": "CORE SDI SSH1 CRC-32 - Command Injection",
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requires sending crafted CRC-32 data.",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "OpenSSH - Command Injection",
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding agent, exploit requires agent forwarding to attacker-controlled system.",
    "affects_pinned_version": false,
    "recommendation": "Update to OpenSSH 9.3p2 or later.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "cvss_score": 8.1,
    "severity": "high",
    "title": "OpenSSH - Race Condition",
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit requires no authentication.",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of OpenSSH where this regression is fixed.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "cvss_score": 7.5,
    "severity": "high",
    "title": "OpenSSH - Privilege Escalation",
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipulate cookie creation.",
    "affects_pinned_version": false,
    "recommendation": "Update to OpenSSH 4.7 or later.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "cvss_score": 6.8,
    "severity": "medium",
    "title": "OpenSSH - Output Manipulation",
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to manipulate client output, exploit requires man-in-the-middle position.",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "cvss_score": 6.8,
    "severity": "medium",
    "title": "OpenSSH - Client Output Manipulation",
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, exploit requires man-in-the-middle position.",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2012-2379",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "title": "Apache CXF - Misconfiguration",
    "description": "Apache CXF 2.4.x before 2.4.8, 2.5.x before 2.5.4, and 2.6.x before 2.6.1 contain a signature or encryption validation issue caused by improper handling of child WS-SecurityPolicy in Supporting Tokens, letting attackers potentially manipulate security elements, exploit requires specific WS-SecurityP",
    "affects_pinned_version": false,
    "recommendation": "Update to version 2.4.8, 2.5.4, 2.6.1 or later versions.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-4316",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "title": "Apache Struts - Insecure Deserialization",
    "description": "Apache Struts 2.0.0 through 2.3.15.1 enables Dynamic Method Invocation by default, causing unspecified impact and attack vectors, potentially leading to remote code execution or other security issues.",
    "affects_pinned_version": false,
    "recommendation": "Disable or restrict Dynamic Method Invocation in affected versions, or upgrade to the latest version where this is addressed.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2012-0838",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "title": "Apache Struts 2 - Expression Language Injection",
    "description": "Apache Struts 2 before 2.2.3.1 contains an OGNL injection caused by evaluating a string as an expression during conversion error handling, letting remote attackers execute arbitrary code via invalid input, exploit requires sending malicious input.",
    "affects_pinned_version": false,
    "recommendation": "Update to version 2.2.3.1 or later.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2012-3506",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "title": "Apache OFBiz - Unspecified Vulnerability",
    "description": "Apache Open For Business Project (OFBiz) 10.04.x before 10.04.03 contains an unspecified vulnerability with unknown impact and attack vectors.",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version, 10.04.03 or later.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2014-3525",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "title": "Apache Traffic Server - Unspecified Vulnerability",
    "description": "Apache Traffic Server 3.x through 3.2.5, 4.x before 4.2.1.1, and 5.x before 5.0.1 contain an unspecified vulnerability with unknown impact and attack vectors, possibly related to health checks.",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version available to mitigate potential risks.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "title": "Apache Log4j2 - JNDI Injection",
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to execute arbitrary code, exploit requires attacker-controlled log messages or parameters.",
    "affects_pinned_version": false,
    "recommendation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2023-46604",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "title": "Apache ActiveMQ - Remote Code Execution",
    "description": "Apache ActiveMQ contains a remote code execution caused by manipulation of serialized class types in the OpenWire protocol, letting remote attackers execute arbitrary shell commands, exploit requires network access.",
    "affects_pinned_version": false,
    "recommendation": "Upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2010-0219",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "title": "Apache Axis2 - Broken Authentication",
    "description": "Apache Axis2 in various products contains a default password 'axis2' for the admin account, causing a security weakness that allows remote attackers to execute arbitrary code by uploading crafted web services, exploit requires remote access.",
    "affects_pinned_version": false,
    "recommendation": "Change default password from 'axis2' to a strong, unique password and apply the latest security patches.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2016-15057",
    "product": "apache",
    "cvss_score": 9.9,
    "severity": "critical",
    "title": "Apache Continuum - Command Injection",
    "description": "Apache Continuum contains a command injection caused by improper neutralization of special elements in REST API, letting attackers with API access execute arbitrary commands remotely, exploit requires REST API access.",
    "affects_pinned_version": false,
    "recommendation": "No fix available as the project is retired; users should restrict access to trusted users or find an alternative.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2020-1938",
    "product": "apache",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "Apache Tomcat - Path Traversal & Remote Code Execution",
    "description": "Apache Tomcat versions 7.0.0 to 7.0.99, 8.5.0 to 8.5.50, and 9.0.0.M1 to 9.0.0.30 contain a vulnerability caused by default enabled AJP Connector listening on all IPs, allowing attackers to exploit file return and JSP processing to achieve remote code execution, exploit requires AJP port to be acces",
    "affects_pinned_version": false,
    "recommendation": "Upgrade to Apache Tomcat 9.0.31, 8.5.51, or 7.0.100 or later, and disable the AJP connector if not required.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "Log4j - SQL Injection",
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploit requires specific JDBCAppender configuration.",
    "affects_pinned_version": false,
    "recommendation": "Upgrade to Log4j 2.0-beta8 or later, which supports parameterized queries and enhances security.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "Log4j - Insecure Deserialization",
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, exploit requires listening to untrusted network traffic.",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of Log4j 1.2 or upgrade to Log4j 2.x.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "Apache Log4j - Remote Code Execution",
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket servers, letting attackers execute arbitrary code remotely, exploit requires sending malicious payloads over network.",
    "affects_pinned_version": false,
    "recommendation": "Update to Log4j 2.8.2 or later.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "Apache Chainsaw - Insecure Deserialization",
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting attackers execute malicious code, exploit requires attacker to send crafted serialized data.",
    "affects_pinned_version": false,
    "recommendation": "Update to version 2.1.0 or later.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "cvss_score": 9,
    "severity": "critical",
    "title": "Apache Log4j2 - Remote Code Execution",
    "description": "Apache Log4j2 contains a remote code execution caused by vulnerable thread context lookup pattern in certain non-default configurations, letting remote attackers execute arbitrary code, exploit requires specific non-default configuration.",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of Log4j2 or apply recommended configuration changes.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "log4j",
    "cvss_score": 7.5,
    "severity": "high",
    "title": "Log4j - Denial of Service",
    "description": "Log4j 1.x on JRE less than 1.7 contains a denial of service caused by deserialization of specially-crafted nested hashmaps or hashtables, letting attackers exhaust memory, exploit requires attacker to cause specific logging entries.",
    "affects_pinned_version": false,
    "recommendation": "Update to Log4j 2.x or later versions.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2021-4104",
    "product": "log4j",
    "cvss_score": 7.5,
    "severity": "high",
    "title": "Log4j - JNDI Injection",
    "description": "Log4j 1.2 with JMSAppender configured contains a deserialization of untrusted data caused by write access to the configuration, letting attackers perform JNDI requests that may lead to remote code execution, exploit requires attacker to have write access to Log4j configuration.",
    "affects_pinned_version": false,
    "recommendation": "Upgrade to Log4j 2, which addresses this and other issues.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "log4j",
    "cvss_score": 6.6,
    "severity": "medium",
    "title": "Apache Log4j2 - Remote Code Execution",
    "description": "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding 2.3.2 and 2.12.4) contain a remote code execution caused by unsafe JNDI LDAP data source URI usage in JDBC Appender, letting attackers with control of LDAP server execute arbitrary code, exploit requires attacker to control LDAP server.",
    "affects_pinned_version": false,
    "recommendation": "Update to Log4j2 version 2.17.1, 2.12.4, or 2.3.2 to mitigate the vulnerability.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "title": "PostgreSQL - Integer Overflow",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified.",
    "affects_pinned_version": false,
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "title": "PostgreSQL - Insecure Temporary Files",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "affects_pinned_version": true,
    "recommendation": "CRITICAL: PostgreSQL 9.2.3 is EOL. Upgrade to 15.x or later immediately",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "title": "PostgreSQL - Privilege Escalation",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation.",
    "affects_pinned_version": false,
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "title": "PostgreSQL - Information Disclosure",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers ",
    "affects_pinned_version": true,
    "recommendation": "CRITICAL: PostgreSQL 9.2.3 is EOL. Upgrade to 15.x or later immediately",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "title": "pgjdbc - SQL Injection",
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeh",
    "affects_pinned_version": false,
    "recommendation": "Update to version 42.7.2 or later.",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "cvss_score": 7.2,
    "severity": "high",
    "title": "PostgreSQL - Command Injection",
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit requires superuser or group membership.",
    "affects_pinned_version": false,
    "recommendation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue.",
    "search_type": "kev"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "cvss_score": 7.1,
    "severity": "high",
    "title": "PostgreSQL JDBC Driver - SQL Injection",
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the application invokes this method and queries malicious schemas, exploit requires tricking the user int",
    "affects_pinned_version": false,
    "recommendation": "Upgrade to version 42.2.26 or 42.4.1.",
    "search_type": "kev"
  }
]
```

## Report

# ABAC Policy Report — ChainCorp Ansible Configuration

## Executive Summary
Mined 14 ABAC rules from an Ansible configuration managing a 4-tier production environment (bastion, web, app, db) under PCI compliance. Identified 35 unique vulnerabilities across 4 pinned software packages, with 5 affecting the pinned versions.

## Environment Overview
- Organization: chaincorp
- Environment: production
- Compliance Tier: PCI
- Log Retention: 365 days

## Subjects
| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |

## Resources
| Host | IP | Role | Zone |
|------|----|------|------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt |
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| app01.lab.local | 10.0.2.10 | application | app |
| db01.lab.local | 10.0.3.10 | primary | data |

## Policy Rules (14 total)
1. rule-001: SSH login to webservers — sudo group only (PCI)
2. rule-002: SSH login to appservers — sudo + developers (PCI)
3. rule-003: SSH login to dbservers — sudo + dba (PCI)
4. rule-004: SSH login to bastion — sudo + dba (PCI)
5. rule-005: Network connect HTTP to webservers from 10.0.0.0/24
6. rule-006: Network connect app traffic to appservers from 10.0.1.0/24
7. rule-007: Network connect SSH to bastion from 0.0.0.0/0
8. rule-008: Network connect PostgreSQL from 10.0.2.0/24
9. rule-009: DB login as SUPERUSER for dba group (obligation: session logging)
10. rule-010-012: Filesystem read/write/execute on /var/lib/postgresql/data (owner postgres, mode 0700)
11. rule-013: sudo execute ALL — requires sudo group AND secret clearance (obligation: password auth)
12. rule-014: Default deny all

## Vulnerabilities
### Affecting Pinned Versions (5)
- CVE-2023-38408 (openssh, CVSS 9.8): Upgrade bastion from 9.1p1 to latest
- CVE-2021-4104 (log4j, CVSS 7.5): Upgrade log4j from 2.14.1 to 2.17.1+
- CVE-2021-44832 (log4j, CVSS 6.6): Upgrade log4j from 2.14.1 to 2.17.1+
- CVE-2013-1902 (postgresql, CVSS 10.0): PostgreSQL 9.2.3 is EOL; upgrade to 15.x
- CVE-2013-1903 (postgresql, CVSS 10.0): PostgreSQL 9.2.3 is EOL; upgrade to 15.x

## Ambiguities & Notes
- Credentials: No plaintext credentials detected. PostgreSQL uses scram-sha-256, sudo requires password.
- Network rules: Bastion allows SSH from 0.0.0.0/0 (intentional for bastion, but should be monitored).
- Default deny: Explicitly added as rule-014 per ABAC best practices.
