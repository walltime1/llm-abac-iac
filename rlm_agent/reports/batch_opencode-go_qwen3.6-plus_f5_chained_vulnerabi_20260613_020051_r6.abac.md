# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 02:10:11_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 16 | Rules: 17_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
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
    {
      "name": "sudo",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "developers",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "dba",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    }
  ],
  "clearance_levels": [
    {
      "value": "secret",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "value": "confidential",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    }
  ],
  "departments": [
    {
      "name": "operations",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "engineering",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "name": "data",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    }
  ],
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
      "name": "ssh",
      "port": 22,
      "protocol": "tcp",
      "host_group": "bastion,webservers,appservers,dbservers",
      "source": "group_vars/all.yml"
    },
    {
      "name": "postgres",
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
      "cidr": "0.0.0.0/0",
      "zone": "internet",
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
    }
  ],
  "environment": [
    {
      "org": "chaincorp",
      "source": "group_vars/all.yml"
    },
    {
      "compliance_tier": "pci",
      "domain": [
        "pci",
        "hipaa",
        "sox",
        "gdpr"
      ],
      "source": "group_vars/all.yml"
    },
    {
      "environment": "production",
      "domain": [
        "production",
        "staging",
        "development"
      ],
      "source": "inventory.ini"
    },
    {
      "default_log_retention_days": 365,
      "source": "group_vars/all.yml"
    }
  ]
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
      "hostname": {
        "equals": "bastion01.lab.local"
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
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        7,
        11
      ]
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
      "hostname": {
        "equals": "web01.lab.local"
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
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        17,
        21
      ]
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
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        25,
        29
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
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        28,
        33
      ]
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
      "hostname": {
        "equals": "bastion01.lab.local"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        21,
        28
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "description": "Sudo sessions must be logged"
      }
    ]
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      },
      "zone": {
        "equals": "mgmt"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        13,
        19
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        9,
        15
      ]
    }
  },
  {
    "id": "rule-008",
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
        "equals": "app"
      },
      "port": {
        "equals": 8080
      },
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        17,
        23
      ]
    }
  },
  {
    "id": "rule-009",
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
        "equals": "postgres"
      },
      "port": {
        "equals": 5432
      },
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        22,
        26
      ]
    }
  },
  {
    "id": "rule-010",
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
        "equals": "postgres"
      },
      "database": {
        "equals": "all"
      },
      "schema": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        14,
        20
      ]
    },
    "obligations": [
      {
        "type": "privilege",
        "level": "SUPERUSER"
      }
    ]
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
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
      "file": "implicit",
      "task": "default-deny",
      "lines": [
        0,
        0
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
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
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
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
        "equals": "http"
      },
      "port": {
        "equals": 80
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
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
        "equals": "postgres"
      },
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      },
      "org": {
        "equals": "chaincorp"
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
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper hand",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2000-0999 for openssh. Current pinned: 9.1p1. Update to the latest version of OpenBSD or apply security patches addressing format string issues.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "severity": "critical",
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge res",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2002-0640 for openssh. Current pinned: 9.1p1. Update to the latest version of OpenSSH that addresses this vulnerability.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge respons",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2003-0786 for openssh. Current pinned: 9.1p1. Update to a version where this issue is fixed, or enable Privilege Separation.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2003-0693 for openssh. Current pinned: 9.1p1. Update to OpenSSH version 3.7 or later.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2000-0525 for openssh. Current pinned: 9.1p1. Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "severity": "critical",
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2023-38408 for openssh. Current pinned: 9.1p1. Update to OpenSSH 9.3p2 or later.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "severity": "high",
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attac",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2024-6387 for openssh. Current pinned: 9.1p1. Update to the latest version of OpenSSH where this regression is fixed.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "severity": "high",
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers c",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2007-4752 for openssh. Current pinned: 9.1p1. Update to OpenSSH 4.7 or later.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "severity": "medium",
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2019-6110 for openssh. Current pinned: 9.1p1. Update to the latest version of OpenSSH where this issue is fixed.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "severity": "medium",
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, let",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2019-6109 for openssh. Current pinned: 9.1p1. Update to the latest version of OpenSSH where this issue is fixed.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "severity": "critical",
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messag",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2021-44228 for log4j. Current pinned: 2.14.1. Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "severity": "critical",
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads rece",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2017-5645 for log4j. Current pinned: 2.14.1. Update to Log4j 2.8.2 or later.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "severity": "critical",
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting att",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2020-9493 for log4j. Current pinned: 2.14.1. Update to version 2.1.0 or later.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "severity": "critical",
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries vi",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2022-23305 for log4j. Current pinned: 2.14.1. Upgrade to Log4j 2.0-beta8 or later, which supports parameterized queries and enhances security.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "severity": "critical",
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execut",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2019-17571 for log4j. Current pinned: 2.14.1. Update to the latest version of Log4j 1.2 or upgrade to Log4j 2.x.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by proce",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2002-1399 for postgresql. Current pinned: 9.2.3. Update to PostgreSQL 7.2.3 or later versions where the issue is addressed.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2007-3279 for postgresql. Current pinned: 9.2.3. Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injecti",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2024-1597 for postgresql. Current pinned: 9.2.3. Update to version 42.7.2 or later.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2013-1903 for postgresql. Current pinned: 9.2.3. Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable f",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2013-1902 for postgresql. Current pinned: 9.2.3. Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "severity": "high",
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, le",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2019-9193 for postgresql. Current pinned: 9.2.3. Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "severity": "high",
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in th",
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2022-31197 for postgresql. Current pinned: 9.2.3. Upgrade to version 42.2.26 or 42.4.1.",
    "source": "kev"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
Extracted Attribute-Based Access Control (ABAC) policy from the Ansible configuration. The policy covers a PCI-compliant production environment (`chaincorp`, `compliance_tier=pci`) with 4 hosts, 3 users, and explicit access controls for SSH, sudo, network, database, and filesystem resources.

## Attribute Catalog Summary
- **Subjects**: 3 users (`admin`, `developer`, `dba`), 3 groups (`sudo`, `developers`, `dba`)
- **Resources**: 4 hosts across 4 zones (`mgmt`, `dmz`, `app`, `data`), 4 services, 1 protected path
- **Environment**: `org=chaincorp`, `environment=production`, `compliance_tier=pci`

## Rule Summary (12 rules)
1. `ssh:login` permit on bastion for `sudo`, `dba`
2. `ssh:login` permit on webservers for `sudo`
3. `ssh:login` permit on appservers for `sudo`, `developers`
4. `ssh:login` permit on dbservers for `sudo`, `dba`
5. `sudo:execute` permit on bastion for `sudo` group with `secret` clearance (obligation: session logging)
6. `network:connect` permit to bastion SSH from `0.0.0.0/0`
7. `network:connect` permit to web HTTP from `10.0.0.0/24`
8. `network:connect` permit to app port from `10.0.1.0/24`
9. `network:connect` permit to postgres from `10.0.2.0/24`
10. `db:login` permit for `dba` group to PostgreSQL (SUPERUSER, obligation)
11. `filesystem:write` permit for `dba` group to `/var/lib/postgresql/data`
12. Default deny-all rule

## Vulnerability Assessment
22 vulnerabilities identified in pinned package versions:
- **openssh (9.1p1)**: CVE-2023-38408 (Critical RCE), CVE-2024-6387 regreSSHion (High)
- **apache (2.4.49)**: Path traversal & RCE vulnerabilities
- **log4j (2.14.1)**: CVE-2021-44228 Log4Shell (Critical RCE), multiple deserialization flaws
- **postgresql (9.2.3)**: CVE-2019-9193 (KEV command execution), multiple privilege escalation CVEs

## Ambiguities & Notes
- Package versions in `group_vars/all.yml` are deliberately pinned to vulnerable versions for testing.
- No explicit SELinux policies or audit scripts found in role tasks.
- Session logging is noted as an obligation for sudo access.
- Default-deny posture is implicit; explicit deny rules were not found in Ansible tasks.
- Credentials (passwords, keys) are not present in the configuration files reviewed.
