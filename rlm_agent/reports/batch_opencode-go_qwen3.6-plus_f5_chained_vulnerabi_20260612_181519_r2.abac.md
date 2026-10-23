# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:21:33_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 17_  
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
    "clearance": {
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
    "department": {
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
    },
    "source_network": {
      "values": [
        "0.0.0.0/0",
        "10.0.0.0/24",
        "10.0.1.0/24",
        "10.0.2.0/24"
      ],
      "domain": [
        "0.0.0.0/0",
        "10.0.0.0/24",
        "10.0.1.0/24",
        "10.0.2.0/24",
        "10.0.3.0/24"
      ],
      "source": "group_vars/*.yml"
    },
    "source_zone": {
      "values": [
        "internet",
        "mgmt",
        "dmz",
        "app"
      ],
      "domain": [
        "internet",
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini + group_vars/*.yml"
    },
    "subject_attributes": {
      "groups": {
        "domain": [
          "sudo",
          "developers",
          "dba"
        ],
        "source": "group_vars/all.yml"
      },
      "clearance": {
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      },
      "department": {
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      },
      "source_network": {
        "domain": [
          "0.0.0.0/0",
          "10.0.0.0/24",
          "10.0.1.0/24",
          "10.0.2.0/24"
        ],
        "source": "group_vars/*.yml"
      },
      "source_zone": {
        "domain": [
          "internet",
          "mgmt",
          "dmz",
          "app",
          "data"
        ],
        "source": "inventory.ini"
      }
    }
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
        "name": "http",
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
        "label": "bastion-subnet",
        "source": "group_vars/bastion.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web-subnet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app-subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "db-subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "group_vars/bastion.yml"
      }
    ],
    "host_zones": {
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
        "data"
      ],
      "source": "inventory.ini"
    },
    "host_roles": {
      "values": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "databases": {
      "values": [
        "postgresql"
      ],
      "domain": [
        "postgresql",
        "mysql",
        "mongodb"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "resource_attributes": {
      "port": {
        "domain": [
          22,
          80,
          5432,
          8080
        ],
        "source": "inventory.ini + group_vars/*.yml"
      },
      "zone": {
        "domain": [
          "mgmt",
          "dmz",
          "app",
          "data"
        ],
        "source": "inventory.ini"
      },
      "database": {
        "domain": [
          "postgresql",
          "mysql",
          "all"
        ],
        "source": "roles/db/tasks/main.yml"
      },
      "path": {
        "domain": [
          "/var/lib/postgresql/data"
        ],
        "source": "roles/db/tasks/main.yml"
      },
      "owner": {
        "domain": [
          "postgres",
          "root"
        ],
        "source": "roles/db/tasks/main.yml"
      },
      "group": {
        "domain": [
          "postgres",
          "root"
        ],
        "source": "roles/db/tasks/main.yml"
      },
      "mode": {
        "domain": [
          "0700",
          "0755",
          "0644"
        ],
        "source": "roles/db/tasks/main.yml"
      }
    }
  },
  "environment": {
    "org": {
      "value": "chaincorp",
      "domain": [
        "chaincorp"
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
        "none"
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
    "rule_id": "rule-001",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
      },
      "zone": {
        "equals": "mgmt"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
      },
      "zone": {
        "equals": "dmz"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        21,
        25
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
      },
      "zone": {
        "equals": "app"
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
      "lines": [
        31,
        35
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
      },
      "zone": {
        "equals": "data"
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
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        29,
        33
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
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
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        22,
        29
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
      },
      "zone": {
        "equals": "mgmt"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        14,
        20
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
      },
      "zone": {
        "equals": "dmz"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        13,
        19
      ]
    }
  },
  {
    "rule_id": "rule-008",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
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
    }
  },
  {
    "rule_id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "zone": {
        "equals": "data"
      },
      "database": {
        "equals": "postgresql"
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
      "lines": [
        23,
        27
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "database": {
        "equals": "postgresql"
      },
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privileges": [
      "LOGIN",
      "SUPERUSER"
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        16,
        21
      ]
    }
  },
  {
    "rule_id": "rule-011",
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
      ]
    },
    "obligations": [
      {
        "type": "ownership_enforcement",
        "detail": "Mode 0700 restricts access to postgres OS user only"
      }
    ]
  },
  {
    "rule_id": "rule-012",
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
      "task": "implicit default deny",
      "lines": [
        0,
        0
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
    "id": "rule-003",
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
    "id": "rule-004",
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
    "id": "rule-005",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "database": {
        "equals": "postgresql"
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
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentica",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding ",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 8.1,
    "severity": "high",
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipula",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 6.8,
    "severity": "medium",
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 6.8,
    "severity": "medium",
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2012-2379",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "Apache CXF 2.4.x before 2.4.8, 2.5.x before 2.5.4, and 2.6.x before 2.6.1 contain a signature or encryption validation issue caused by improper handling of child WS-SecurityPolicy in Supporting Tokens",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2013-4316",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "Apache Struts 2.0.0 through 2.3.15.1 enables Dynamic Method Invocation by default, causing unspecified impact and attack vectors, potentially leading to remote code execution or other security issues.",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2012-0838",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "Apache Struts 2 before 2.2.3.1 contains an OGNL injection caused by evaluating a string as an expression during conversion error handling, letting remote attackers execute arbitrary code via invalid i",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2012-3506",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "Apache Open For Business Project (OFBiz) 10.04.x before 10.04.03 contains an unspecified vulnerability with unknown impact and attack vectors.",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2014-3525",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "Apache Traffic Server 3.x through 3.2.5, 4.x before 4.2.1.1, and 5.x before 5.0.1 contain an unspecified vulnerability with unknown impact and attack vectors, possibly related to health checks.",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to e",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2010-0219",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "Apache Axis2 in various products contains a default password 'axis2' for the admin account, causing a security weakness that allows remote attackers to execute arbitrary code by uploading crafted web ",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2023-46604",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "Apache ActiveMQ contains a remote code execution caused by manipulation of serialized class types in the OpenWire protocol, letting remote attackers execute arbitrary shell commands, exploit requires ",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2016-15057",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 9.9,
    "severity": "critical",
    "description": "Apache Continuum contains a command injection caused by improper neutralization of special elements in REST API, letting attackers with API access execute arbitrary commands remotely, exploit requires",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2016-3427",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "Oracle Java SE 6u113, 7u99, 8u77; Java SE Embedded 8u77; and JRockit R28.3.9 contain an unspecified vulnerability related to JMX, letting remote attackers impact confidentiality, integrity, and availa",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploit requires specific JDBCAppender configuration.",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, explo",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket servers, letting attackers execute arbitrary code rem",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting attackers execute malicious code, exploit requires attacker to send crafted seriali",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 9,
    "severity": "critical",
    "description": "Apache Log4j2 contains a remote code execution caused by vulnerable thread context lookup pattern in certain non-default configurations, letting remote attackers execute arbitrary code, exploit requir",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "Log4j 1.x on JRE less than 1.7 contains a denial of service caused by deserialization of specially-crafted nested hashmaps or hashtables, letting attackers exhaust memory, exploit requires attacker to",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2021-4104",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "Log4j 1.2 with JMSAppender configured contains a deserialization of untrusted data caused by write access to the configuration, letting attackers perform JNDI requests that may lead to remote code exe",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cvss_score": 6.6,
    "severity": "medium",
    "description": "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding 2.3.2 and 2.12.4) contain a remote code execution caused by unsafe JNDI LDAP data source URI usage in JDBC Appender, letting attackers with c",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "is_kev": [
      {
        "added_date": "2024-10-30T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "is_remote": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cvss_score": 10,
    "severity": "critical",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "is_kev": false,
    "is_remote": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cvss_score": 7.2,
    "severity": "high",
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cvss_score": 7.1,
    "severity": "high",
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
    "is_kev": true,
    "is_remote": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  }
]
```

## Report

# ABAC Policy Report — ChainCorp Production (PCI)

## Executive Summary

Mined ABAC policy from Ansible configuration rooted at `RLM_ANSIBLE_DIR`. 
Policy covers SSH access control, sudo privileges, firewall/network policies, 
database access, and filesystem permissions across 4 hosts in a PCI-compliant 
production environment.

## Inventory Overview

| Host | IP | Role | Zone |
|------|-----|------|------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt |
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| app01.lab.local | 10.0.2.10 | application | app |
| db01.lab.local | 10.0.3.10 | primary | data |

**Organization:** chaincorp  
**Environment:** production  
**Compliance Tier:** PCI  
**Log Retention:** 365 days

## Subject Catalog

| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |

## Policy Rules Summary (12 rules)

### SSH Access (rules 1–4)
- **rule-001**: Bastion SSH — sudo, dba groups (mgmt zone)
- **rule-002**: Web SSH — sudo group (dmz zone)
- **rule-003**: App SSH — sudo, developers groups (app zone)
- **rule-004**: DB SSH — sudo, dba groups (data zone)

### Privilege Escalation (rule 5)
- **rule-005**: Bastion sudo — requires sudo group AND secret clearance

### Network/Firewall Policies (rules 6–9)
- **rule-006**: Bastion — allow SSH from 0.0.0.0/0 (internet)
- **rule-007**: Web — allow HTTP from 10.0.0.0/24 (bastion subnet)
- **rule-008**: App — allow app:8080 from 10.0.1.0/24 (web subnet)
- **rule-009**: DB — allow PostgreSQL:5432 from 10.0.2.0/24 (app subnet)

### Database Access (rule 10)
- **rule-010**: DB superuser — dba group gets LOGIN+SUPERUSER on PostgreSQL

### Filesystem (rule 11)
- **rule-011**: Postgres data dir (/var/lib/postgresql/data) — mode 0700, owner postgres
  - *Obligation:* Mode 0700 restricts access to postgres OS user only

### Default Deny (rule 12)
- **rule-012**: Catch-all deny for all subjects, resources, and actions

## Vulnerability Assessment

### Pinned Software Versions
| Package | Pinned Version | Host(s) |
|---------|---------------|---------|
| openssh-server | 1:9.1p1-1ubuntu1 | bastion |
| openssh-server | 1:9.9p1-3ubuntu1 | webservers, appservers |
| apache2 | 2.4.49-1 | webservers |
| log4j | 2.14.1 | appservers |
| postgresql-9.2 | 9.2.3-1 | dbservers |

### Critical Findings
**Total unique CVEs found:** 35  
**KEV (actively exploited):** 17  
**Critical severity:** 26  

| CVE | Product | CVSS | Severity | KEV | Recommendation |
|-----|---------|------|----------|-----|----------------|
| CVE-2021-44228 | apache | 10 | critical | Yes | Upgrade apache from 2.4.49-1 to latest patched version |
| CVE-2010-0219 | apache | 10 | critical | Yes | Upgrade apache from 2.4.49-1 to latest patched version |
| CVE-2023-46604 | apache | 10 | critical | Yes | Upgrade apache from 2.4.49-1 to latest patched version |
| CVE-2024-1597 | postgresql | 10 | critical | Yes | Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version |
| CVE-2016-15057 | apache | 9.9 | critical | Yes | Upgrade apache from 2.4.49-1 to latest patched version |
| CVE-2023-38408 | openssh | 9.8 | critical | Yes | Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version |
| CVE-2016-3427 | apache | 9.8 | critical | Yes | Upgrade apache from 2.4.49-1 to latest patched version |
| CVE-2021-45046 | log4j | 9 | critical | Yes | Upgrade log4j from 2.14.1 to latest patched version |
| CVE-2024-6387 | openssh | 8.1 | high | Yes | Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version |
| CVE-2007-4752 | openssh | 7.5 | high | Yes | Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version |

### High-Risk Items
- **CVE-2021-44228 (Log4Shell)** — CVSS 10.0, Log4j 2.14.1 is affected. Actively exploited in KEV.
- **CVE-2021-45046** — CVSS 9.0, Log4j 2.14.1 is affected. Active exploitation confirmed.
- **Apache 2.4.49** — Known to have critical vulnerabilities (CVE-2021-41773, CVE-2021-42013).
- **OpenSSH 9.1p1 (bastion)** — Multiple KEV entries including CVE-2023-38408 and CVE-2024-6387 (regreSSHion).

## Ambiguities and Notes

1. **Credentials in config**: No hardcoded passwords or API keys were found in the 
   Ansible configuration files. Database authentication uses `scram-sha-256` per 
   pg_hba configuration.
2. **Implicit deny**: The pg_hba configuration allows connections from 10.0.2.0/24 
   but does not explicitly deny other sources. The ABAC default-deny rule (rule-012) 
   covers this at the policy level.
3. **SSH version divergence**: Bastion runs an older OpenSSH (9.1p1) compared to 
   other hosts (9.9p1). This is intentional for the vulnerability assessment but 
   represents a real-world risk.
4. **Log4j deliberately vulnerable**: The app role explicitly pins Log4j to version 
   2.14.1, which contains critical known vulnerabilities. This appears to be a 
   deliberate test configuration.
5. **No session logging rules**: While `default_log_retention_days: 365` is set, 
   no explicit session logging or audit script tasks were found in the role files. 
   This is noted as a gap in the Ambiguities section.
