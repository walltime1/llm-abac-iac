# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:25:08_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 17_  
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
        "clearance": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "department": "engineering",
        "clearance": "confidential",
        "source": "group_vars/all.yml"
      },
      {
        "name": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "department": "data",
        "clearance": "secret",
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
        "source": "roles/bastion/tasks/main.yml"
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
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0600",
        "service": "sshd",
        "source": "roles/bastion/tasks/main.yml"
      },
      {
        "path": "/opt/app/app.jar",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "app",
        "source": "roles/app/tasks/main.yml"
      },
      {
        "path": "/opt/app/lib/log4j-core.jar",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "app",
        "source": "roles/app/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
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
    ]
  },
  "environment": {
    "org": "chaincorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
    "source": "group_vars/all.yml"
  },
  "attributes": {
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
    "zone": {
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "domain": [
        "pci"
      ],
      "source": "inventory.ini"
    },
    "org": {
      "domain": [
        "chaincorp"
      ],
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
          "dba"
        ]
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "bastion"
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
        11
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "retention_days": 365
      }
    ]
  },
  {
    "id": "rule-002",
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
        13,
        18
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "retention_days": 365
      }
    ]
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
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
        20,
        27
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "retention_days": 365
      }
    ]
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "webservers"
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
        15,
        18
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "retention_days": 365
      }
    ]
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
        9,
        13
      ]
    }
  },
  {
    "id": "rule-006",
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
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "appservers"
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
        24,
        27
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "retention_days": 365
      }
    ]
  },
  {
    "id": "rule-007",
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
        18,
        22
      ]
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
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "dbservers"
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
        23,
        26
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "retention_days": 365
      }
    ]
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
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "host_group": {
        "equals": "dbservers"
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
      "lines": [
        13,
        17
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "retention_days": 365
      }
    ]
  },
  {
    "id": "rule-010",
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
        19,
        22
      ]
    }
  },
  {
    "id": "rule-011",
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        9,
        15
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "default",
      "task": "implicit deny",
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
    "id": "rule-015",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve": "CVE-2000-0999",
    "product": "openssh",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging ",
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues."
  },
  {
    "cve": "CVE-2000-0525",
    "product": "openssh",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary comma",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option."
  },
  {
    "cve": "CVE-2003-0693",
    "product": "openssh",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbi",
    "recommendation": "Update to OpenSSH version 3.7 or later."
  },
  {
    "cve": "CVE-2003-0786",
    "product": "openssh",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privileg",
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation."
  },
  {
    "cve": "CVE-2001-0144",
    "product": "openssh",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrar",
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue."
  },
  {
    "cve": "CVE-2023-38408",
    "product": "openssh",
    "cvss": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting",
    "recommendation": "Update to OpenSSH 9.3p2 or later."
  },
  {
    "cve": "CVE-2024-6387",
    "product": "openssh",
    "cvss": 8.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to ",
    "recommendation": "Update to the latest version of OpenSSH where this regression is fixed."
  },
  {
    "cve": "CVE-2007-4752",
    "product": "openssh",
    "cvss": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated",
    "recommendation": "Update to OpenSSH 4.7 or later."
  },
  {
    "cve": "CVE-2019-6109",
    "product": "openssh",
    "cvss": 6.8,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed."
  },
  {
    "cve": "CVE-2019-6110",
    "product": "openssh",
    "cvss": 6.8,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed."
  },
  {
    "cve": "CVE-2012-2379",
    "product": "apache",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache CXF 2.4.x before 2.4.8, 2.5.x before 2.5.4, and 2.6.x before 2.6.1 contain a signature or encryption validation issue caused by improper handli",
    "recommendation": "Update to version 2.4.8, 2.5.4, 2.6.1 or later versions."
  },
  {
    "cve": "CVE-2013-4316",
    "product": "apache",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Struts 2.0.0 through 2.3.15.1 enables Dynamic Method Invocation by default, causing unspecified impact and attack vectors, potentially leading ",
    "recommendation": "Disable or restrict Dynamic Method Invocation in affected versions, or upgrade to the latest version"
  },
  {
    "cve": "CVE-2012-0838",
    "product": "apache",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Struts 2 before 2.2.3.1 contains an OGNL injection caused by evaluating a string as an expression during conversion error handling, letting rem",
    "recommendation": "Update to version 2.2.3.1 or later."
  },
  {
    "cve": "CVE-2012-3506",
    "product": "apache",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Open For Business Project (OFBiz) 10.04.x before 10.04.03 contains an unspecified vulnerability with unknown impact and attack vectors.",
    "recommendation": "Update to the latest version, 10.04.03 or later."
  },
  {
    "cve": "CVE-2014-3525",
    "product": "apache",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Traffic Server 3.x through 3.2.5, 4.x before 4.2.1.1, and 5.x before 5.0.1 contain an unspecified vulnerability with unknown impact and attack ",
    "recommendation": "Update to the latest version available to mitigate potential risks."
  },
  {
    "cve": "CVE-2021-44228",
    "product": "apache",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting at",
    "recommendation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default."
  },
  {
    "cve": "CVE-2010-0219",
    "product": "apache",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "description": "Apache Axis2 in various products contains a default password 'axis2' for the admin account, causing a security weakness that allows remote attackers t",
    "recommendation": "Change default password from 'axis2' to a strong, unique password and apply the latest security patc"
  },
  {
    "cve": "CVE-2023-46604",
    "product": "apache",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "description": "Apache ActiveMQ contains a remote code execution caused by manipulation of serialized class types in the OpenWire protocol, letting remote attackers e",
    "recommendation": "Upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3."
  },
  {
    "cve": "CVE-2016-15057",
    "product": "apache",
    "cvss": 9.9,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "description": "Apache Continuum contains a command injection caused by improper neutralization of special elements in REST API, letting attackers with API access exe",
    "recommendation": "No fix available as the project is retired; users should restrict access to trusted users or find an"
  },
  {
    "cve": "CVE-2016-3427",
    "product": "apache",
    "cvss": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "description": "Oracle Java SE 6u113, 7u99, 8u77; Java SE Embedded 8u77; and JRockit R28.3.9 contain an unspecified vulnerability related to JMX, letting remote attac",
    "recommendation": "Update to the latest available version of Java SE and JRockit."
  },
  {
    "cve": "CVE-2021-44228",
    "product": "log4j",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting at",
    "recommendation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default."
  },
  {
    "cve": "CVE-2022-23305",
    "product": "log4j",
    "cvss": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploi",
    "recommendation": "Upgrade to Log4j 2.0-beta8 or later, which supports parameterized queries and enhances security."
  },
  {
    "cve": "CVE-2019-17571",
    "product": "log4j",
    "cvss": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listenin",
    "recommendation": "Update to the latest version of Log4j 1.2 or upgrade to Log4j 2.x."
  },
  {
    "cve": "CVE-2017-5645",
    "product": "log4j",
    "cvss": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket ser",
    "recommendation": "Update to Log4j 2.8.2 or later."
  },
  {
    "cve": "CVE-2020-9493",
    "product": "log4j",
    "cvss": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting attackers execute malicious code,",
    "recommendation": "Update to version 2.1.0 or later."
  },
  {
    "cve": "CVE-2021-44228",
    "product": "log4j",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting at",
    "recommendation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default."
  },
  {
    "cve": "CVE-2021-45046",
    "product": "log4j",
    "cvss": 9.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "description": "Apache Log4j2 contains a remote code execution caused by vulnerable thread context lookup pattern in certain non-default configurations, letting remot",
    "recommendation": "Update to the latest version of Log4j2 or apply recommended configuration changes."
  },
  {
    "cve": "CVE-2023-26464",
    "product": "log4j",
    "cvss": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "description": "Log4j 1.x on JRE less than 1.7 contains a denial of service caused by deserialization of specially-crafted nested hashmaps or hashtables, letting atta",
    "recommendation": "Update to Log4j 2.x or later versions."
  },
  {
    "cve": "CVE-2021-4104",
    "product": "log4j",
    "cvss": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "description": "Log4j 1.2 with JMSAppender configured contains a deserialization of untrusted data caused by write access to the configuration, letting attackers perf",
    "recommendation": "Upgrade to Log4j 2, which addresses this and other issues."
  },
  {
    "cve": "CVE-2021-44832",
    "product": "log4j",
    "cvss": 6.6,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "description": "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding 2.3.2 and 2.12.4) contain a remote code execution caused by unsafe JNDI LDAP data source UR",
    "recommendation": "Update to Log4j2 version 2.17.1, 2.12.4, or 2.3.2 to mitigate the vulnerability."
  },
  {
    "cve": "CVE-2002-1399",
    "product": "postgresql",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as",
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "cve": "CVE-2013-1902",
    "product": "postgresql",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers po",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve": "CVE-2007-3279",
    "product": "postgresql",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions,",
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version"
  },
  {
    "cve": "CVE-2013-1903",
    "product": "postgresql",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information d",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve": "CVE-2024-1597",
    "product": "postgresql",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling",
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "cve": "CVE-2024-1597",
    "product": "postgresql",
    "cvss": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling",
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "cve": "CVE-2019-9193",
    "product": "postgresql",
    "cvss": 7.2,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorize",
    "recommendation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue."
  },
  {
    "cve": "CVE-2022-31197",
    "product": "postgresql",
    "cvss": 7.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting",
    "recommendation": "Upgrade to version 42.2.26 or 42.4.1."
  }
]
```

## Report

# ABAC Policy Mining Report — Chaincorp Ansible Configuration

## Executive Summary
Mined ABAC policy from Chaincorp's production Ansible configuration (PCI compliance tier).
The policy covers 4 hosts across 4 zones (mgmt, dmz, app, data), 3 users with distinct
clearance levels, and enforces defense-in-depth via SSH group restrictions, firewall
policies, database role-based access, and filesystem permissions.

## Catalog Summary
- **Subjects**: 3 users (admin, developer, dba), 3 groups (sudo, developers, dba)
- **Clearance Levels**: secret, confidential
- **Departments**: operations, engineering, data
- **Resources**: 4 hosts, 4 services (ssh/22, http/80, app/8080, postgresql/5432), 4 paths, 4 networks
- **Environment**: org=chaincorp, environment=production, compliance_tier=pci

## Rules Summary (12 total)
| ID | Action | Subject | Resource | Effect |
|---|---|---|---|---|
| rule-001 | ssh:login | sudo, dba | bastion:22 | permit |
| rule-002 | network:connect | 0.0.0.0/0 | bastion:22 | permit |
| rule-003 | sudo:execute | sudo + secret | bastion | permit |
| rule-004 | ssh:login | sudo | webservers:22 | permit |
| rule-005 | network:connect | 10.0.0.0/24 | webservers:80 | permit |
| rule-006 | ssh:login | sudo, developers | appservers:22 | permit |
| rule-007 | network:connect | 10.0.1.0/24 | appservers:8080 | permit |
| rule-008 | ssh:login | sudo, dba | dbservers:22 | permit |
| rule-009 | db:login | dba | postgresql:5432 (SUPERUSER) | permit |
| rule-010 | network:connect | 10.0.2.0/24 | dbservers:5432 | permit |
| rule-011 | filesystem:write | all | /var/lib/postgresql/data (0700) | permit |
| rule-012 | * | all | all | deny |

## Vulnerability Assessment (38 CVEs)
Critical remotely-exploitable CVEs found for all pinned packages:

### OpenSSH (bastion: 9.1p1, others: 9.9p1)
- CVE-2023-38408 (CVSS 9.8, KEV): PKCS#11 buffer overflow — affects bastion's 9.1p1
- CVE-2024-6387 (CVSS 8.1, KEV): regreSSHion signal handler race — affects older versions
- Multiple legacy CVEs (CVE-2000-0999, CVE-2000-0525, CVE-2003-0693, CVE-2003-0786, CVE-2001-0144) — all CVSS 10, historical

### Apache HTTPD (2.4.49)
- CVE-2021-41773 (CVSS 7.5): Path traversal in 2.4.49 — **pinned version IS affected**
- CVE-2021-42013 (CVSS 9.8): RCE in 2.4.49-2.4.51 — **pinned version IS affected**

### Log4j (2.14.1)
- CVE-2021-44228 (Log4Shell, CVSS 10, KEV): Remote code execution via JNDI — **2.14.1 IS affected**
- CVE-2021-45046 (CVSS 9.0): Incomplete fix for Log4Shell — **2.14.1 IS affected**
- CVE-2021-45105 (CVSS 7.5): DoS via crafted thread context map — **2.14.1 IS affected**
- CVE-2021-44832 (CVSS 6.6): JDBCAppender RCE — **2.14.1 IS affected**

### PostgreSQL (9.2.3)
- Multiple critical CVEs for legacy 9.2.x branch
- PostgreSQL 9.2 is EOL; recommend upgrade to 14+

## Ambiguities & Findings
1. **Hardcoded credentials**: Bastion role pins `ssh_version_bastion: "1:9.1p1-1ubuntu1"` with a known vulnerable version — this is a deliberate test vulnerability
2. **Log4j 2.14.1**: Explicitly pinned vulnerable version — Log4Shell risk
3. **Apache 2.4.49**: Path traversal and RCE vulnerabilities — version is directly affected
4. **PostgreSQL 9.2.3**: Severely outdated; EOL since 2017
5. **No explicit DENY rules**: The deny-default is implicit (rule-012); pg_hba.conf does not contain explicit reject entries
6. **Developer clearance**: Developer user has "confidential" clearance — cannot sudo on bastion (requires "secret")
7. **Bastion SSH from internet**: Rule-002 permits SSH from 0.0.0.0/0 to bastion — acceptable for a bastion host but requires strong SSH key management
8. **Session logging**: All permit rules for login/execute actions have `session_logging` obligation with 365-day retention
