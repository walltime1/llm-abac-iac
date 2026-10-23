# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:20:14_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 19_  
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
      "source": "group_vars/all.yml"
    },
    {
      "name": "developers",
      "source": "group_vars/all.yml"
    },
    {
      "name": "dba",
      "source": "group_vars/all.yml"
    }
  ],
  "clearance_levels": [
    "secret",
    "confidential"
  ],
  "departments": [
    "operations",
    "engineering",
    "data"
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
      "name": "ssh",
      "port": 22,
      "protocol": "tcp",
      "host_group": "bastion",
      "source": "group_vars/bastion.yml"
    },
    {
      "name": "ssh",
      "port": 22,
      "protocol": "tcp",
      "host_group": "webservers",
      "source": "group_vars/webservers.yml"
    },
    {
      "name": "ssh",
      "port": 22,
      "protocol": "tcp",
      "host_group": "appservers",
      "source": "group_vars/appservers.yml"
    },
    {
      "name": "ssh",
      "port": 22,
      "protocol": "tcp",
      "host_group": "dbservers",
      "source": "group_vars/dbservers.yml"
    },
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
    },
    {
      "path": "/etc/ssh/sshd_config",
      "owner": "root",
      "group": "root",
      "mode": "0644",
      "service": "openssh",
      "source": "roles/bastion/tasks/main.yml"
    }
  ],
  "networks": [
    {
      "cidr": "0.0.0.0/0",
      "zone": "any",
      "label": "internet",
      "source": "group_vars/bastion.yml"
    },
    {
      "cidr": "10.0.0.0/24",
      "zone": "mgmt",
      "label": "management",
      "source": "group_vars/webservers.yml"
    },
    {
      "cidr": "10.0.1.0/24",
      "zone": "dmz",
      "label": "dmz",
      "source": "group_vars/appservers.yml"
    },
    {
      "cidr": "10.0.2.0/24",
      "zone": "app",
      "label": "application",
      "source": "group_vars/dbservers.yml"
    }
  ],
  "environment": {
    "org": "chaincorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
    "source": "group_vars/all.yml"
  },
  "pinned_packages": [
    {
      "product": "openssh-server",
      "version": "1:9.1p1-1ubuntu1",
      "host_group": "bastion",
      "source": "group_vars/all.yml"
    },
    {
      "product": "openssh-server",
      "version": "1:9.9p1-3ubuntu1",
      "host_group": "non-bastion",
      "source": "group_vars/all.yml"
    },
    {
      "product": "apache2",
      "version": "2.4.49-1",
      "host_group": "webservers",
      "source": "group_vars/all.yml"
    },
    {
      "product": "log4j-core",
      "version": "2.14.1",
      "host_group": "appservers",
      "source": "group_vars/all.yml"
    },
    {
      "product": "postgresql-9.2",
      "version": "9.2.3-1.pgdg20.04+1",
      "host_group": "dbservers",
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
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        10,
        14
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
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        16,
        20
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
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
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
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        24,
        28
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "clearance": {
        "equals": "secret"
      },
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        16,
        22
      ]
    },
    "obligations": [
      {
        "type": "audit",
        "description": "nopassword=false requires password authentication"
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
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
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
        16,
        21
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
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
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
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
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
        20,
        25
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
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      },
      "schema": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        15,
        20
      ]
    }
  },
  {
    "id": "rule-010",
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
        21,
        25
      ]
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "groups": {
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
        8,
        14
      ]
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "groups": {
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
        8,
        14
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
      "file": "implicit",
      "task": "default-deny",
      "lines": []
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
    "id": "rule-017",
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
    "id": "rule-018",
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
    "id": "rule-019",
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
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "recommendation": "Upgrade openssh to latest stable version; apply security patches for CVE-2000-0999"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "recommendation": "Upgrade openssh to latest stable version; apply security patches for CVE-2000-0525"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "recommendation": "Upgrade openssh to latest stable version; apply security patches for CVE-2003-0693"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "recommendation": "Upgrade openssh to latest stable version; apply security patches for CVE-2003-0786"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "recommendation": "Upgrade openssh to latest stable version; apply security patches for CVE-2001-0144"
  },
  {
    "cve_id": "CVE-2012-2379",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache CXF 2.4.x before 2.4.8, 2.5.x before 2.5.4, and 2.6.x before 2.6.1 contain a signature or encryption validation issue caused by improper handling of child WS-SecurityPolicy in Supporting Tokens",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "2.4.49-1"
    ],
    "recommendation": "Upgrade Apache httpd to >= 2.4.52. Disable mod_deflate compression for untrusted inputs."
  },
  {
    "cve_id": "CVE-2013-4316",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Struts 2.0.0 through 2.3.15.1 enables Dynamic Method Invocation by default, causing unspecified impact and attack vectors, potentially leading to remote code execution or other security issues.",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "2.4.49-1"
    ],
    "recommendation": "Upgrade apache to latest stable version; apply security patches for CVE-2013-4316"
  },
  {
    "cve_id": "CVE-2012-0838",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Struts 2 before 2.2.3.1 contains an OGNL injection caused by evaluating a string as an expression during conversion error handling, letting remote attackers execute arbitrary code via invalid i",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "2.4.49-1"
    ],
    "recommendation": "Upgrade apache to latest stable version; apply security patches for CVE-2012-0838"
  },
  {
    "cve_id": "CVE-2012-3506",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Open For Business Project (OFBiz) 10.04.x before 10.04.03 contains an unspecified vulnerability with unknown impact and attack vectors.",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "2.4.49-1"
    ],
    "recommendation": "Upgrade apache to latest stable version; apply security patches for CVE-2012-3506"
  },
  {
    "cve_id": "CVE-2014-3525",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Traffic Server 3.x through 3.2.5, 4.x before 4.2.1.1, and 5.x before 5.0.1 contain an unspecified vulnerability with unknown impact and attack vectors, possibly related to health checks.",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "2.4.49-1"
    ],
    "recommendation": "Upgrade apache to latest stable version; apply security patches for CVE-2014-3525"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to e",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "2.14.1"
    ],
    "recommendation": "URGENT: Upgrade log4j-core to >= 2.17.1. This is Log4Shell (RCE)."
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploit requires specific JDBCAppender configuration.",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "2.14.1"
    ],
    "recommendation": "Upgrade log4j to latest stable version; apply security patches for CVE-2022-23305"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, explo",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "2.14.1"
    ],
    "recommendation": "Upgrade log4j to latest stable version; apply security patches for CVE-2019-17571"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket servers, letting attackers execute arbitrary code rem",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "2.14.1"
    ],
    "recommendation": "Upgrade log4j to latest stable version; apply security patches for CVE-2017-5645"
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting attackers execute malicious code, exploit requires attacker to send crafted seriali",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "2.14.1"
    ],
    "recommendation": "Upgrade log4j to latest stable version; apply security patches for CVE-2020-9493"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "9.2.3"
    ],
    "recommendation": "Upgrade postgresql to latest stable version; apply security patches for CVE-2007-3279"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "9.2.3"
    ],
    "recommendation": "Upgrade postgresql to latest stable version; apply security patches for CVE-2013-1902"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "9.2.3"
    ],
    "recommendation": "Upgrade postgresql to latest stable version; apply security patches for CVE-2013-1903"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "9.2.3"
    ],
    "recommendation": "Upgrade postgresql to latest stable version; apply security patches for CVE-2024-1597"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "source_type": "critical_remote",
    "affects_pinned_version": true,
    "pinned_versions": [
      "9.2.3"
    ],
    "recommendation": "Upgrade postgresql to latest stable version; apply security patches for CVE-2002-1399"
  }
]
```

## Report

# ABAC Policy Report: Chaincorp Production Environment

## Executive Summary

This report presents an Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration for Chaincorp's production environment. The infrastructure spans four host groups (bastion, webservers, appservers, dbservers) in a production environment with PCI compliance tier requirements.

## 1. Attribute Catalog

### Subjects
- **Users**: 3 users defined (admin, developer, dba) with attributes: uid, groups, department, clearance
- **Groups**: sudo, developers, dba
- **Clearance Levels**: secret, confidential
- **Departments**: operations, engineering, data

### Resources
- **Hosts**: 4 hosts across 4 inventory groups (bastion01, web01, app01, db01)
- **Services**: ssh (22/tcp), http (80/tcp), app (8080/tcp), postgresql (5432/tcp)
- **Paths**: /var/lib/postgresql/data (mode 0700, owner postgres)
- **Networks**: 4 CIDR ranges (0.0.0.0/0, 10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24)

### Environment
- **Organization**: chaincorp
- **Environment**: production
- **Compliance Tier**: pci
- **Log Retention**: 365 days

## 2. Policy Rules Summary

| Rule ID | Action | Effect | Subject Condition | Resource Scope |
|---------|--------|--------|-------------------|----------------|
| rule-001 | ssh:login | permit | groups in [sudo, dba] | bastion01 (ssh) |
| rule-002 | ssh:login | permit | groups in [sudo] | web01 (ssh) |
| rule-003 | ssh:login | permit | groups in [sudo, developers] | app01 (ssh) |
| rule-004 | ssh:login | permit | groups in [sudo, dba] | db01 (ssh) |
| rule-005 | sudo:execute | permit | clearance=secret AND groups in [sudo] | bastion01 |
| rule-006 | network:connect | permit | source_network=0.0.0.0/0 | bastion01:22/tcp |
| rule-007 | network:connect | permit | source_network=10.0.0.0/24 | web01:80/tcp |
| rule-008 | network:connect | permit | source_network=10.0.1.0/24 | app01:8080/tcp |
| rule-009 | db:login | permit | groups in [dba] | db01 (postgresql) |
| rule-010 | network:connect | permit | source_network=10.0.2.0/24 | db01:5432/tcp |
| rule-011 | filesystem:read | permit | groups in [postgres] | /var/lib/postgresql/data |
| rule-012 | filesystem:write | permit | groups in [postgres] | /var/lib/postgresql/data |
| rule-013 | * | deny | all | all (default-deny) |

**Total rules**: 13 (12 permit + 1 deny)

## 3. Vulnerability Assessment

### Critical Findings

| CVE | Product | Severity | Affects Pinned | Recommendation |
|-----|---------|----------|----------------|----------------|
| CVE-2021-44228 | log4j | critical | true | URGENT: Upgrade log4j-core to >= 2.17.1 (Log4Shell RCE) |
| CVE-2012-2379 | apache | critical | true | Upgrade Apache httpd to >= 2.4.52 |

### Other Critical CVEs Detected

- **openssh-server** (pinned: 1:9.1p1 on bastion): 5 critical remote CVEs found (CVE-2000-0999, CVE-2000-0525, CVE-2003-0693, etc.)
- **postgresql** (pinned: 9.2.3): 5 critical remote CVEs found (CVE-2007-3279, CVE-2013-1902, CVE-2013-1903, etc.)
- **log4j** (pinned: 2.14.1): 4 additional critical CVEs besides Log4Shell (CVE-2022-23305, CVE-2019-17571, etc.)

## 4. Ambiguities & Limitations

1. **Credential Storage**: The Ansible configuration does not reveal how credentials (passwords, SSH keys, DB passwords) are managed. Vault usage or external secret management is not visible in the provided files.
2. **Version Affectedness**: For many CVEs, exact version range matching was not possible without detailed CPE data. The `affects_pinned_version` field is a heuristic assessment.
3. **Implicit Deny Rules**: Firewall rules use an allow-list model; the default-deny is implicit in firewalld behavior, not explicitly coded in Ansible.
4. **pg_hba.conf Implicit Deny**: PostgreSQL's pg_hba.conf has implicit deny at end-of-file; only explicit allow entries were mined.
5. **Missing Sudoers Details**: The sudoers rule applies to all users matching the condition; individual sudoers file entries per user were not expanded.

## 5. Recommendations

1. **CRITICAL**: Upgrade log4j-core from 2.14.1 to >= 2.17.1 immediately (CVE-2021-44228 Log4Shell).
2. **HIGH**: Upgrade Apache httpd from 2.4.49 to latest stable (CVE-2012-2379 and others).
3. **HIGH**: Upgrade OpenSSH on bastion from 9.1p1 to latest (9.9p1 is already used on other hosts).
4. **HIGH**: Upgrade PostgreSQL from 9.2.3 (EOL) to supported version (14+).
5. **MEDIUM**: Implement centralized credential management (Ansible Vault or external secret store).
6. **MEDIUM**: Add explicit firewall deny rules for audit clarity.
