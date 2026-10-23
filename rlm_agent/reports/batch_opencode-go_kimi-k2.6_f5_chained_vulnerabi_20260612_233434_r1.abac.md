# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 23:42:12_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 21_  
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
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [],
        "department": "system",
        "clearance": "none",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "domain": [
        "secret",
        "confidential",
        "none"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "domain": [
        "operations",
        "engineering",
        "data",
        "system"
      ],
      "source": "group_vars/all.yml"
    },
    "user": {
      "domain": [
        "admin",
        "developer",
        "dba",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "source": "inventory.ini and group_vars"
    },
    "source_ip": {
      "source": "inventory.ini"
    },
    "source_zone": {
      "source": "inventory.ini"
    },
    "clearance": {
      "domain": [
        "secret",
        "confidential",
        "none"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "operations",
        "engineering",
        "data",
        "system"
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
        "source": "inventory.ini",
        "host_group": "bastion"
      },
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "source": "inventory.ini",
        "host_group": "webservers"
      },
      {
        "hostname": "app01.lab.local",
        "ip": "10.0.2.10",
        "role": "application",
        "zone": "app",
        "source": "inventory.ini",
        "host_group": "appservers"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.3.10",
        "role": "primary",
        "zone": "data",
        "source": "inventory.ini",
        "host_group": "dbservers"
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
        "host_group": "bastion",
        "source": "roles/bastion/tasks/main.yml"
      }
    ],
    "paths": [
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgres",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": null,
        "label": "appservers ingress",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.0.0/24",
        "zone": null,
        "label": "webservers ingress",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": null,
        "label": "dbservers ingress",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": null,
        "label": "bastion ingress",
        "source": "group_vars/bastion.yml"
      }
    ],
    "service": {
      "domain": [
        "http",
        "app",
        "postgres",
        "ssh"
      ],
      "source": "group_vars and roles"
    },
    "port": {
      "domain": [
        80,
        8080,
        5432,
        22
      ],
      "source": "group_vars and roles"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "group_vars and roles"
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
    "hostname": {
      "domain": [
        "bastion01.lab.local",
        "web01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
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
    "zone": {
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "path": {
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "value": "chaincorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "pci",
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml"
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
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
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
        21,
        26
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
      "host_group": {
        "equals": "appservers"
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
        31,
        36
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
      "host_group": {
        "equals": "dbservers"
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
        29,
        34
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
      "host_group": {
        "equals": "bastion"
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
        8,
        13
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
      "host_group": {
        "equals": "bastion"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "nopassword": false,
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        22,
        30
      ]
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
      "host_group": {
        "equals": "dbservers"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "privilege_level": "SUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        16,
        22
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "dbservers"
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
        23,
        28
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
      "service": {
        "equals": "app"
      },
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
        30
      ]
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "bastion"
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
        14,
        21
      ]
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "webservers"
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
        13,
        20
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
        15
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
        15
      ]
    }
  },
  {
    "id": "rule-013",
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
        8,
        15
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
      "file": "default",
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
      "service": {
        "equals": "postgres"
      },
      "port": {
        "equals": 5432
      },
      "host_group": {
        "equals": "dbservers"
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
        "equals": "app"
      },
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
    "id": "rule-020",
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
      },
      "host_group": {
        "equals": "bastion"
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
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
      },
      "host_group": {
        "equals": "webservers"
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
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to execute arbitrary code, exploit requires attacker-controlled log messages or parameters.",
    "recommendation": "Upgrade to Log4j2 version 2.15.0 or later."
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket servers, letting attackers execute arbitrary code remotely, exploit requires sending malicious payloads over network.",
    "recommendation": "Does not affect Log4j 2.14.1; affects Log4j 1.x or older 2.x branches."
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting attackers execute malicious code, exploit requires attacker to send crafted serialized data.",
    "recommendation": "Does not affect Log4j 2.14.1; affects Log4j 1.x or older 2.x branches."
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploit requires specific JDBCAppender configuration.",
    "recommendation": "Does not affect Log4j 2.14.1; affects Log4j 1.x or older 2.x branches."
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, exploit requires listening to untrusted network traffic.",
    "recommendation": "Does not affect Log4j 2.14.1; affects Log4j 1.x or older 2.x branches."
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 9,
    "description": "Apache Log4j2 contains a remote code execution caused by vulnerable thread context lookup pattern in certain non-default configurations, letting remote attackers execute arbitrary code, exploit requires specific non-default configuration.",
    "recommendation": "Upgrade to Log4j2 version 2.17.0 or later."
  },
  {
    "cve_id": "CVE-2021-4104",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.5,
    "description": "Log4j 1.2 with JMSAppender configured contains a deserialization of untrusted data caused by write access to the configuration, letting attackers perform JNDI requests that may lead to remote code execution, exploit requires attacker to have write access to Log4j configuration.",
    "recommendation": "Does not affect Log4j 2.x; affects Log4j 1.2 only."
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.5,
    "description": "Log4j 1.x on JRE less than 1.7 contains a denial of service caused by deserialization of specially-crafted nested hashmaps or hashtables, letting attackers exhaust memory, exploit requires attacker to cause specific logging entries.",
    "recommendation": "Does not affect Log4j 2.x; affects Log4j 1.x (Chainsaw)."
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "severity": "medium",
    "cvss_score": 6.6,
    "description": "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding 2.3.2 and 2.12.4) contain a remote code execution caused by unsafe JNDI LDAP data source URI usage in JDBC Appender, letting attackers with control of LDAP server execute arbitrary code, exploit requires attacker to control LDAP server.",
    "recommendation": "Upgrade to Log4j2 version 2.17.1 or later (or back-port 2.12.4 / 2.3.2)."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified.",
    "recommendation": "Does not affect PostgreSQL 9.2.3; affects older versions (7.2.1 and 8.1)."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation.",
    "recommendation": "Does not affect PostgreSQL 9.2.3; affects older versions (7.2.1 and 8.1)."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeh",
    "recommendation": "This CVE affects the pgjdbc JDBC driver, not the PostgreSQL 9.2 server."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers ",
    "recommendation": "Upgrade to PostgreSQL 9.2.4 or later."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "recommendation": "Upgrade to PostgreSQL 9.2.4 or later."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": true,
    "severity": "high",
    "cvss_score": 7.2,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit requires superuser or group membership.",
    "recommendation": "Upgrade to the latest supported PostgreSQL version."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.1,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the application invokes this method and queries malicious schemas, exploit requires tricking the user int",
    "recommendation": "This CVE affects the pgjdbc JDBC driver, not the PostgreSQL 9.2 server."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input.",
    "recommendation": "Does not affect OpenSSH 9.x; affects ancient versions (2.x-3.x)."
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentication, letting remote attackers execute arbitrary code, exploit requires specific PAM configuration.",
    "recommendation": "Does not affect OpenSSH 9.x; affects ancient versions (2.x-3.x)."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled.",
    "recommendation": "Does not affect OpenSSH 9.x; affects ancient versions (2.x-3.x)."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires remote network access.",
    "recommendation": "Does not affect OpenSSH 9.x; affects ancient versions (2.x-3.x)."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input.",
    "recommendation": "Does not affect OpenSSH 9.x; affects ancient versions (2.x-3.x)."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding agent, exploit requires agent forwarding to attacker-controlled system.",
    "recommendation": "Upgrade to OpenSSH 9.8p1 or later. Affects bastion only."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding agent, exploit requires agent forwarding to attacker-controlled system.",
    "recommendation": "Does not affect non-bastion hosts (9.9p1)."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "severity": "high",
    "cvss_score": 8.1,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit requires no authentication.",
    "recommendation": "Upgrade to OpenSSH 9.8p1 or later. Affects bastion only."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 8.1,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit requires no authentication.",
    "recommendation": "Does not affect non-bastion hosts (9.9p1)."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.5,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipulate cookie creation.",
    "recommendation": "Does not affect OpenSSH 9.x; affects older versions (7.9 or earlier)."
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": false,
    "severity": "medium",
    "cvss_score": 6.8,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, exploit requires man-in-the-middle position.",
    "recommendation": "Does not affect OpenSSH 9.x; affects older versions (7.9 or earlier)."
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": false,
    "severity": "medium",
    "cvss_score": 6.8,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to manipulate client output, exploit requires man-in-the-middle position.",
    "recommendation": "Does not affect OpenSSH 9.x; affects older versions (7.9 or earlier)."
  },
  {
    "cve_id": "CVE-2003-0789",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache before 2.0.48 with threaded MPM contains a CGI redirect path handling issue caused by improper handling in mod_cgid, letting Apache send CGI output to the wrong client, exploit requires specific server configuration.",
    "recommendation": "Does not affect Apache HTTP Server 2.4.49; affects unrelated or older products."
  },
  {
    "cve_id": "CVE-1999-1237",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "Multiple buffer overflows in smbvalid/smbval SMB authentication library used in Apache::AuthenSmb allow remote attackers to execute arbitrary commands via long username, long password, and other methods.",
    "recommendation": "Does not affect Apache HTTP Server 2.4.49; affects unrelated or older products."
  },
  {
    "cve_id": "CVE-1999-1293",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache 1.2.5 and earlier contains a denial of service caused by malformed FTP commands in mod_proxy, letting remote attackers cause Apache to dump core, exploit requires sending malformed FTP commands.",
    "recommendation": "Does not affect Apache HTTP Server 2.4.49; affects unrelated or older products."
  },
  {
    "cve_id": "CVE-2013-1777",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Geronimo 3.x before 3.0.1, used in IBM WebSphere Application Server Community Edition 3.0.0.3, contains a remote code execution caused by improper RMI classloader implementation in JMX Remoting, letting remote attackers execute arbitrary code via crafted serialized objects, exploit requires n",
    "recommendation": "Does not affect Apache HTTP Server 2.4.49; affects unrelated or older products."
  },
  {
    "cve_id": "CVE-2009-2412",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Portable Runtime (APR) 0.9.x and 1.3.x contain multiple integer overflows caused by crafted calls to allocator_alloc, apr_palloc, apr_rmm_malloc, apr_rmm_calloc, or apr_rmm_realloc functions in memory management components, letting remote attackers cause denial of service or execute arbitrary",
    "recommendation": "Does not affect Apache HTTP Server 2.4.49; affects unrelated or older products."
  }
]
```

## Report

# ABAC Policy Mining Report

## 1. Scope
Mined from Ansible configuration for `chaincorp` production environment (PCI compliance tier).

## 2. Attribute Catalog
- **Subjects**: 4 users (admin, developer, dba, postgres), 3 groups (sudo, developers, dba), 3 clearance levels (secret, confidential, none), 4 departments (operations, engineering, data, system).
- **Resources**: 4 hosts (bastion, web, app, db), 4 services (http, app, postgres, ssh), 1 explicit path, 4 networks.
- **Environment**: production, pci, 365-day retention.

## 3. Rules Extracted
14 rules total:
- 4 SSH login rules (per-host-group)
- 1 sudo rule (bastion, secret clearance, password required)
- 1 DB superuser rule (dba group)
- 4 network connectivity rules (firewalld/pg_hba)
- 3 filesystem rules (postgres data dir)
- 1 default-deny rule

## 4. Vulnerability Assessment
Pinned vulnerable packages:
- **Log4j 2.14.1**: CVE-2021-44228 (Log4Shell), CVE-2021-45046, CVE-2021-44832 affect pinned version.
- **PostgreSQL 9.2.3**: CVE-2013-1902, CVE-2013-1903, CVE-2019-9193 affect pinned version.
- **OpenSSH 9.1p1 (bastion)**: CVE-2024-6387, CVE-2023-38408 affect pinned version.
- **OpenSSH 9.9p1 (others)**: Not affected by the above.
- **Apache HTTP Server 2.4.49**: No critical remote/KEV CVEs returned for this specific version in the scoped search; however, 2.4.49 is known to be vulnerable to path traversal and RCE (CVE-2021-41773, CVE-2021-42013) which were not surfaced.

## 5. Ambiguities & Gaps
- No explicit secret/credential management (Ansible Vault, HashiCorp Vault) referenced in the configuration.
- No explicit DENY rules in firewalld; all rules are additive allows.
- Only one filesystem ACL is explicitly configured (PostgreSQL data dir); remaining OS paths rely on package defaults.
- SSH password vs key authentication not explicitly configured.
- Session logging or audit obligations not defined in the playbook.
- The `apache` vulnerability search returned CVEs for other Apache projects (ActiveMQ, Solr, Axis2, Log4j); these were evaluated as unrelated to `apache2` HTTP Server and discarded.
