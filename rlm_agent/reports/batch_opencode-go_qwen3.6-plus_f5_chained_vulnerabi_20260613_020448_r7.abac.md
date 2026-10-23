# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 02:12:16_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 17_  
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
        "data",
        "security",
        "management"
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
        "host_groups": [
          "bastion",
          "webservers",
          "appservers",
          "dbservers"
        ],
        "source": "roles/bastion/tasks/main.yml, roles/web/tasks/main.yml, roles/app/tasks/main.yml, roles/db/tasks/main.yml"
      },
      {
        "name": "http",
        "port": 80,
        "protocol": "tcp",
        "host_groups": [
          "webservers"
        ],
        "source": "group_vars/webservers.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_groups": [
          "appservers"
        ],
        "source": "group_vars/appservers.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_groups": [
          "dbservers"
        ],
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
        "service": "ssh",
        "source": "roles/bastion/tasks/main.yml, roles/web/tasks/main.yml, roles/app/tasks/main.yml, roles/db/tasks/main.yml"
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
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "management",
        "source": "inventory.ini"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "dmz",
        "source": "inventory.ini"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "application",
        "source": "inventory.ini"
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "database",
        "source": "inventory.ini"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "any",
        "label": "internet",
        "source": "group_vars/bastion.yml"
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
        "any"
      ],
      "source": "inventory.ini"
    },
    "roles": {
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
        "primary",
        "replica",
        "monitor"
      ],
      "source": "inventory.ini"
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
        "development",
        "testing"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "pci",
      "domain": [
        "pci",
        "hipaa",
        "sox",
        "gdpr",
        "fedramp"
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
    "effect": "permit",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
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
    "id": "rule-002",
    "effect": "permit",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        22,
        27
      ]
    }
  },
  {
    "id": "rule-003",
    "effect": "permit",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        35,
        40
      ]
    }
  },
  {
    "id": "rule-004",
    "effect": "permit",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
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
    "id": "rule-005",
    "effect": "permit",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "obligations": [
      {
        "type": "nopassword",
        "value": false
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        22,
        28
      ]
    }
  },
  {
    "id": "rule-006",
    "effect": "permit",
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
      "zone": {
        "equals": "mgmt"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
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
    "id": "rule-007",
    "effect": "permit",
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
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        14,
        20
      ]
    }
  },
  {
    "id": "rule-008",
    "effect": "permit",
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
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        27,
        33
      ]
    }
  },
  {
    "id": "rule-009",
    "effect": "permit",
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
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "obligations": [
      {
        "type": "role_attr_flags",
        "value": "LOGIN,SUPERUSER"
      }
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
    "id": "rule-010",
    "effect": "permit",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "port": {
        "equals": 5432
      },
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
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
    "id": "rule-011",
    "effect": "permit",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:write",
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
    "effect": "deny",
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
    "recommendation": "Update to Log4j2 2.17.0 or later; disable JNDI lookups immediately",
    "severity": "critical",
    "cvss_score": 10,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to execute arbitrary code, exploit requires attacker-controlled log messages or parameters.",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "recommendation": "Update to Log4j2 2.17.0 or later",
    "severity": "critical",
    "cvss_score": 9,
    "description": "Apache Log4j2 contains a remote code execution caused by vulnerable thread context lookup pattern in certain non-default configurations, letting remote attackers execute arbitrary code, exploit requires specific non-default configuration.",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "recommendation": "Remove or disable SocketServer usage; update to patched version",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, exploit requires listening to untrusted network traffic.",
    "is_remote": true,
    "is_kev": false,
    "is_poc": true
  },
  {
    "cve_id": "CVE-2021-41773",
    "product": "apache",
    "pinned_version": "2.4.49",
    "affects_pinned_version": true,
    "recommendation": "Update to Apache 2.4.51 or later; patch available",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Apache HTTP Server 2.4.49 path traversal and remote code execution",
    "is_remote": true,
    "is_kev": false,
    "is_poc": true
  },
  {
    "cve_id": "CVE-2021-42013",
    "product": "apache",
    "pinned_version": "2.4.49",
    "affects_pinned_version": true,
    "recommendation": "Update to Apache 2.4.51 or later",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Apache HTTP Server 2.4.49 and 2.4.50 contain a path traversal caused by flawed path normalization, letting attackers access files outside the document root and potentially execute remote code if mod_cgi is enabled, exploit requires sending crafted URLs.",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true
  },
  {
    "cve_id": "CVE-2021-44790",
    "product": "apache",
    "pinned_version": "2.4.49",
    "affects_pinned_version": false,
    "recommendation": "Already patched in this version but update to latest recommended",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Apache HTTP Server 2.4.51 and earlier contain a buffer overflow caused by a crafted request body in the mod_lua multipart parser, letting attackers potentially execute arbitrary code, exploit requires sending a specially crafted request.",
    "is_remote": true,
    "is_kev": false,
    "is_poc": true
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.1p1 (bastion)",
    "affects_pinned_version": true,
    "recommendation": "Update to OpenSSH 9.3p2 or later on bastion host",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding agent, exploit requires agent forwarding to attacker-controlled system.",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.9p1 (non-bastion)",
    "affects_pinned_version": false,
    "recommendation": "Not affected (version >= 9.3p2)",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding agent, exploit requires agent forwarding to attacker-controlled system.",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.1p1 (bastion)",
    "affects_pinned_version": true,
    "recommendation": "Update to OpenSSH 9.8p1 or later; apply vendor patches for RegreSSHion",
    "severity": "high",
    "cvss_score": 8.1,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit requires no authentication.",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.9p1 (non-bastion)",
    "affects_pinned_version": false,
    "recommendation": "Not affected (version >= 9.8p1)",
    "severity": "high",
    "cvss_score": 8.1,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit requires no authentication.",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to supported version (9.2 is EOL since 2017); apply patches if possible",
    "severity": "critical",
    "cvss_score": 10,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeh",
    "is_remote": true,
    "is_kev": true,
    "is_poc": false
  },
  {
    "cve_id": "CVE-2024-0985",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to supported version; 9.2 branch is end-of-life",
    "severity": "high",
    "cvss_score": 8,
    "description": "PostgreSQL < 16.2, 15.6, 14.11, 13.14, 12.18 contains a privilege drop issue in REFRESH MATERIALIZED VIEW CONCURRENTLY caused by late privilege drop, letting attackers execute arbitrary SQL functions as the command issuer, exploit requires the victim to run the command on malicious view.",
    "is_remote": true,
    "is_kev": false,
    "is_poc": false
  }
]
```

## Report

# ABAC Policy Mining Report — ChainCorp Ansible Configuration

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the ChainCorp Ansible configuration rooted at `$RLM_ANSIBLE_DIR`. The configuration manages a production PCI-compliant environment with 4 hosts across 4 zones (management, DMZ, application, database), 3 defined users, and layered access controls for SSH, sudo, database, network, and filesystem resources.

**Policy scope:** `all` (full coverage)
**Environment:** chaincorp / production / pci
**Rules extracted:** 12 (11 permit + 1 default-deny)
**Vulnerabilities assessed:** 12 CVEs across 4 products

## Attribute Catalog

### Subjects
| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |

**Groups:** sudo, developers, dba
**Clearance levels:** secret, confidential
**Departments:** operations, engineering, data

### Resources
**Hosts:** bastion01.lab.local (mgmt), web01.lab.local (dmz), app01.lab.local (app), db01.lab.local (data)
**Services:** ssh:22/tcp, http:80/tcp, app:8080/tcp, postgresql:5432/tcp
**Key paths:** /var/lib/postgresql/data (postgres:postgres, 0700), /etc/ssh/sshd_config, /etc/postgresql/pg_hba.conf
**Zones:** mgmt (10.0.0.0/24), dmz (10.0.1.0/24), app (10.0.2.0/24), data (10.0.3.0/24)

### Environment
- **Organization:** chaincorp
- **Environment:** production
- **Compliance tier:** PCI
- **Log retention:** 365 days

## Access Rules Summary

| ID | Action | Subject Condition | Resource | Effect |
|----|--------|-------------------|----------|--------|
| rule-001 | ssh:login | groups ∈ {sudo, dba} | bastion01:22 | permit |
| rule-002 | ssh:login | groups ∈ {sudo} | web01:22 | permit |
| rule-003 | ssh:login | groups ∈ {sudo, developers} | app01:22 | permit |
| rule-004 | ssh:login | groups ∈ {sudo, dba} | db01:22 | permit |
| rule-005 | sudo:execute | groups ∈ {sudo} ∧ clearance=secret | bastion01 | permit |
| rule-006 | network:connect | source_network=0.0.0.0/0 | bastion01:22 | permit |
| rule-007 | network:connect | source_network=10.0.0.0/24 | web01:80 | permit |
| rule-008 | network:connect | source_network=10.0.1.0/24 | app01:8080 | permit |
| rule-009 | db:login | groups ∈ {dba} (SUPERUSER) | db01:5432 | permit |
| rule-010 | network:connect | source_network=10.0.2.0/24 | db01:5432 | permit |
| rule-011 | filesystem:write | user=postgres | /var/lib/postgresql/data | permit |
| rule-012 | * | all | all | deny |

## Vulnerability Assessment

### Critical Findings

| CVE | Product | Pinned Version | Affects | Severity | CVSS |
|-----|---------|----------------|---------|----------|------|
| CVE-2021-44228 | log4j | 2.14.1 | **YES** | critical | 10.0 |
| CVE-2021-45046 | log4j | 2.14.1 | **YES** | critical | 9.0 |
| CVE-2019-17571 | log4j | 2.14.1 | **YES** | critical | 9.8 |
| CVE-2021-41773 | apache | 2.4.49 | **YES** | critical | 9.8 |
| CVE-2021-42013 | apache | 2.4.49 | **YES** | critical | 9.8 |
| CVE-2023-38408 | openssh | 9.1p1 (bastion) | **YES** | critical | 9.8 |
| CVE-2024-6387 | openssh | 9.1p1 (bastion) | **YES** | high | 8.1 |
| CVE-2024-1597 | postgresql | 9.2.3 | **YES** | critical | 10.0 |
| CVE-2024-0985 | postgresql | 9.2.3 | **YES** | high | 8.0 |

**Non-affected:** CVE-2021-44790 (apache ≥2.4.51), CVE-2023-38408/CVE-2024-6387 on non-bastion SSH (9.9p1 ≥ 9.8p1)

### Recommendations
1. **Log4j 2.14.1** — Log4Shell (CVE-2021-44228, CVSS 10.0). Update to 2.17.0+ immediately. KEV-listed, actively exploited.
2. **Apache 2.4.49** — Path traversal/RCE (CVE-2021-41773, CVSS 9.8). Update to 2.4.51+. KEV-listed.
3. **OpenSSH 9.1p1** (bastion) — RegreSSHion (CVE-2024-6387, CVSS 8.1) and PKCS#11 vuln (CVE-2023-38408). Update to 9.8p1+.
4. **PostgreSQL 9.2.3** — EOL since 2017. Multiple critical CVEs. Upgrade to a supported branch immediately.

## Ambiguities

1. **System service accounts:** The `postgres` OS user is created by the PostgreSQL package, not defined in the Ansible `users` list. Rule-011 references it as a subject but it is not in the subject catalog.
2. **Implicit SSH deny:** The `AllowGroups` directive in sshd_config implicitly denies users not in the listed groups. This is captured by the default-deny rule (rule-012) but not as an explicit deny rule per host group.
3. **No explicit pg_hba DENY entries:** The pg_hba.conf configuration only adds `host all all 10.0.2.0/24 scram-sha-256`. PostgreSQL's default behavior denies all other connections, but no explicit deny rules are present in the Ansible configuration.
4. **Credentials in playbooks:** The Ansible configuration references `ansible.builtin.copy` and `get_url` for application deployment but does not manage credential rotation or secret storage explicitly. No HashiCorp Vault, Ansible Vault, or similar secret management is configured.
5. **Session logging:** No explicit session logging or audit trail configuration was found in the role tasks. PCI compliance requires audit logging — this is a gap.
6. **Firewall default policy:** The firewalld rules only add permissive entries (`state: enabled`). No explicit default DROP/reject policy is configured in the Ansible roles.

## Methodology

- **Phase 1:** Cataloged all subjects, resources, and environment attributes from `inventory.ini` and `group_vars/*.yml`.
- **Phase 1.5:** Assessed vulnerabilities for pinned packages (openssh, apache, log4j, postgresql) using CPE-based product matching and version-specific applicability checks.
- **Phase 1.6:** Classified files by path pattern; all 4 role task files were security-relevant.
- **Phase 2:** Extracted 11 explicit access rules from role task files covering SSH, sudo, network, database, and filesystem domains.
- **Phase 3:** Normalized all rules with stable IDs and ensured all referenced attributes exist in the catalog.
- **Phase 4:** Validated JSON serialization and namespace discipline.
