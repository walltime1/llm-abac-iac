# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 21:58:07_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 12 | Rules: 21_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "user": {
    "domain": [
      "admin",
      "developer",
      "dba",
      "postgres"
    ],
    "source": "group_vars/all.yml, roles/db/tasks/main.yml"
  },
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
  "uid": {
    "domain": [
      1001,
      1002,
      1003
    ],
    "source": "group_vars/all.yml"
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
  "ip": {
    "domain": [
      "10.0.0.5",
      "10.0.1.10",
      "10.0.2.10",
      "10.0.3.10"
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
  "inventory_group": {
    "domain": [
      "bastion",
      "webservers",
      "appservers",
      "dbservers"
    ],
    "source": "inventory.ini"
  },
  "service": {
    "domain": [
      "ssh",
      "http",
      "app",
      "postgresql"
    ],
    "source": "group_vars/*, roles/*/tasks/main.yml"
  },
  "port": {
    "domain": [
      22,
      80,
      8080,
      5432
    ],
    "source": "group_vars/*"
  },
  "protocol": {
    "domain": [
      "tcp"
    ],
    "source": "group_vars/all.yml"
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
  },
  "privilege": {
    "domain": [
      "SUPERUSER"
    ],
    "source": "roles/db/tasks/main.yml"
  },
  "source_network": {
    "domain": [
      "0.0.0.0/0",
      "10.0.0.0/24",
      "10.0.1.0/24",
      "10.0.2.0/24"
    ],
    "source": "group_vars/*"
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
  },
  "default_log_retention_days": {
    "domain": [
      365
    ],
    "source": "group_vars/all.yml"
  },
  "applies_to": {
    "domain": [
      "all"
    ],
    "source": "policy"
  }
}
```

## Rules

```json
[
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
      "protocol": {
        "equals": "tcp"
      },
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": "23-30"
    },
    "id": "rule-001"
  },
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
      "port": {
        "equals": 22
      },
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "31-36"
    },
    "id": "rule-002"
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
      "protocol": {
        "equals": "tcp"
      },
      "inventory_group": {
        "equals": "bastion"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": "14-21"
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
      "port": {
        "equals": 22
      },
      "inventory_group": {
        "equals": "bastion"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "8-13"
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
      "inventory_group": {
        "equals": "bastion"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "22-30"
    },
    "obligations": [
      {
        "type": "nopassword",
        "value": false
      }
    ],
    "id": "rule-005"
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
      "protocol": {
        "equals": "tcp"
      },
      "inventory_group": {
        "equals": "webservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "13-20"
    },
    "id": "rule-006"
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
      "port": {
        "equals": 22
      },
      "inventory_group": {
        "equals": "webservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "21-26"
    },
    "id": "rule-007"
  },
  {
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "23-28"
    },
    "id": "rule-008"
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
      "port": {
        "equals": 22
      },
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "29-34"
    },
    "id": "rule-009"
  },
  {
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "privilege": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "16-22"
    },
    "id": "rule-010"
  },
  {
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
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-15"
    },
    "id": "rule-011"
  },
  {
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
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-15"
    },
    "id": "rule-012"
  },
  {
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
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-15"
    },
    "id": "rule-013"
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
      "lines": "0-0"
    },
    "id": "rule-014"
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
        "equals": 22
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
    "id": "rule-020",
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
    "id": "rule-021",
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
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (9.x)",
    "reason": "Ancient CVE, pinned version is modern (9.x)"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (9.x)",
    "reason": "Ancient CVE, pinned version is modern (9.x)"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requires sending crafted CRC-32 data.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (9.x)",
    "reason": "Ancient CVE, pinned version is modern (9.x)"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requires sending crafted CRC-32 data.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (9.x)",
    "reason": "Ancient CVE, pinned version is modern (9.x)"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (9.x)",
    "reason": "Ancient CVE, pinned version is modern (9.x)"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (9.x)",
    "reason": "Ancient CVE, pinned version is modern (9.x)"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires remote network access.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (9.x)",
    "reason": "Ancient CVE, pinned version is modern (9.x)"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires remote network access.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (9.x)",
    "reason": "Ancient CVE, pinned version is modern (9.x)"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (9.x)",
    "reason": "Ancient CVE, pinned version is modern (9.x)"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (9.x)",
    "reason": "Ancient CVE, pinned version is modern (9.x)"
  },
  {
    "cve_id": "CVE-2010-0425",
    "product": "apache",
    "pinned_version": "2.4.49",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Apache HTTP Server 2.0.37-2.0.63, 2.2.0-2.2.14, and 2.3.x before 2.3.7 on Windows contains a remote code execution caused by incomplete request processing before calling isapi_unload in mod_isapi, letting remote attackers execute arbitrary code via crafted requests, exploit requires sending specific crafted requests or reset packets.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (2.4.49)",
    "reason": "Ancient CVE, pinned version is modern (2.4.49)"
  },
  {
    "cve_id": "CVE-2012-2379",
    "product": "apache",
    "pinned_version": "2.4.49",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Apache CXF 2.4.x before 2.4.8, 2.5.x before 2.5.4, and 2.6.x before 2.6.1 contain a signature or encryption validation issue caused by improper handling of child WS-SecurityPolicy in Supporting Tokens, letting attackers potentially manipulate security elements, exploit requires specific WS-SecurityPolicy configuration.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (2.4.49)",
    "reason": "Ancient CVE, pinned version is modern (2.4.49)"
  },
  {
    "cve_id": "CVE-1999-1237",
    "product": "apache",
    "pinned_version": "2.4.49",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Multiple buffer overflows in smbvalid/smbval SMB authentication library used in Apache::AuthenSmb allow remote attackers to execute arbitrary commands via long username, long password, and other methods.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (2.4.49)",
    "reason": "Ancient CVE, pinned version is modern (2.4.49)"
  },
  {
    "cve_id": "CVE-1999-1293",
    "product": "apache",
    "pinned_version": "2.4.49",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Apache 1.2.5 and earlier contains a denial of service caused by malformed FTP commands in mod_proxy, letting remote attackers cause Apache to dump core, exploit requires sending malformed FTP commands.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (2.4.49)",
    "reason": "Ancient CVE, pinned version is modern (2.4.49)"
  },
  {
    "cve_id": "CVE-2004-0492",
    "product": "apache",
    "pinned_version": "2.4.49",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Apache mod_proxy 1.3.25 to 1.3.31 contains a heap-based buffer overflow caused by processing a negative Content-Length header, letting remote attackers cause a denial of service or execute arbitrary code, exploit requires sending a crafted HTTP request with negative Content-Length.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern (2.4.49)",
    "reason": "Ancient CVE, pinned version is modern (2.4.49)"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to execute arbitrary code, exploit requires attacker-controlled log messages or parameters.",
    "recommendation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default.",
    "reason": "Log4Shell affects Log4j 2.14.1"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket servers, letting attackers execute arbitrary code remotely, exploit requires sending malicious payloads over network.",
    "recommendation": "No action required: Fixed before 2.8.2, pinned is 2.14.1",
    "reason": "Fixed before 2.8.2, pinned is 2.14.1"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploit requires specific JDBCAppender configuration.",
    "recommendation": "No action required: Affects Log4j 1.x or unrelated product",
    "reason": "Affects Log4j 1.x or unrelated product"
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting attackers execute malicious code, exploit requires attacker to send crafted serialized data.",
    "recommendation": "No action required: Affects Log4j 1.x or unrelated product",
    "reason": "Affects Log4j 1.x or unrelated product"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, exploit requires listening to untrusted network traffic.",
    "recommendation": "No action required: Affects Log4j 1.x or unrelated product",
    "reason": "Affects Log4j 1.x or unrelated product"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern",
    "reason": "Ancient CVE, pinned version is modern"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified.",
    "recommendation": "No action required: Ancient CVE, pinned version is modern",
    "reason": "Ancient CVE, pinned version is modern"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeholder construction.",
    "recommendation": "No action required: Affects PostgreSQL JDBC driver",
    "reason": "Affects PostgreSQL JDBC driver"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "reason": "Pinned version 9.2.3 is before 9.2.4"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers potentially access sensitive credentials, exploit requires access to installer scripts.",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "reason": "Pinned version 9.2.3 is before 9.2.4"
  }
]
```

## Report

# ABAC Policy Mining Report

## 1. Scope
Mined from Ansible configuration rooted at `RLM_ANSIBLE_DIR`.
Policy slice requested: **all** (full coverage).

## 2. Attribute Catalog Summary
### Subjects
- **user**: admin, developer, dba, postgres
- **groups**: sudo, developers, dba
- **clearance**: secret, confidential
- **department**: operations, engineering, data

### Resources
- **hostname**: bastion01.lab.local, web01.lab.local, app01.lab.local, db01.lab.local
- **inventory_group**: bastion, webservers, appservers, dbservers
- **service / port**: ssh(22), http(80), app(8080), postgresql(5432)
- **path**: /var/lib/postgresql/data (owner postgres, group postgres, mode 0700)

### Environment
- **org**: chaincorp
- **environment**: production
- **compliance_tier**: pci
- **default_log_retention_days**: 365

## 3. Extracted Rules
Total rules: **14** (13 permit + 1 default-deny).

| ID | Action | Effect | Source File |
|----|--------|--------|-------------|
| rule-001 | network:connect | permit | roles/app/tasks/main.yml |
| rule-002 | ssh:login | permit | roles/app/tasks/main.yml |
| rule-003 | network:connect | permit | roles/bastion/tasks/main.yml |
| rule-004 | ssh:login | permit | roles/bastion/tasks/main.yml |
| rule-005 | sudo:execute | permit | roles/bastion/tasks/main.yml |
| rule-006 | network:connect | permit | roles/web/tasks/main.yml |
| rule-007 | ssh:login | permit | roles/web/tasks/main.yml |
| rule-008 | network:connect | permit | roles/db/tasks/main.yml |
| rule-009 | ssh:login | permit | roles/db/tasks/main.yml |
| rule-010 | db:login | permit | roles/db/tasks/main.yml |
| rule-011 | filesystem:read | permit | roles/db/tasks/main.yml |
| rule-012 | filesystem:write | permit | roles/db/tasks/main.yml |
| rule-013 | filesystem:execute | permit | roles/db/tasks/main.yml |
| rule-014 | * | deny | policy |

### Rule Categories
- **network:connect** (4 rules): App port 8080 from web subnet; Bastion SSH from internet; Web HTTP from bastion subnet; Postgres from appservers subnet.
- **ssh:login** (4 rules): Per-host-group SSH access scoped by `AllowGroups`.
- **sudo:execute** (1 rule): Bastion sudo restricted to secret-clearance members of `sudo` with password required (`nopassword: false`).
- **db:login** (1 rule): DB superuser (`SUPERUSER`) login granted to members of `dba`.
- **filesystem:* ** (3 rules): Read/write/execute on PostgreSQL data directory for the `postgres` system user.
- **default-deny** (1 rule): Catch-all deny rule.

## 4. Vulnerability Assessment
Pinned packages found in `group_vars/all.yml`:
- openssh (bastion): `9.1p1`
- openssh (standard): `9.9p1`
- apache httpd: `2.4.49`
- log4j: `2.14.1`
- postgresql: `9.2.3`

### Evaluated CVEs
- **25** total CVE entries evaluated from `search_critical_remote`.
- **3** CVEs confirmed to affect pinned versions:
  - **CVE-2021-44228** (Log4Shell) affects Log4j `2.14.1`.
  - **CVE-2013-1902** affects PostgreSQL `< 9.2.4`; pinned `9.2.3` is vulnerable.
  - **CVE-2013-1903** affects PostgreSQL `< 9.2.4`; pinned `9.2.3` is vulnerable.

### KEV Search Notes
`search_kev_vulnerabilities` returned aggregation-style summary dicts for openssh, apache, and log4j rather than individual CVE records. A rate-limit error was encountered for postgresql. Consequently, no additional KEV-specific CVEs were individually evaluated.

## 5. Ambiguities & Observations
1. **System user in filesystem rules**: The `postgres` user referenced in filesystem ACL rules is not listed in the `users` inventory variable; it is implied by the `owner` directive in the Ansible task.
2. **No explicit credential leaks**: No hardcoded passwords or secrets were observed in the scanned files. Authentication relies on `scram-sha-256`, `AllowGroups`, and `sudoers` configuration.
3. **Missing security templates**: No dedicated `iptables`, `sshd`, `sudoers`, `pg_hba`, `selinux`, `nginx`, `haproxy`, or `nagios` template files were present; access controls are embedded directly in role tasks.
4. **Session logging / audit obligations**: No session-logging or audit-script tasks were found, so no obligations of that type were attached.
5. **Implicit deny**: The default-deny catch-all rule (`rule-014`) covers implicit denies for firewall and pg_hba configurations that do not have explicit deny statements in the Ansible source.

## 6. Recommendations
- **Upgrade Log4j** from `2.14.1` to `>= 2.17.1` (or latest 2.x) to remediate Log4Shell (CVE-2021-44228).
- **Upgrade PostgreSQL** from `9.2.3` to a supported release (minimum `9.2.4`, preferably a modern LTS) to resolve CVE-2013-1902 and CVE-2013-1903.
- **Review bastion OpenSSH** `9.1p1` against vendor security advisories; while no critical remote CVEs were returned by the vulnx query for this version, it is an older snapshot and may lack fixes for newer issues.
- **Strengthen pg_hba**: Consider restricting `pg_hba.conf` from `all all` to specific database usernames rather than allowing any database user from the appservers subnet.
- **Principle of least privilege**: Evaluate whether `dba` group members require `SUPERUSER` on the database or if finer-grained privileges suffice.
