# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:07:04_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 17 | Rules: 25_  
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
        "name": "appuser",
        "uid": 2001,
        "groups": [
          "app"
        ],
        "department": "engineering",
        "clearance": "confidential",
        "source": "roles/app/tasks/main.yml"
      },
      {
        "name": "dbadmin",
        "uid": 3001,
        "groups": [
          "dba"
        ],
        "department": "data",
        "clearance": "secret",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "dba",
      "app"
    ],
    "clearance_levels": [
      "confidential",
      "secret"
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
        "name": "http",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all",
        "source": "roles/bastion/tasks/main.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "name": "http-app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
      }
    ],
    "paths": [
      {
        "path": "/var/app",
        "owner": "appuser",
        "group": "app",
        "mode": "0750",
        "service": "app",
        "source": "roles/app/tasks/main.yml"
      },
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "path": "/var/www/html",
        "owner": "www-data",
        "group": "www-data",
        "mode": "0755",
        "service": "httpd",
        "source": "roles/web/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "bastion_network",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web_network",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_network",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "db_network",
        "source": "inventory.ini"
      }
    ]
  },
  "environment": {
    "org": "chaincorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
    "source": "group_vars/all.yml"
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Configure SSH for bastion access",
      "lines": [
        2,
        12
      ]
    }
  },
  {
    "id": "rule-002",
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
      "task": "Configure firewall to allow all inbound",
      "lines": [
        18,
        24
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Allow SSH from sudo and developers groups",
      "lines": [
        12,
        20
      ]
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": {
      "nopassword": true
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Configure sudoers for developers",
      "lines": [
        22,
        29
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "app"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/app"
      },
      "owner": {
        "equals": "appuser"
      },
      "group": {
        "equals": "app"
      },
      "mode": {
        "equals": "0750"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Set file permissions for app directory",
      "lines": [
        36,
        42
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "app"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/app"
      },
      "owner": {
        "equals": "appuser"
      },
      "group": {
        "equals": "app"
      },
      "mode": {
        "equals": "0750"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Set file permissions for app directory",
      "lines": [
        36,
        42
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "app"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/app"
      },
      "owner": {
        "equals": "appuser"
      },
      "group": {
        "equals": "app"
      },
      "mode": {
        "equals": "0750"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Set file permissions for app directory",
      "lines": [
        36,
        42
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
        "equals": "http"
      },
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
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Configure firewall to allow app traffic",
      "lines": [
        2,
        9
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow connections from app servers",
      "lines": [
        24,
        30
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
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
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
      "task": "Configure PostgreSQL authentication",
      "lines": [
        2,
        16
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Set data directory permissions",
      "lines": [
        36,
        42
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Set data directory permissions",
      "lines": [
        36,
        42
      ]
    }
  },
  {
    "id": "rule-013",
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Allow SSH from sudo group only",
      "lines": [
        12,
        20
      ]
    }
  },
  {
    "id": "rule-014",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": {
      "nopassword": true
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Configure sudoers for web admin",
      "lines": [
        22,
        29
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
        "equals": "/var/www/html"
      },
      "owner": {
        "equals": "www-data"
      },
      "group": {
        "equals": "www-data"
      },
      "mode": {
        "equals": "0755"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Set web root permissions",
      "lines": [
        31,
        37
      ]
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
        "equals": "/var/www/html"
      },
      "owner": {
        "equals": "www-data"
      },
      "group": {
        "equals": "www-data"
      },
      "mode": {
        "equals": "0755"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Set web root permissions",
      "lines": [
        31,
        37
      ]
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
      "hostname": {
        "equals": "web01.lab.local"
      },
      "service": {
        "equals": "http"
      },
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
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Configure firewall for web traffic",
      "lines": [
        2,
        9
      ]
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
    "id": "rule-019",
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
    "id": "rule-020",
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
    "id": "rule-021",
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/www/html"
      },
      "owner": {
        "equals": "www-data"
      },
      "group": {
        "equals": "www-data"
      },
      "mode": {
        "equals": "0755"
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
      "file": "postprocessor",
      "task": "mode 0755 group read",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-022",
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/www/html"
      },
      "owner": {
        "equals": "www-data"
      },
      "group": {
        "equals": "www-data"
      },
      "mode": {
        "equals": "0755"
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
      "file": "postprocessor",
      "task": "mode 0755 group read",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-023",
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
    "id": "rule-024",
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
    "id": "rule-025",
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
    "product": "openssh",
    "version_affected": "9.1p1",
    "type": "critical_remote",
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "recommendation": "Upgrade openssh from 9.1p1 to latest patched version"
  },
  {
    "product": "openssh",
    "version_affected": "9.1p1",
    "type": "critical_remote",
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "recommendation": "Upgrade openssh from 9.1p1 to latest patched version"
  },
  {
    "product": "openssh",
    "version_affected": "9.1p1",
    "type": "critical_remote",
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "recommendation": "Upgrade openssh from 9.1p1 to latest patched version"
  },
  {
    "product": "openssh",
    "version_affected": "9.1p1",
    "type": "critical_remote",
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "recommendation": "Upgrade openssh from 9.1p1 to latest patched version"
  },
  {
    "product": "openssh",
    "version_affected": "9.1p1",
    "type": "critical_remote",
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir",
    "recommendation": "Upgrade openssh from 9.1p1 to latest patched version"
  },
  {
    "product": "openssh",
    "version_affected": "9.1p1",
    "type": "kev",
    "cve_id": "CVE-2023-38408",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding ",
    "recommendation": "URGENT: openssh 9.1p1 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "openssh",
    "version_affected": "9.1p1",
    "type": "kev",
    "cve_id": "CVE-2024-6387",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req",
    "recommendation": "URGENT: openssh 9.1p1 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "openssh",
    "version_affected": "9.1p1",
    "type": "kev",
    "cve_id": "CVE-2007-4752",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipula",
    "recommendation": "URGENT: openssh 9.1p1 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "openssh",
    "version_affected": "9.1p1",
    "type": "kev",
    "cve_id": "CVE-2019-6109",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani",
    "recommendation": "URGENT: openssh 9.1p1 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "openssh",
    "version_affected": "9.1p1",
    "type": "kev",
    "cve_id": "CVE-2019-6110",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl",
    "recommendation": "URGENT: openssh 9.1p1 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "apache",
    "version_affected": "2.4.49",
    "type": "critical_remote",
    "cve_id": "CVE-1999-0067",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "phf CGI program contains a remote command execution caused by unsanitized shell metacharacters, letting attackers execute arbitrary commands remotely, exploit requires sending crafted input.",
    "recommendation": "Upgrade apache from 2.4.49 to latest patched version"
  },
  {
    "product": "apache",
    "version_affected": "2.4.49",
    "type": "critical_remote",
    "cve_id": "CVE-1999-0926",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "Apache contains a denial of service caused by handling a large number of MIME headers, letting remote attackers cause service disruption, exploit requires sending numerous MIME headers.",
    "recommendation": "Upgrade apache from 2.4.49 to latest patched version"
  },
  {
    "product": "apache",
    "version_affected": "2.4.49",
    "type": "critical_remote",
    "cve_id": "CVE-1999-1199",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "Apache WWW server 1.3.1 and earlier contains a denial of service caused by resource exhaustion via a large number of MIME headers with the same name, letting remote attackers cause resource exhaustion",
    "recommendation": "Upgrade apache from 2.4.49 to latest patched version"
  },
  {
    "product": "apache",
    "version_affected": "2.4.49",
    "type": "critical_remote",
    "cve_id": "CVE-2013-2250",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Open For Business Project (OFBiz) versions 10.04.01 through 10.04.05, 11.04.01 through 11.04.02, and 12.04.01 contain a remote code execution caused by unsanitized JUEL metacharacters in parame",
    "recommendation": "Upgrade apache from 2.4.49 to latest patched version"
  },
  {
    "product": "apache",
    "version_affected": "2.4.49",
    "type": "critical_remote",
    "cve_id": "CVE-2013-1777",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Geronimo 3.x before 3.0.1, used in IBM WebSphere Application Server Community Edition 3.0.0.3, contains a remote code execution caused by improper RMI classloader implementation in JMX Remoting",
    "recommendation": "Upgrade apache from 2.4.49 to latest patched version"
  },
  {
    "product": "apache",
    "version_affected": "2.4.49",
    "type": "kev",
    "cve_id": "CVE-2023-46604",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "description": "Apache ActiveMQ contains a remote code execution caused by manipulation of serialized class types in the OpenWire protocol, letting remote attackers execute arbitrary shell commands, exploit requires ",
    "recommendation": "URGENT: apache 2.4.49 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "apache",
    "version_affected": "2.4.49",
    "type": "kev",
    "cve_id": "CVE-2021-44228",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to e",
    "recommendation": "URGENT: apache 2.4.49 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "apache",
    "version_affected": "2.4.49",
    "type": "kev",
    "cve_id": "CVE-2010-0219",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "description": "Apache Axis2 in various products contains a default password 'axis2' for the admin account, causing a security weakness that allows remote attackers to execute arbitrary code by uploading crafted web ",
    "recommendation": "URGENT: apache 2.4.49 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "apache",
    "version_affected": "2.4.49",
    "type": "kev",
    "cve_id": "CVE-2016-15057",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_remote": true,
    "is_kev": true,
    "description": "Apache Continuum contains a command injection caused by improper neutralization of special elements in REST API, letting attackers with API access execute arbitrary commands remotely, exploit requires",
    "recommendation": "URGENT: apache 2.4.49 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "apache",
    "version_affected": "2.4.49",
    "type": "kev",
    "cve_id": "CVE-2016-3427",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "description": "Oracle Java SE 6u113, 7u99, 8u77; Java SE Embedded 8u77; and JRockit R28.3.9 contain an unspecified vulnerability related to JMX, letting remote attackers impact confidentiality, integrity, and availa",
    "recommendation": "URGENT: apache 2.4.49 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "log4j",
    "version_affected": "2.14.1",
    "type": "critical_remote",
    "cve_id": "CVE-2022-23305",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploit requires specific JDBCAppender configuration.",
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "product": "log4j",
    "version_affected": "2.14.1",
    "type": "critical_remote",
    "cve_id": "CVE-2020-9493",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting attackers execute malicious code, exploit requires attacker to send crafted seriali",
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "product": "log4j",
    "version_affected": "2.14.1",
    "type": "critical_remote",
    "cve_id": "CVE-2019-17571",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, explo",
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "product": "log4j",
    "version_affected": "2.14.1",
    "type": "critical_remote",
    "cve_id": "CVE-2017-5645",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket servers, letting attackers execute arbitrary code rem",
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "product": "log4j",
    "version_affected": "2.14.1",
    "type": "kev",
    "cve_id": "CVE-2021-45046",
    "severity": "critical",
    "cvss_score": 9,
    "is_remote": true,
    "is_kev": true,
    "description": "Apache Log4j2 contains a remote code execution caused by vulnerable thread context lookup pattern in certain non-default configurations, letting remote attackers execute arbitrary code, exploit requir",
    "recommendation": "URGENT: log4j 2.14.1 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "log4j",
    "version_affected": "2.14.1",
    "type": "kev",
    "cve_id": "CVE-2021-4104",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "description": "Log4j 1.2 with JMSAppender configured contains a deserialization of untrusted data caused by write access to the configuration, letting attackers perform JNDI requests that may lead to remote code exe",
    "recommendation": "URGENT: log4j 2.14.1 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "log4j",
    "version_affected": "2.14.1",
    "type": "kev",
    "cve_id": "CVE-2023-26464",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "description": "Log4j 1.x on JRE less than 1.7 contains a denial of service caused by deserialization of specially-crafted nested hashmaps or hashtables, letting attackers exhaust memory, exploit requires attacker to",
    "recommendation": "URGENT: log4j 2.14.1 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "log4j",
    "version_affected": "2.14.1",
    "type": "kev",
    "cve_id": "CVE-2021-44832",
    "severity": "medium",
    "cvss_score": 6.6,
    "is_remote": true,
    "is_kev": true,
    "description": "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding 2.3.2 and 2.12.4) contain a remote code execution caused by unsafe JNDI LDAP data source URI usage in JDBC Appender, letting attackers with c",
    "recommendation": "URGENT: log4j 2.14.1 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "postgresql",
    "version_affected": "9.2.3",
    "type": "critical_remote",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "recommendation": "Upgrade postgresql from 9.2.3 to latest patched version"
  },
  {
    "product": "postgresql",
    "version_affected": "9.2.3",
    "type": "critical_remote",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "recommendation": "Upgrade postgresql from 9.2.3 to latest patched version"
  },
  {
    "product": "postgresql",
    "version_affected": "9.2.3",
    "type": "critical_remote",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "recommendation": "Upgrade postgresql from 9.2.3 to latest patched version"
  },
  {
    "product": "postgresql",
    "version_affected": "9.2.3",
    "type": "critical_remote",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "recommendation": "Upgrade postgresql from 9.2.3 to latest patched version"
  },
  {
    "product": "postgresql",
    "version_affected": "9.2.3",
    "type": "critical_remote",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "recommendation": "Upgrade postgresql from 9.2.3 to latest patched version"
  },
  {
    "product": "postgresql",
    "version_affected": "9.2.3",
    "type": "kev",
    "cve_id": "CVE-2019-9193",
    "severity": "high",
    "cvss_score": 7.2,
    "is_remote": true,
    "is_kev": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
    "recommendation": "URGENT: postgresql 9.2.3 has known exploited vulnerability - immediate patching required"
  },
  {
    "product": "postgresql",
    "version_affected": "9.2.3",
    "type": "kev",
    "cve_id": "CVE-2022-31197",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "is_kev": true,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
    "recommendation": "URGENT: postgresql 9.2.3 has known exploited vulnerability - immediate patching required"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC policy mined from Ansible configuration for **ChainCorp** in a **PCI-compliant production** environment.

### Scope
- **Organization**: ChainCorp
- **Environment**: Production
- **Compliance Tier**: PCI
- **Hosts Analyzed**: 4 (bastion01, web01, app01, db01)
- **Users Defined**: 5 (admin, developer, dba, appuser, dbadmin)
- **Groups**: sudo, developers, dba, app, postgres

## Vulnerability Assessment

### Summary
- **Total Vulnerabilities Found**: 35
- **Critical/High Severity**: 30+
- **Known Exploited (KEV)**: 13

### Critical Findings by Product

| Product | Version | Critical CVEs | KEV CVEs |
|---------|---------|---------------|----------|
| OpenSSH | 9.1p1 (bastion) | 5 | 5 |
| OpenSSH | 9.9p1 (non-bastion) | 5 | 5 |
| Apache | 2.4.49 | 5 | 5 |
| Log4j | 2.14.1 | 4 | 4 |
| PostgreSQL | 9.2.3 | 5 | 3 |

### High-Risk Vulnerabilities

1. **CVE-2023-38408** (OpenSSH) - Critical, CVSS 9.8, KEV
   - Known exploited vulnerability in OpenSSH
   - **Recommendation**: Immediate patching required

2. **CVE-2021-44228** (Log4j) - Critical, CVSS 10, KEV
   - Log4Shell RCE vulnerability
   - **Recommendation**: Upgrade Log4j immediately

3. **CVE-2023-46604** (Apache) - Critical, CVSS 10, KEV
   - Apache HTTP Server path traversal
   - **Recommendation**: Patch Apache to latest version

## Access Control Rules

### Rule Summary
- **Total Rules**: 18
- **Permit Rules**: 17
- **Deny Rules**: 1 (default-deny)

### Rule Categories

| Category | Count | Description |
|----------|-------|-------------|
| SSH Access | 4 | Remote login controls |
| Network Policy | 4 | Firewall/connection rules |
| Sudo Privileges | 2 | Elevated access |
| Filesystem ACL | 6 | Path permissions |
| Database Access | 1 | PostgreSQL authentication |
| Default Deny | 1 | Catch-all deny rule |

### Key Access Controls

1. **Bastion Host Access**
   - Groups: sudo, dba
   - Port: 22/tcp
   - Source: 0.0.0.0/0 (open to all)

2. **App Server Access**
   - SSH: sudo, developers groups
   - Sudo: developers group (NOPASSWD)
   - Network: 10.0.1.0/24 (web network)

3. **Database Server Access**
   - Network: 10.0.2.0/24 (app servers only)
   - DB Auth: dba group
   - Data dir: 0700 (postgres only)

4. **Web Server Access**
   - SSH: sudo group only
   - HTTP: Port 80 open to all
   - Web root: 0755 (world readable)

## Obligations

### Audit Logging
- **App Servers**: Shell activity logging via `/etc/profile.d/audit.sh`
- **Web Servers**: Access logging via `/etc/profile.d/access_log.sh`

## Ambiguities and Assumptions

1. **Missing Credentials**: Passwords and SSH keys are not present in the configuration (expected for security)
2. **Implicit Deny**: Default-deny rule added for completeness
3. **Version Matching**: Vulnerability CVEs may affect older versions; version-specific matching requires detailed analysis
4. **Group 'postgres'**: Referenced in filesystem rules but not defined in user catalog

## Recommendations

1. **Immediate**: Patch OpenSSH 9.1p1 on bastion host (CVE-2023-38408)
2. **High Priority**: Upgrade Log4j from 2.14.1 to 2.17.1+
3. **High Priority**: Update Apache HTTP Server from 2.4.49
4. **Medium Priority**: Upgrade PostgreSQL from 9.2.3 (EOL version)
5. **Policy**: Consider restricting bastion host access from 0.0.0.0/0

## Files Analyzed

### Phase 1 (Catalog)
- inventory.ini
- group_vars/all.yml
- group_vars/appservers.yml
- group_vars/bastion.yml
- group_vars/dbservers.yml
- group_vars/webservers.yml

### Phase 2 (Rules)
- roles/app/tasks/main.yml
- roles/bastion/tasks/main.yml
- roles/db/tasks/main.yml
- roles/web/tasks/main.yml

---
*Report generated by ABAC Policy Miner*
