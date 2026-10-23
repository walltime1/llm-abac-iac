# ABAC Policy Mining — goal: all
_Generated: 2026-04-25 12:35:03_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 19_  
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
        "value": "operations",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "engineering",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "data",
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
        "name": "httpd",
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
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all",
        "source": "group_vars/all.yml"
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
        "label": "web",
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
      }
    ],
    "paths": [
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql",
        "source": "group_vars/dbservers.yml"
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "10-14"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "20-24"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "30-34"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "25-29"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
      },
      "service": {
        "equals": "sudo"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "password_required",
        "description": "nopassword: false"
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "16-22"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privileges": [
      "SUPERUSER",
      "LOGIN"
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "16-20"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": "6-10"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-008",
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
        "equals": "httpd"
      },
      "port": {
        "equals": 80
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "14-19"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-009",
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": "24-29"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "21-24"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "11-15"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "11-15"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
    "source": {
      "file": "implicit",
      "task": "default-deny",
      "lines": "N/A"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
      "compliance_tier": {
        "equals": "pci"
      },
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
      "compliance_tier": {
        "equals": "pci"
      },
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
      },
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
      "service": {
        "equals": "httpd"
      },
      "port": {
        "equals": 80
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
      },
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
    "pinned_version": "1:9.1p1-1ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2010-0425",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2012-2379",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-1999-1237",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-1999-1293",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2004-0492",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2023-46604",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2010-0219",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2016-15057",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2023-34478",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache from 2.4.49-1 to latest patched version"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2021-4104",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "medium",
    "cvss_score": 6.6,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j from 2.14.1 to latest patched version"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "severity": "high",
    "cvss_score": 7.2,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 to latest patched version"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the Ansible configuration for ChainCorp's production environment. The policy covers SSH access, sudo privileges, database access, network connectivity, and filesystem permissions across 4 hosts in a PCI-compliant infrastructure.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | chaincorp |
| Environment | production |
| Compliance Tier | PCI |
| Log Retention | 365 days |

## Subject Catalog

### Users (3)
| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |

### Groups (3)
- `sudo` - Administrative access
- `developers` - Application development team
- `dba` - Database administrators

### Clearance Levels
- `secret` (admin, dba)
- `confidential` (developer)

## Resource Catalog

### Hosts (4)
| Hostname | IP | Role | Zone |
|----------|-----|------|------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt |
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| app01.lab.local | 10.0.2.10 | application | app |
| db01.lab.local | 10.0.3.10 | primary | data |

### Services (4)
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| ssh | 22 | tcp | all |
| httpd | 80 | tcp | webservers |
| app | 8080 | tcp | appservers |
| postgresql | 5432 | tcp | dbservers |

### Networks (4)
| CIDR | Zone | Label |
|------|------|-------|
| 10.0.0.0/24 | mgmt | management |
| 10.0.1.0/24 | dmz | web |
| 10.0.2.0/24 | app | application |
| 10.0.3.0/24 | data | database |

## Vulnerability Assessment

### Summary
- **Total Vulnerabilities Found**: 35 unique CVEs
- **Critical Severity**: 26
- **High Severity**: 7
- **Medium Severity**: 2

### Package Vulnerabilities

| Product | Pinned Version | Critical | High | Medium |
|---------|----------------|----------|------|--------|
| openssh | 1:9.1p1-1ubuntu1 | 6 | 3 | 2 |
| apache | 2.4.49-1 | 9 | 0 | 0 |
| log4j | 2.14.1 | 5 | 2 | 1 |
| postgresql | 9.2.3-1.pgdg20.04+1 | 5 | 2 | 0 |

### Notable Critical Vulnerabilities
- **CVE-2021-44228** (Log4Shell) - Log4j remote code execution
- **CVE-2022-23305** (Log4j) - Additional Log4j RCE
- **CVE-2023-38408** - OpenSSH privilege escalation
- **CVE-2024-1597** - PostgreSQL critical vulnerability

## Extracted ABAC Rules (13)

### SSH Access Rules (4)
| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-001 | groups in [sudo, dba] | bastion01, ssh | ssh:login | permit |
| rule-002 | groups = sudo | web01, ssh | ssh:login | permit |
| rule-003 | groups in [sudo, developers] | app01, ssh | ssh:login | permit |
| rule-004 | groups in [sudo, dba] | db01, ssh | ssh:login | permit |

### Sudo Rules (1)
| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-005 | groups=sudo AND clearance=secret | bastion01, sudo | sudo:execute | permit |

### Database Rules (1)
| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-006 | groups = dba | postgresql, all DB | db:login | permit |

### Network/Firewall Rules (4)
| Rule ID | Source Network | Resource | Action | Effect |
|---------|----------------|----------|--------|--------|
| rule-007 | 0.0.0.0/0 | bastion01, ssh:22 | network:connect | permit |
| rule-008 | 10.0.0.0/24 | web01, httpd:80 | network:connect | permit |
| rule-009 | 10.0.1.0/24 | app01, app:8080 | network:connect | permit |
| rule-010 | 10.0.2.0/24 | db01, postgresql:5432 | network:connect | permit |

### Filesystem Rules (2)
| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-011 | user=postgres | /var/lib/postgresql/data | filesystem:read | permit |
| rule-012 | user=postgres | /var/lib/postgresql/data | filesystem:write | permit |

### Default Deny (1)
| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-013 | all | all | * | deny |

## Ambiguities and Notes

1. **Credentials**: No explicit credential management rules found. Password policies not defined in Ansible configuration.

2. **Session Logging**: No explicit session logging or audit rules found in the configuration.

3. **SELinux**: No SELinux policies defined in the Ansible configuration.

4. **Package Versions**: All pinned package versions are known to have critical vulnerabilities. Immediate remediation recommended.

5. **Network Exposure**: Bastion host (rule-007) allows SSH from 0.0.0.0/0 (internet), which may violate PCI DSS requirements for direct internet exposure.

## Recommendations

1. **Immediate**: Upgrade all vulnerable packages to patched versions
2. **High**: Review bastion SSH access from internet (0.0.0.0/0)
3. **Medium**: Add session logging and audit rules
4. **Medium**: Define explicit credential management policies
5. **Low**: Consider SELinux policies for additional hardening
