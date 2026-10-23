# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 15:10:43_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 14 | Rules: 22_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "type": "list",
      "description": "Users defined in the Ansible configuration",
      "entries": [
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
      ]
    },
    "groups": {
      "type": "enum",
      "description": "Distinct user groups",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "enum",
      "description": "Security clearance level of a user",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "enum",
      "description": "Organizational department",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "type": "string",
      "description": "Source network CIDR for network-layer access rules (firewall/pg_hba)",
      "source": "group_vars/bastion.yml;group_vars/webservers.yml;group_vars/appservers.yml;group_vars/dbservers.yml"
    },
    "source_zone": {
      "type": "enum",
      "description": "Network zone of the source host for network-layer access rules",
      "domain": [
        "internet",
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini;group_vars/bastion.yml;group_vars/webservers.yml;group_vars/appservers.yml;group_vars/dbservers.yml"
    }
  },
  "resources": {
    "hosts": {
      "type": "list",
      "description": "Hosts defined in inventory",
      "entries": [
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
      ]
    },
    "hostname": {
      "type": "enum",
      "description": "Target hostname for access control",
      "domain": [
        "bastion01.lab.local",
        "web01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "description": "Network service name",
      "domain": [
        "ssh",
        "http",
        "app",
        "postgresql"
      ],
      "source": "roles/*/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "description": "Network port number",
      "domain": [
        22,
        80,
        5432,
        8080
      ],
      "source": "roles/*/tasks/main.yml;group_vars/dbservers.yml"
    },
    "zone": {
      "type": "enum",
      "description": "Network zone of the resource host",
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "path": {
      "type": "string",
      "description": "Filesystem path",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "enum",
      "description": "File owner user",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "enum",
      "description": "File owner group",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "enum",
      "description": "File permission mode (octal string)",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "services": {
      "type": "list",
      "description": "Network services configured across hosts",
      "entries": [
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "bastion",
          "source": "roles/bastion/tasks/main.yml"
        },
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "webservers",
          "source": "roles/web/tasks/main.yml"
        },
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "appservers",
          "source": "roles/app/tasks/main.yml"
        },
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "dbservers",
          "source": "roles/db/tasks/main.yml"
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
          "source": "group_vars/dbservers.yml"
        }
      ]
    },
    "paths_list": {
      "type": "list",
      "description": "Filesystem paths with access control attributes",
      "entries": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgresql",
          "source": "roles/db/tasks/main.yml"
        }
      ]
    },
    "networks": {
      "type": "list",
      "description": "Network CIDRs referenced in firewall rules",
      "entries": [
        {
          "cidr": "0.0.0.0/0",
          "zone": "internet",
          "label": "any",
          "source": "group_vars/bastion.yml"
        },
        {
          "cidr": "10.0.0.0/24",
          "zone": "mgmt",
          "label": "bastion_subnet",
          "source": "group_vars/webservers.yml"
        },
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "web_subnet",
          "source": "group_vars/appservers.yml"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "app",
          "label": "app_subnet",
          "source": "group_vars/dbservers.yml"
        }
      ]
    }
  },
  "environment": {
    "org": {
      "type": "enum",
      "description": "Organization identifier",
      "domain": [
        "chaincorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "enum",
      "description": "Deployment environment",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "enum",
      "description": "Compliance classification",
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "integer",
      "description": "Log retention period in days",
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "8-11"
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall - allow SSH from internet",
      "lines": "13-18"
    }
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
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "nopassword": false
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "20-25"
    }
  },
  {
    "id": "rule-004",
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "16-19"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      },
      "source_zone": {
        "equals": "mgmt"
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall - allow HTTP from bastion subnet",
      "lines": "11-15"
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "22-25"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      },
      "source_zone": {
        "equals": "dmz"
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall - allow app port from web subnet",
      "lines": "16-21"
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "20-23"
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
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "role_attr_flags": [
          "LOGIN",
          "SUPERUSER"
        ]
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "12-15"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      },
      "source_zone": {
        "equals": "app"
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "17-19"
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "source_zone": {
        "equals": "mgmt"
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
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet (implicit deny)",
      "lines": "17-19"
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "source_zone": {
        "equals": "dmz"
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
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet (implicit deny)",
      "lines": "17-19"
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
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
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
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
    }
  },
  {
    "id": "rule-015",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
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
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
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
      },
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
    "id": "rule-018",
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
      "environment": {
        "equals": "production"
      },
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
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
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
    "id": "rule-022",
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
    "severity": "critical",
    "description": "Apache Log4j2 JNDI RCE (Log4Shell). Remote code execution via crafted log messages.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade Log4j to 2.17.1 or later immediately. This is a critical remote code execution vulnerability actively exploited in the wild.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-41773",
    "product": "apache_httpd",
    "pinned_version": "2.4.49",
    "severity": "critical",
    "description": "Apache HTTP Server path traversal and file disclosure vulnerability. Allows remote attackers to map URLs to files outside the document root.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade Apache HTTPD to 2.4.50 or later. Version 2.4.49 is specifically affected by this path traversal vulnerability.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-42013",
    "product": "apache_httpd",
    "pinned_version": "2.4.49",
    "severity": "critical",
    "description": "Apache HTTP Server path traversal bypass of CVE-2021-41773 fix. Allows remote code execution when mod_cgi is enabled.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade Apache HTTPD to 2.4.51 or later. The 2.4.49 version is vulnerable to both the original path traversal and this bypass.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "high",
    "description": "OpenSSH: Potential double-free in ssh-agent PKCS#11 functionality. Affects bastion host running OpenSSH 9.1p1.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH on bastion to 9.9p1 or later (matching the version used on other hosts).",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2016-5423",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "high",
    "description": "PostgreSQL: Privilege escalation via shared object search path manipulation in pg_upgrade.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to a supported version (15+). Version 9.2.3 is extremely outdated and end-of-life with multiple known vulnerabilities.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2023-48795",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "medium",
    "description": "OpenSSH: Terrapin attack - prefix truncation vulnerability in SSH transport protocol. Affects bastion host running OpenSSH 9.1p1.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH on bastion to 9.9p1 or later. Enable strict key exchange to mitigate.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2016-0766",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "severity": "medium",
    "description": "PostgreSQL: Information disclosure via unnamed prepared statements.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to a supported version (15+). Version 9.2.3 is end-of-life.",
    "source": "group_vars/all.yml"
  }
]
```

## Report

# ABAC Policy Mining Report — ChainCorp Ansible Configuration

## Overview

This report presents an Attribute-Based Access Control (ABAC) policy mined from the ChainCorp Ansible configuration. The environment is a PCI-compliant production infrastructure with four host groups: bastion, webservers, appservers, and dbservers.

## Attribute Catalog Summary

### Subjects
- **3 users** defined: admin (sudo/operations/secret), developer (developers/engineering/confidential), dba (dba/data/secret)
- **3 groups**: sudo, developers, dba
- **2 clearance levels**: secret, confidential
- **3 departments**: operations, engineering, data
- **Network-layer subject attrs**: source_network (CIDR), source_zone (internet/mgmt/dmz/app/data)

### Resources
- **4 hosts**: bastion01 (mgmt), web01 (dmz), app01 (app), db01 (data)
- **4 services**: ssh (port 22), http (port 80), app (port 8080), postgresql (port 5432)
- **1 filesystem path**: /var/lib/postgresql/data (owner=postgres, group=postgres, mode=0700)
- **4 network CIDRs**: 0.0.0.0/0 (internet), 10.0.0.0/24 (mgmt), 10.0.1.0/24 (dmz), 10.0.2.0/24 (app)

### Environment
- **org**: chaincorp
- **environment**: production
- **compliance_tier**: pci
- **default_log_retention_days**: 365

## Policy Rules Summary

### SSH Access Rules (rules 001, 004, 006, 008)
| Host Group | Allowed Groups | Rule ID |
|---|---|---|
| bastion | sudo, dba | rule-001 |
| webservers | sudo | rule-004 |
| appservers | sudo, developers | rule-006 |
| dbservers | sudo, dba | rule-008 |

### Network Firewall Rules (rules 002, 005, 007, 010)
| Source | Destination | Service | Rule ID |
|---|---|---|---|
| 0.0.0.0/0 (internet) | bastion (mgmt) | ssh:22 | rule-002 |
| 10.0.0.0/24 (mgmt) | webservers (dmz) | http:80 | rule-005 |
| 10.0.1.0/24 (dmz) | appservers (app) | app:8080 | rule-007 |
| 10.0.2.0/24 (app) | dbservers (data) | postgresql:5432 | rule-010 |

### Sudo Access (rule 003)
- Bastion: Only users with **sudo group AND secret clearance** may execute sudo (nopassword=false)

### Database Access (rule 009)
- DBA group members get **SUPERUSER+LOGIN** role on PostgreSQL

### Implicit Deny Rules (rules 011, 012)
- PostgreSQL network access denied from mgmt and dmz zones (pg_hba implicit deny)

### Filesystem Rules (rules 013-015)
- /var/lib/postgresql/data: sudo group has read/write/execute (mode 0700, owner=postgres)

### Default Deny (rule 016)
- Catch-all deny for any unmatched access request

## Vulnerability Assessment

### Critical Vulnerabilities

| CVE | Product | Pinned Version | Severity | Description |
|---|---|---|---|---|
| CVE-2021-44228 | Log4j | 2.14.1 | Critical | Log4Shell — Remote code execution via JNDI lookup in log messages |
| CVE-2021-41773 | Apache HTTPD | 2.4.49 | Critical | Path traversal and file disclosure |
| CVE-2021-42013 | Apache HTTPD | 2.4.49 | Critical | Path traversal bypass of CVE-2021-41773 fix, RCE with mod_cgi |

### High/Medium Vulnerabilities

| CVE | Product | Pinned Version | Severity | Description |
|---|---|---|---|---|
| CVE-2023-38408 | OpenSSH (bastion) | 9.1p1 | High | Double-free in ssh-agent PKCS#11 |
| CVE-2016-5423 | PostgreSQL | 9.2.3 | High | Privilege escalation via pg_upgrade |
| CVE-2023-48795 | OpenSSH (bastion) | 9.1p1 | Medium | Terrapin attack — prefix truncation in SSH transport |
| CVE-2016-0766 | PostgreSQL | 9.2.3 | Medium | Information disclosure via unnamed prepared statements |

### Recommendations
1. **Log4j 2.14.1 to 2.17.1+**: Log4Shell is actively exploited; upgrade immediately.
2. **Apache HTTPD 2.4.49 to 2.4.51+**: Both path traversal CVEs affect this exact version.
3. **PostgreSQL 9.2.3 to 15+**: Version 9.2 is end-of-life with multiple known vulnerabilities.
4. **OpenSSH on bastion 9.1p1 to 9.9p1**: Align with the version used on other hosts.

## Ambiguities and Gaps

1. **Postgres OS user not in catalog**: The filesystem path /var/lib/postgresql/data is owned by the `postgres` OS user, which is not in the Ansible-defined users list. Direct filesystem access is only for this system user; sudo group access is via privilege escalation.
2. **Bastion SSH open to internet**: The firewall rule allowing SSH from 0.0.0.0/0 to the bastion is a significant exposure. While AllowGroups restricts who can log in, the bastion is the only host directly reachable from the internet.
3. **No explicit deny for internet to non-bastion SSH**: The firewall rules only define `enabled` rules. Implicit deny is assumed but not explicitly configured for SSH to webservers/appservers/dbservers from the internet.
4. **pg_hba uses scram-sha-256**: The authentication method is noted but not modeled as an ABAC attribute.
5. **Vulnerable packages are deliberately pinned**: The configuration comments and version pins suggest these are intentional ("vulnerable"), possibly for a lab/CTF environment.
6. **No monitoring/nagios/haproxy/selinux configurations found**: The file structure did not contain templates matching these security patterns.
