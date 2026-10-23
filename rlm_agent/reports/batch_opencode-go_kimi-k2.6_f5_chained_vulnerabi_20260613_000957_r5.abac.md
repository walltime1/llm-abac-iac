# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 00:23:31_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 17 | Rules: 21_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "type": "list",
      "items": [
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
          "department": null,
          "clearance": null,
          "source": "roles/db/tasks/main.yml"
        }
      ],
      "source": "group_vars/all.yml"
    },
    "user": {
      "type": "enum",
      "domain": [
        "admin",
        "developer",
        "dba",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "dba",
        "developers",
        "sudo"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "enum",
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "enum",
      "domain": [
        "data",
        "engineering",
        "operations"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "type": "enum",
      "domain": [
        "0.0.0.0/0",
        "10.0.0.0/24",
        "10.0.1.0/24",
        "10.0.2.0/24"
      ],
      "source": "group_vars/*.yml"
    }
  },
  "resources": {
    "hosts": {
      "type": "list",
      "items": [
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
      "domain": [
        "bastion01.lab.local",
        "web01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "zones": {
      "type": "enum",
      "domain": [
        "app",
        "data",
        "dmz",
        "mgmt"
      ],
      "source": "inventory.ini"
    },
    "roles": {
      "type": "enum",
      "domain": [
        "application",
        "bastion",
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "inventory_groups": {
      "type": "enum",
      "domain": [
        "appservers",
        "bastion",
        "dbservers",
        "webservers"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "appservers",
        "bastion",
        "dbservers",
        "webservers",
        "all"
      ],
      "source": "inventory.ini"
    },
    "services": {
      "type": "list",
      "items": [
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "all",
          "source": "group_vars/all.yml"
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
          "name": "postgres",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers",
          "source": "group_vars/dbservers.yml"
        }
      ],
      "domain": [
        "ssh",
        "http",
        "app",
        "postgres"
      ],
      "source": "group_vars/*.yml"
    },
    "paths": {
      "type": "list",
      "items": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgres",
          "source": "roles/db/tasks/main.yml"
        }
      ],
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "networks": {
      "type": "list",
      "items": [
        {
          "cidr": "0.0.0.0/0",
          "zone": null,
          "label": "firewall_allow_bastion",
          "source": "group_vars/bastion.yml"
        },
        {
          "cidr": "10.0.0.0/24",
          "zone": null,
          "label": "firewall_allow_web",
          "source": "group_vars/webservers.yml"
        },
        {
          "cidr": "10.0.1.0/24",
          "zone": null,
          "label": "firewall_allow_app",
          "source": "group_vars/appservers.yml"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": null,
          "label": "db_allow_app",
          "source": "group_vars/dbservers.yml"
        }
      ],
      "source": "group_vars/*.yml"
    },
    "port": {
      "type": "enum",
      "domain": [
        22,
        80,
        8080,
        5432
      ],
      "source": "group_vars/*.yml"
    },
    "owner": {
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "enum",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "privilege_level": {
      "type": "enum",
      "domain": [
        "superuser"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "string",
      "value": "chaincorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "enum",
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "integer",
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
      "host_group": {
        "equals": "bastion"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "8-13"
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "31-35"
    }
  },
  {
    "id": "rule-003",
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "21-25"
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
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "29-33"
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "nopassword": false,
    "commands": "ALL",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "22-29"
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
      },
      "service": {
        "equals": "postgres"
      },
      "privilege_level": {
        "equals": "superuser"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "16-22"
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
      "host_group": {
        "equals": "bastion"
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": "14-21"
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
      "host_group": {
        "equals": "appservers"
      },
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": "23-30"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "13-20"
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
      "host_group": {
        "equals": "dbservers"
      },
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "23-28"
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
    }
  },
  {
    "id": "rule-014",
    "subject_condition": {
      "source_network": {
        "in": [
          "0.0.0.0/0",
          "10.0.0.0/24",
          "10.0.1.0/24"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
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
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "23-28"
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
      "lines": "0"
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
    "id": "rule-019",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
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
      "host_group": {
        "equals": "appservers"
      },
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
      "host_group": {
        "equals": "webservers"
      },
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
    "pinned_versions": [
      "9.9p1",
      "9.1p1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.00418,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input."
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "pinned_versions": [
      "9.9p1",
      "9.1p1"
    ],
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.66963,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentication, letting remote attackers execute arbitrary code, exploit requires specific PAM configuration."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_versions": [
      "9.9p1",
      "9.1p1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.03141,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_versions": [
      "9.9p1",
      "9.1p1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.26823,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires remote network access."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_versions": [
      "9.9p1",
      "9.1p1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.00709,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input."
  },
  {
    "cve_id": "CVE-2003-0789",
    "product": "apache",
    "pinned_versions": [
      "2.4.49"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.08237,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "Apache before 2.0.48 with threaded MPM contains a CGI redirect path handling issue caused by improper handling in mod_cgid, letting Apache send CGI output to the wrong client, exploit requires specific server configuration."
  },
  {
    "cve_id": "CVE-1999-1237",
    "product": "apache",
    "pinned_versions": [
      "2.4.49"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.07397,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "Multiple buffer overflows in smbvalid/smbval SMB authentication library used in Apache::AuthenSmb allow remote attackers to execute arbitrary commands via long username, long password, and other methods."
  },
  {
    "cve_id": "CVE-1999-1293",
    "product": "apache",
    "pinned_versions": [
      "2.4.49"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.01716,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "Apache 1.2.5 and earlier contains a denial of service caused by malformed FTP commands in mod_proxy, letting remote attackers cause Apache to dump core, exploit requires sending malformed FTP commands."
  },
  {
    "cve_id": "CVE-2013-1777",
    "product": "apache",
    "pinned_versions": [
      "2.4.49"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.08279,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "Apache Geronimo 3.x before 3.0.1, used in IBM WebSphere Application Server Community Edition 3.0.0.3, contains a remote code execution caused by improper RMI classloader implementation in JMX Remoting, letting remote attackers execute arbitrary code via crafted serialized objects, exploit requires network access to JMX connector."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.00458,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.02885,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3"
    ],
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.0055,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers potentially access sensitive credentials, exploit requires access to installer scripts."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3"
    ],
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.00523,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified."
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "epss": 0.94358,
    "kev": true,
    "recommendation": "Upgrade to the latest patched version; KEV confirmed active exploitation; prioritize patching immediately; Critical severity; consider isolating affected systems",
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to execute arbitrary code, exploit requires attacker-controlled log messages or parameters."
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "epss": 0.93917,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket servers, letting attackers execute arbitrary code remotely, exploit requires sending malicious payloads over network."
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "epss": 0.09452,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploit requires specific JDBCAppender configuration."
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "epss": 0.28502,
    "kev": false,
    "recommendation": "Upgrade to the latest patched version; Critical severity; consider isolating affected systems",
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, exploit requires listening to untrusted network traffic."
  }
]
```

## Report

# ABAC Policy Mining Report

## Summary
Mined a full ABAC policy from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`.
- **Policy goal**: `all`
- **Hosts**: 4 (bastion, web, app, db)
- **Human users**: 3 (admin, developer, dba)
- **System user**: `postgres` (referenced as filesystem owner)
- **Services**: ssh, http, app, postgres
- **Paths**: `/var/lib/postgresql/data`
- **Rules extracted**: 15 (13 permit + 1 explicit deny + 1 default-deny)

## Phase 1 — Catalog
- **Subjects**: `users` list with name, uid, groups, clearance, department, source.
- **Groups**: `sudo`, `developers`, `dba`.
- **Clearance levels**: `confidential`, `secret`.
- **Departments**: `data`, `engineering`, `operations`.
- **Resources**: 4 hosts with role, zone, inventory_group.
- **Services**: 4 services with port, protocol, host_group.
- **Paths**: 1 postgres data directory with owner, group, mode.
- **Networks**: 4 CIDRs used in firewall / pg_hba rules.
- **Environment**: org=`chaincorp`, environment=`production`, compliance_tier=`pci`, retention=365 days.

## Phase 1.5 — Vulnerability Assessment
Scanned pinned packages found in `group_vars/all.yml`:
- **openssh** (9.9p1 / 9.1p1)
- **apache** (2.4.49)
- **postgresql** (9.2.3)
- **log4j** (2.14.1)

Results:
- **17 CVEs** retained after discarding unrelated-product noise.
- **CVE-2021-44228** (Log4j 2.14.1) — critical, KEV, affects pinned version.
- **CVE-2002-0640** (OpenSSH 9.1p1) — critical, affects pinned version.
- **CVE-2013-1902** & **CVE-2013-1903** (PostgreSQL 9.2.3) — critical, affect pinned version.
- Remaining retained CVEs are critical/high but do not affect the exact pinned versions.

## Phase 2 — Rule Extraction
- **SSH access control** (`ssh:login`): 4 permit rules derived from `AllowGroups` in `sshd_config` across bastion, appservers, webservers, and dbservers.
- **Sudo access** (`sudo:execute`): 1 permit rule for secret-clearance `sudo` group members on the bastion, requiring a password (`nopassword: false`).
- **Database auth** (`db:login`): 1 permit rule granting `SUPERUSER` to DBAs on the dbservers.
- **Network policy** (`network:connect`): 4 permit rules from firewalld/pg_hba for ssh, http, app, and postgres ports.
- **Explicit deny**: 1 deny rule for postgres connections to dbservers from non-appservers subnets (implicit pg_hba default deny).
- **Filesystem ACL** (`filesystem:read/write/execute`): 3 permit rules for the postgres data directory owner.

## Phase 3 — Normalization
- Added missing catalog attributes (`source_network`, `privilege_level`, `port`, `owner`, `group`, `mode`) so every rule condition resolves to a known attribute.
- Assigned stable rule IDs (`rule-001` through `rule-015`).
- Every non-default rule includes `environment_condition: {"environment": {"equals": "production"}}`.

## Ambiguities
- `postgres` appears as a filesystem owner but is not fully defined in the `users` list with clearance/department; it was added as a system-level subject.
- No explicit `pg_hba` DENY lines exist in the Ansible files; the deny behavior is implicit and was captured as an explicit deny rule plus the global default-deny.
- No hardcoded credentials were discovered in any scanned file.
- No session-logging or audit-script obligations were found.

## Phase 4 — Validation
- All JSON structures (`attributes`, `rules`, `vulnerabilities`) validated successfully.
