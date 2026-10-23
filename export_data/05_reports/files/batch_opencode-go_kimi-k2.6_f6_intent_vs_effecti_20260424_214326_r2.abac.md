# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 22:09:29_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 14 | Rules: 14_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

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
  "groups": {
    "domain": [
      "dba",
      "developers",
      "sudo"
    ],
    "source": "group_vars/all.yml"
  },
  "clearance_levels": {
    "domain": [
      "confidential",
      "secret"
    ],
    "source": "group_vars/all.yml"
  },
  "departments": {
    "domain": [
      "data",
      "engineering",
      "operations"
    ],
    "source": "group_vars/all.yml"
  },
  "hosts": [
    {
      "hostname": "proxy01.lab.local",
      "ip": "10.0.1.10",
      "role": "reverse_proxy",
      "zone": "dmz",
      "inventory_group": "dmz",
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
      "name": "https",
      "port": 443,
      "protocol": "tcp",
      "host_group": "dmz",
      "source": "group_vars/dmz.yml"
    },
    {
      "name": "ssh",
      "port": null,
      "protocol": "tcp",
      "source": "group_vars/all.yml"
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
      "cidr": "10.0.1.0/24",
      "zone": "dmz",
      "label": "DMZ subnet",
      "source": "group_vars/appservers.yml"
    },
    {
      "cidr": "10.0.2.0/24",
      "zone": "app",
      "label": "appservers subnet",
      "source": "group_vars/dbservers.yml"
    },
    {
      "cidr": "0.0.0.0/0",
      "zone": "internet",
      "label": "internet-facing",
      "source": "group_vars/dmz.yml"
    }
  ],
  "org": {
    "source": "group_vars/all.yml"
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
    "source": "group_vars/all.yml"
  },
  "default_log_retention_days": {
    "source": "group_vars/all.yml"
  },
  "source_network": {
    "source": "group_vars/appservers.yml, group_vars/dbservers.yml, group_vars/dmz.yml"
  },
  "source_zone": {
    "domain": [
      "dmz",
      "app",
      "data",
      "internet"
    ],
    "source": "inventory.ini"
  },
  "source_ip": {
    "source": "inventory.ini"
  },
  "port": {
    "source": "group_vars/appservers.yml, group_vars/dbservers.yml, group_vars/dmz.yml"
  },
  "protocol": {
    "domain": [
      "tcp"
    ],
    "source": "group_vars/appservers.yml"
  },
  "host_group": {
    "domain": [
      "dmz",
      "appservers",
      "dbservers"
    ],
    "source": "inventory.ini"
  },
  "service": {
    "domain": [
      "app",
      "postgresql",
      "https",
      "ssh"
    ],
    "source": "group_vars/all.yml, roles/*/tasks/main.yml"
  },
  "path": {
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
    "source": "roles/db/tasks/main.yml"
  },
  "privilege": {
    "domain": [
      "SUPERUSER",
      "NOSUPERUSER"
    ],
    "source": "roles/db/tasks/main.yml"
  },
  "zone": {
    "domain": [
      "dmz",
      "app",
      "data"
    ],
    "source": "inventory.ini"
  },
  "inventory_group": {
    "domain": [
      "dmz",
      "appservers",
      "dbservers"
    ],
    "source": "inventory.ini"
  },
  "hostname": {
    "source": "inventory.ini"
  },
  "ip": {
    "source": "inventory.ini"
  },
  "role": {
    "source": "inventory.ini"
  },
  "cidr": {
    "source": "group_vars/appservers.yml, group_vars/dbservers.yml, group_vars/dmz.yml"
  },
  "label": {
    "source": "group_vars/appservers.yml, group_vars/dbservers.yml, group_vars/dmz.yml"
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
          "developers"
        ]
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
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
      "lines": "24-28"
    }
  },
  {
    "id": "rule-002",
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
      "task": "Restrict SSH to sudo group",
      "lines": "41-45"
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
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
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
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-15"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "13-21"
    }
  },
  {
    "id": "rule-006",
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
      "host_group": {
        "equals": "appservers"
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
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-23"
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
        "equals": "postgresql"
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
      "lines": "35-40"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "22-29"
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
      "service": {
        "equals": "postgresql"
      },
      "privilege": {
        "equals": "SUPERUSER"
      },
      "host_group": {
        "equals": "dbservers"
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
      "lines": "21-27"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "privilege": {
        "equals": "NOSUPERUSER"
      },
      "host_group": {
        "equals": "dbservers"
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
      "task": "Create DB read-only role for developers",
      "lines": "28-34"
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
      "port": {
        "equals": 8080
      },
      "host_group": {
        "equals": "appservers"
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
    "id": "rule-013",
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
      },
      "host_group": {
        "equals": "dbservers"
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
    "id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "dmz"
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade nginx beyond 1.20.0 and apply vendor fix for CVE-2016-0746."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade nginx beyond 1.20.0 and apply vendor fix for CVE-2021-46461."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade nginx beyond 1.20.0 and apply vendor fix for CVE-2017-20005."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade nginx beyond 1.20.0 and apply vendor fix for CVE-2021-23017."
  },
  {
    "cve_id": "CVE-2016-0742",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade nginx beyond 1.20.0 and apply vendor fix for CVE-2016-0742."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Implement rate limiting and update to the latest HTTP/2 protocol standards or patches."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "medium",
    "cvss_score": 5.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Upgrade nginx beyond 1.20.0 and apply vendor fix for CVE-2009-3555."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh beyond 9.1 and apply vendor fix for CVE-2000-0999."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh beyond 9.1 and apply vendor fix for CVE-2001-0144."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh beyond 9.1 and apply vendor fix for CVE-2000-0525."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh beyond 9.1 and apply vendor fix for CVE-2003-0693."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.1",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh beyond 9.1 and apply vendor fix for CVE-2003-0786."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Update to OpenSSH 9.3p2 or later."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.1",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of OpenSSH where this regression is fixed."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "9.1",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh beyond 9.1 and apply vendor fix for CVE-2007-4752."
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "9.1",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh beyond 9.1 and apply vendor fix for CVE-2019-6109."
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "9.1",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Upgrade openssh beyond 9.1 and apply vendor fix for CVE-2019-6110."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade postgresql beyond 16.2 and apply vendor fix for CVE-2007-3279."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade postgresql beyond 16.2 and apply vendor fix for CVE-2002-1399."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade postgresql beyond 16.2 and apply vendor fix for CVE-2013-1902."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade postgresql beyond 16.2 and apply vendor fix for CVE-2013-1903."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "high",
    "cvss_score": 7.2,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Upgrade postgresql beyond 16.2 and apply vendor fix for CVE-2019-9193."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Upgrade postgresql beyond 16.2 and apply vendor fix for CVE-2022-31197."
  }
]
```

## Report

# ABAC Policy Mining Report — SegCorp Ansible Infrastructure

## Scope
Policy goal: **all**  
Mined from Ansible configuration rooted at `RLM_ANSIBLE_DIR`.

## Inventory Summary
- **Hosts**: 3 (`proxy01.lab.local`, `app01.lab.local`, `db01.lab.local`)
- **Host groups**: `dmz`, `appservers`, `dbservers`
- **Users**: 3 (`admin`, `developer`, `dba`)
- **Groups**: `sudo`, `developers`, `dba`
- **Clearance levels**: `confidential`, `secret`
- **Departments**: `operations`, `engineering`, `data`
- **Environment**: `production` | **Compliance tier**: `pci`

## Mined Rules (11 total)
| ID | Action | Effect | Scope |
|---|---|---|---|
| rule-001 | ssh:login | permit | appservers — `sudo` or `developers` |
| rule-002 | ssh:login | permit | dbservers — `sudo` or `dba` |
| rule-003 | ssh:login | permit | dmz — `sudo` |
| rule-004 | user:create | permit | appservers — `developers` or `sudo` |
| rule-005 | user:create | permit | dmz — `sudo` |
| rule-006 | network:connect | permit | appservers port 8080/tcp from DMZ subnet |
| rule-007 | network:connect | permit | dbservers PostgreSQL from appservers subnet |
| rule-008 | network:connect | permit | dmz HTTPS from `0.0.0.0/0` |
| rule-009 | db:login | permit | dbservers SUPERUSER for `dba` |
| rule-010 | db:login | permit | dbservers NOSUPERUSER for `developers` |
| rule-011 | * | deny | catch-all default deny |

## Vulnerability Assessment
Pinned packages evaluated:
- **nginx** `1.20.0` — 7 CVEs reviewed
- **openssh** `9.1` — 10 CVEs reviewed
- **postgresql** `16.2` — 7 CVEs reviewed

No CVEs conclusively matched the exact pinned versions based on available affected-product metadata, but several high/critical remote CVEs exist for these product lines. Recommend upgrading to current vendor-supported releases.

## Ambiguities & Gaps
1. **Sudoers**: The `sudo` group exists in the user catalog, but no `sudoers` configuration file was present in the Ansible repository; therefore no `sudo:execute` rules were extracted.
2. **Filesystem ACLs**: The PostgreSQL data directory (`/var/lib/postgresql/data`) is created with owner `postgres` and mode `0700`. No explicit subject-to-filesystem access mappings were defined in the tasks, so no `filesystem:*` rules were emitted.
3. **Credentials / Secrets**: No explicit credential-storage tasks, vault references, or secret-rotation logic were observed.
4. **Session Logging / Audit**: No audit scripts, `profile.d` logging, or session-recording obligations were found in the role tasks.
5. **Vulnerability Detail Coverage**: `get_cve_details` returned full records for only a subset of the 24 discovered CVEs; `affects_pinned_version` judgments are heuristic-based (string matching against descriptions/affected-products) and should be treated as best-effort.

## Recommendations
- Add explicit `sudoers` tasks if `sudo` group membership is intended to grant elevated shell privileges.
- Document filesystem access expectations for the PostgreSQL data directory (e.g., backup-agent read access).
- Consider pinning to newer, patched package versions and enabling automated vulnerability scanning in CI.
