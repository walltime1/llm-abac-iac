# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 20:08:25_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 13 | Rules: 14_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f2_threetier_segmented`_

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
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "user_name": {
      "domain": [
        "admin",
        "developer",
        "dba",
        "postgres"
      ],
      "source": "group_vars/all.yml,roles/db/tasks/main.yml"
    },
    "source_network": {
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "policy-default"
    }
  },
  "resources": {
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
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
      },
      {
        "name": "application",
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
        "label": "dmz_subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "group_vars/dmz.yml"
      }
    ],
    "host_group": {
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "roles": {
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zones": {
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "domain": [
        "nginx",
        "application",
        "postgresql",
        "ssh"
      ],
      "source": "group_vars/all.yml"
    },
    "port": {
      "source": "group_vars/all.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "group_vars/all.yml"
    },
    "hostname": {
      "source": "inventory.ini"
    },
    "ip": {
      "source": "inventory.ini"
    },
    "path": {
      "source": "group_vars/dbservers.yml"
    },
    "owner": {
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "source": "roles/db/tasks/main.yml"
    },
    "database_privilege": {
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "policy-default"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "segcorp"
      ],
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
      "domain": [
        365
      ],
      "source": "group_vars/all.yml"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "policy-default"
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
          "developers"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-14"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "application"
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
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-22"
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
      "service": {
        "equals": "ssh"
      },
      "host_group": {
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
      "lines": "24-28"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      },
      "database_privilege": {
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
      "lines": "21-26"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      },
      "database_privilege": {
        "equals": "NOSUPERUSER"
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
      "task": "Create DB read-only role for developers",
      "lines": "28-33"
    }
  },
  {
    "id": "rule-006",
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
      "lines": "35-39"
    }
  },
  {
    "id": "rule-007",
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
      "lines": "41-45"
    }
  },
  {
    "id": "rule-008",
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
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "12-19"
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
        "equals": "nginx"
      },
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "21-27"
    }
  },
  {
    "id": "rule-010",
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
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "29-33"
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
    },
    "source": {
      "file": "inventory.ini",
      "task": "default-deny",
      "lines": "1"
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
      "service": {
        "equals": "application"
      },
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
      "service": {
        "equals": "nginx"
      },
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
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cves": [
      {
        "cve_id": "CVE-2016-0746",
        "product": "nginx",
        "pinned_version": "1.20.0-1~focal",
        "affects_pinned_version": true,
        "recommendation": "Upgrade to latest patched version."
      },
      {
        "cve_id": "CVE-2021-46461",
        "product": "nginx",
        "pinned_version": "1.20.0-1~focal",
        "affects_pinned_version": false,
        "recommendation": "CVE is for an unrelated product or component."
      },
      {
        "cve_id": "CVE-2017-20005",
        "product": "nginx",
        "pinned_version": "1.20.0-1~focal",
        "affects_pinned_version": true,
        "recommendation": "Upgrade to latest patched version."
      },
      {
        "cve_id": "CVE-2021-23017",
        "product": "nginx",
        "pinned_version": "1.20.0-1~focal",
        "affects_pinned_version": true,
        "recommendation": "Upgrade to latest patched version."
      },
      {
        "cve_id": "CVE-2016-0742",
        "product": "nginx",
        "pinned_version": "1.20.0-1~focal",
        "affects_pinned_version": true,
        "recommendation": "Upgrade to latest patched version."
      }
    ]
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cves": [
      {
        "cve_id": "CVE-2000-0999",
        "product": "openssh",
        "pinned_version": "1:9.6p1-3ubuntu1",
        "affects_pinned_version": false,
        "recommendation": "No action required; version not affected."
      },
      {
        "cve_id": "CVE-2001-0144",
        "product": "openssh",
        "pinned_version": "1:9.6p1-3ubuntu1",
        "affects_pinned_version": false,
        "recommendation": "No action required; version not affected."
      },
      {
        "cve_id": "CVE-2000-0525",
        "product": "openssh",
        "pinned_version": "1:9.6p1-3ubuntu1",
        "affects_pinned_version": false,
        "recommendation": "No action required; version not affected."
      },
      {
        "cve_id": "CVE-2003-0693",
        "product": "openssh",
        "pinned_version": "1:9.6p1-3ubuntu1",
        "affects_pinned_version": true,
        "recommendation": "Upgrade to latest patched version."
      },
      {
        "cve_id": "CVE-2003-0786",
        "product": "openssh",
        "pinned_version": "1:9.6p1-3ubuntu1",
        "affects_pinned_version": false,
        "recommendation": "No action required; version not affected."
      }
    ]
  },
  {
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "cves": [
      {
        "cve_id": "CVE-2007-3279",
        "product": "postgresql",
        "pinned_version": "13.7-1.pgdg20.04+1",
        "affects_pinned_version": false,
        "recommendation": "No action required; version not affected."
      },
      {
        "cve_id": "CVE-2002-1399",
        "product": "postgresql",
        "pinned_version": "13.7-1.pgdg20.04+1",
        "affects_pinned_version": false,
        "recommendation": "No action required; version not affected."
      },
      {
        "cve_id": "CVE-2024-1597",
        "product": "postgresql",
        "pinned_version": "13.7-1.pgdg20.04+1",
        "affects_pinned_version": false,
        "recommendation": "CVE is for an unrelated product or component."
      },
      {
        "cve_id": "CVE-2013-1902",
        "product": "postgresql",
        "pinned_version": "13.7-1.pgdg20.04+1",
        "affects_pinned_version": false,
        "recommendation": "No action required; version not affected."
      },
      {
        "cve_id": "CVE-2013-1903",
        "product": "postgresql",
        "pinned_version": "13.7-1.pgdg20.04+1",
        "affects_pinned_version": false,
        "recommendation": "No action required; version not affected."
      }
    ]
  }
]
```

## Report

# ABAC Policy Mining Report

## Overview
Mined an Attribute-Based Access Control (ABAC) policy from the Ansible repository rooted at `RLM_ANSIBLE_DIR`. The configuration spans three host groups (`dmz`, `appservers`, `dbservers`) and defines subjects, resources, environment attributes, and 11 access rules (10 permits + 1 default-deny).

## Attribute Catalog
- **Subjects**: 3 human users (`admin`, `developer`, `dba`) with group memberships (`sudo`, `developers`, `dba`), departments, and clearance levels. Source network identifiers are used for network-layer subjects.
- **Resources**: 3 hosts, 4 services (nginx, application, postgresql, ssh), 1 filesystem path (`/var/lib/postgresql/data`), and 3 network CIDRs.
- **Environment**: `org=segcorp`, `environment=production`, `compliance_tier=pci`, `default_log_retention_days=365`.

## Extracted Rules
| ID | Action | Effect | Source File |
|----|--------|--------|-------------|
| rule-001 | user:create | permit | roles/app/tasks/main.yml |
| rule-002 | network:connect | permit | roles/app/tasks/main.yml |
| rule-003 | ssh:login | permit | roles/app/tasks/main.yml |
| rule-004 | db:login | permit | roles/db/tasks/main.yml |
| rule-005 | db:login | permit | roles/db/tasks/main.yml |
| rule-006 | network:connect | permit | roles/db/tasks/main.yml |
| rule-007 | ssh:login | permit | roles/db/tasks/main.yml |
| rule-008 | user:create | permit | roles/dmz/tasks/main.yml |
| rule-009 | network:connect | permit | roles/dmz/tasks/main.yml |
| rule-010 | ssh:login | permit | roles/dmz/tasks/main.yml |
| rule-011 | * | deny | inventory.ini (default-deny) |

### Rule Details
- **App Servers**: Members of `sudo` or `developers` groups may log in via SSH and have local shell accounts created. The DMZ subnet (`10.0.1.0/24`) is permitted to reach the application service on TCP/8080.
- **DB Servers**: DBAs receive PostgreSQL `SUPERUSER` login rights, while developers receive `NOSUPERUSER` login rights. The app subnet (`10.0.2.0/24`) may connect to PostgreSQL on TCP/5432. SSH access is restricted to `sudo` and `dba` groups.
- **DMZ**: Only members of the `sudo` group may receive shell accounts or SSH login. All sources (`0.0.0.0/0`) are permitted to connect to HTTPS (TCP/443).

## Vulnerability Assessment
Pinned software versions were assessed for critical/high remote and Known Exploited Vulnerabilities (KEV):
- **nginx 1.20.0**: CVE-2016-0746, CVE-2017-20005, CVE-2021-23017, and CVE-2016-0742 were evaluated as affecting the pinned version. Recommendation: upgrade to the latest patched release.
- **OpenSSH 1:9.6p1-3ubuntu1**: CVE-2003-0693 was evaluated as affecting the pinned version. Recommendation: upgrade to the latest patched release.
- **PostgreSQL 13.7**: No assessed CVEs directly affect the pinned server package (e.g., CVE-2024-1597 pertains to the JDBC driver, not the server).

## Ambiguities
- **Filesystem ACLs**: The Ansible configuration sets `owner=postgres`, `group=postgres`, `mode=0700` on `/var/lib/postgresql/data`. No explicit subject access grant is defined for this directory, so no separate filesystem ACL rule was extracted; POSIX ownership is recorded as a resource attribute instead.
- **Implicit Deny**: The PostgreSQL `pg_hba.conf` and firewalld configurations contain only ALLOW entries. No explicit DENY entries were found in the Ansible tasks; the mandatory default-deny rule (`rule-011`) covers all unmatched access attempts.
- **Sudoers**: The `sudo` group is referenced in `group_vars/all.yml` and used for SSH gating, but no dedicated `sudoers` file or task configures passwordless `sudo` or command restrictions.
