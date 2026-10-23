# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 22:16:04_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 13 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "type": "string",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "string",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "string",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source_ip": {
      "type": "string",
      "source": "roles/app/tasks/main.yml, roles/db/tasks/main.yml, roles/dmz/tasks/main.yml"
    },
    "source_network": {
      "type": "string",
      "domain": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/appservers.yml, group_vars/dbservers.yml, group_vars/dmz.yml"
    },
    "source_zone": {
      "type": "string",
      "domain": [
        "dmz",
        "app",
        "data",
        "internet"
      ],
      "source": "derived from source_network mapping"
    }
  },
  "resources": {
    "hostname": {
      "type": "string",
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "domain": [
        "10.0.1.10",
        "10.0.2.10",
        "10.0.3.10"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "type": "string",
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "string",
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "string",
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "string",
      "domain": [
        "nginx",
        "openssh-server",
        "postgresql",
        "app"
      ],
      "source": "group_vars/all.yml, roles/*/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "domain": [
        22,
        443,
        5432,
        8080
      ],
      "source": "group_vars/appservers.yml, group_vars/dbservers.yml, group_vars/dmz.yml"
    },
    "protocol": {
      "type": "string",
      "domain": [
        "tcp"
      ],
      "source": "roles/*/tasks/main.yml"
    },
    "path": {
      "type": "string",
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "networks": {
      "type": "set",
      "domain": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "10.0.3.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/appservers.yml, group_vars/dbservers.yml, group_vars/dmz.yml"
    }
  },
  "environment": {
    "org": {
      "type": "string",
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "string",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "string",
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml, inventory.ini"
    }
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "description": "Users in sudo group may SSH into DMZ hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "service": {
        "equals": "openssh-server"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-33"
    }
  },
  {
    "id": "rule-002",
    "description": "Users in sudo or developers groups may SSH into app hosts",
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
      },
      "service": {
        "equals": "openssh-server"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
    "id": "rule-003",
    "description": "Users in sudo or dba groups may SSH into db hosts",
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
      },
      "service": {
        "equals": "openssh-server"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "34-37"
    }
  },
  {
    "id": "rule-004",
    "description": "Allow HTTPS (port 443/tcp) from internet to DMZ hosts",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      },
      "source_zone": {
        "equals": "internet"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall - allow HTTPS from internet",
      "lines": "22-27"
    }
  },
  {
    "id": "rule-005",
    "description": "Allow app port (8080/tcp) from DMZ subnet to app hosts",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      },
      "source_zone": {
        "equals": "dmz"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall - allow app port from DMZ only",
      "lines": "16-21"
    }
  },
  {
    "id": "rule-006",
    "description": "Allow PostgreSQL connections from appservers subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      },
      "source_zone": {
        "equals": "app"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "28-31"
    }
  },
  {
    "id": "rule-007",
    "description": "DBA users get PostgreSQL SUPERUSER LOGIN privilege",
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
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "value": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "16-20"
    }
  },
  {
    "id": "rule-008",
    "description": "Developer users get PostgreSQL NOSUPERUSER LOGIN privilege",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "value": "NOSUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "22-26"
    }
  },
  {
    "id": "rule-009",
    "description": "Postgres data directory restricted to owner-only access (mode 0700)",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
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
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "12-17"
    }
  },
  {
    "id": "rule-010",
    "description": "Users in developers or sudo groups are provisioned on app hosts",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "8-13"
    }
  },
  {
    "id": "rule-011",
    "description": "Users in sudo group are provisioned on DMZ hosts",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "14-19"
    }
  },
  {
    "id": "rule-012",
    "description": "Default deny all access not explicitly permitted",
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
      "host_group": {
        "equals": "dmz"
      },
      "port": {
        "equals": 443
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
      "host_group": {
        "equals": "appservers"
      },
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
    "id": "rule-016",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
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
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ",
    "recommendation": "Upgrade nginx to latest stable version; disable TLS renegotiation"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "recommendation": "Not affected - pinned version 1.20.0 is newer than affected range (0.6.18-1.8.0, 1.9.x before 1.9.10)"
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
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ",
    "recommendation": "Not affected - this is an njs module vulnerability (through 0.7.0), not core nginx"
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
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "recommendation": "Not affected - pinned version 1.20.0 is newer than affected range (before 1.13.6)"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "recommendation": "Upgrade nginx to 1.21.0+ or apply patch; configure trusted DNS resolvers"
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
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "recommendation": "Not affected - pinned version 16.2 is far newer than affected range (7.2.1 and earlier)"
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
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "recommendation": "Not affected - pinned version 16.2 is far newer; issue was fixed in earlier releases"
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
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "recommendation": "Not affected - this is a pgjdbc (Java driver) vulnerability, not PostgreSQL server"
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
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "recommendation": "Not affected - pinned version 16.2 is far newer than affected range (9.x versions)"
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
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "recommendation": "Not affected - pinned version 16.2 is far newer than affected range (before 9.2.4)"
  },
  {
    "cve_id": "N/A",
    "product": "openssh-server",
    "pinned_version": "9.1p1",
    "severity": "info",
    "cvss_score": 0,
    "is_remote": false,
    "is_kev": false,
    "affects_pinned_version": false,
    "description": "No critical/high remote vulnerabilities found for openssh-server 9.1p1",
    "recommendation": "Continue monitoring for new vulnerabilities; keep openssh-server updated"
  }
]
```

## Report

# ABAC Policy Mining Report — SegCorp Ansible Configuration

## 1. Executive Summary

This report presents an Attribute-Based Access Control (ABAC) policy mined from the SegCorp Ansible configuration. The infrastructure comprises three network zones (DMZ, Application, Data) with strict network segmentation and role-based SSH access controls. The policy enforces PCI compliance across all production hosts.

**Key findings:**
- 12 access control rules extracted (11 permit + 1 default-deny)
- 25 distinct attributes cataloged across subject, resource, and environment domains
- 2 CVEs potentially affect pinned software versions (CVE-2009-3555, CVE-2021-23017 for nginx)
- PostgreSQL access is properly segmented: DBAs get SUPERUSER, developers get NOSUPERUSER
- SSH access follows least-privilege: only sudo on DMZ, sudo+developers on app, sudo+dba on db

## 2. Attribute Catalog

### 2.1 Subject Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| user | string | admin, developer, dba | group_vars/all.yml |
| uid | integer | — | group_vars/all.yml |
| groups | set | sudo, developers, dba | group_vars/all.yml |
| clearance | string | secret, confidential | group_vars/all.yml |
| department | string | operations, engineering, data | group_vars/all.yml |
| source_ip | string | — | roles/*/tasks/main.yml |
| source_network | string | 10.0.1.0/24, 10.0.2.0/24, 0.0.0.0/0 | group_vars/*.yml |
| source_zone | string | dmz, app, data, internet | derived |

### 2.2 Resource Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| hostname | string | proxy01, app01, db01 | inventory.ini |
| ip | string | 10.0.1.10, 10.0.2.10, 10.0.3.10 | inventory.ini |
| role | string | reverse_proxy, application, primary | inventory.ini |
| zone | string | dmz, app, data | inventory.ini |
| host_group | string | dmz, appservers, dbservers, prod | inventory.ini |
| service | string | nginx, openssh-server, postgresql, app | group_vars/*.yml |
| port | integer | 22, 443, 5432, 8080 | group_vars/*.yml |
| protocol | string | tcp | roles/*/tasks/main.yml |
| path | string | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| owner | string | postgres | roles/db/tasks/main.yml |
| group | string | postgres | roles/db/tasks/main.yml |
| mode | string | 0700 | roles/db/tasks/main.yml |
| database | string | all | roles/db/tasks/main.yml |
| networks | set | 10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24, 0.0.0.0/0 | group_vars/*.yml |

### 2.3 Environment Attributes

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| org | string | segcorp | group_vars/all.yml |
| environment | string | production | inventory.ini |
| compliance_tier | string | pci | group_vars/all.yml |

## 3. Access Control Rules

### 3.1 SSH Access Rules

| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-001 | groups ∈ {sudo} | host_group=dmz, service=openssh-server | ssh:login | permit |
| rule-002 | groups ∈ {sudo, developers} | host_group=appservers, service=openssh-server | ssh:login | permit |
| rule-003 | groups ∈ {sudo, dba} | host_group=dbservers, service=openssh-server | ssh:login | permit |

### 3.2 Network Firewall Rules

| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-004 | source_network=0.0.0.0/0, source_zone=internet | host_group=dmz, port=443, protocol=tcp | network:connect | permit |
| rule-005 | source_network=10.0.1.0/24, source_zone=dmz | host_group=appservers, port=8080, protocol=tcp | network:connect | permit |
| rule-006 | source_network=10.0.2.0/24, source_zone=app | host_group=dbservers, service=postgresql, port=5432 | network:connect | permit |

### 3.3 Database Access Rules

| Rule | Subject | Resource | Action | Effect | Obligation |
|------|---------|----------|--------|--------|------------|
| rule-007 | groups ∈ {dba} | host_group=dbservers, service=postgresql | db:login | permit | privilege_level=SUPERUSER |
| rule-008 | groups ∈ {developers} | host_group=dbservers, service=postgresql | db:login | permit | privilege_level=NOSUPERUSER |

### 3.4 Filesystem Rules

| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-009 | groups ∈ {sudo, dba} | path=/var/lib/postgresql/data, owner=postgres, group=postgres, mode=0700, host_group=dbservers | filesystem:read | permit |

### 3.5 User Provisioning Rules

| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-010 | groups ∈ {developers, sudo} | host_group=appservers | user:create | permit |
| rule-011 | groups ∈ {sudo} | host_group=dmz | user:create | permit |

### 3.6 Default Deny

| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-012 | applies_to=all | applies_to=all | * | deny |

## 4. Vulnerability Assessment

### 4.1 Pinned Software Versions

| Package | Pinned Version | Source |
|---------|---------------|--------|
| nginx | 1.20.0-1~focal | group_vars/all.yml |
| openssh-server | 1:9.1p1-1ubuntu1 | group_vars/all.yml |
| postgresql-16 | 16.2-1.pgdg22.04+1 | group_vars/all.yml |

### 4.2 Potentially Affecting CVEs

| CVE | Product | Severity | CVSS | Affects Pinned? | Recommendation |
|-----|---------|----------|------|-----------------|----------------|
| CVE-2009-3555 | nginx | critical | 9.8 | Yes | Upgrade nginx; disable TLS renegotiation |
| CVE-2021-23017 | nginx | high | — | Yes | Upgrade nginx to 1.21.0+; configure trusted DNS resolvers |
| CVE-2016-0746 | nginx | critical | — | No | Pinned 1.20.0 is newer than affected range (≤1.8.0, <1.9.10) |
| CVE-2021-46461 | nginx | critical | — | No | njs module vulnerability, not core nginx |
| CVE-2017-20005 | nginx | critical | — | No | Pinned 1.20.0 is newer than affected range (<1.13.6) |
| CVE-2002-1399 | postgresql | critical | 10 | No | Pinned 16.2 far newer than affected (≤7.2.1) |
| CVE-2007-3279 | postgresql | critical | — | No | Pinned 16.2 far newer; issue fixed in earlier releases |
| CVE-2024-1597 | postgresql | critical | — | No | pgjdbc (Java driver) vulnerability, not PostgreSQL server |
| CVE-2013-1903 | postgresql | critical | — | No | Pinned 16.2 far newer than affected (9.x) |
| CVE-2013-1902 | postgresql | critical | — | No | Pinned 16.2 far newer than affected (<9.2.4) |

**openssh-server 9.1p1**: No critical/high remote vulnerabilities found.

### 4.3 Risk Summary

- **nginx 1.20.0**: 2 CVEs potentially affect the pinned version (CVE-2009-3555 TLS renegotiation, CVE-2021-23017 DNS resolver). Recommend upgrading to nginx 1.25+ or applying patches.
- **postgresql 16.2**: No identified CVEs affect the pinned version. All critical CVEs target much older versions.
- **openssh-server 9.1p1**: No critical/high remote vulnerabilities identified.

## 5. Ambiguities and Assumptions

1. **SSH AllowGroups semantics**: The `AllowGroups` directive in sshd_config permits login only to users who are members of the listed groups. We interpret this as `ssh:login` permit rules scoped by group membership.

2. **pg_hba.conf implicit deny**: The `pg_hba.conf` entry `host all all 10.0.2.0/24 scram-sha-256` permits connections from the appservers subnet. The implicit default for pg_hba is deny-all — connections from other subnets are denied. We model this as a single permit rule (rule-006) plus the default-deny rule (rule-012).

3. **Filesystem permissions on postgres data dir**: Mode 0700 means only the `postgres` OS user can read/write/execute. We model this as a permit for sudo/dba groups (who can escalate to root/postgres) with the resource attributes capturing the actual ownership.

4. **User provisioning conditional logic**: The `when` clauses in user creation tasks (`'developers' in item.groups or 'sudo' in item.groups`, `'sudo' in item.groups`, `'dba' in item.groups`) determine which users are provisioned on which hosts. We model these as `user:create` permit rules.

5. **Network zone derivation**: Source zones (dmz, app, data, internet) are derived from the CIDR ranges in firewall rules, not explicitly stated in the Ansible config.

6. **Credentials**: No explicit credential management (passwords, keys, certificates) was found in the Ansible configuration. This is flagged as an ambiguity — credentials may be managed outside this configuration.

7. **Session logging / audit**: No session logging or audit scripts were found in the Ansible configuration. PCI compliance may require additional logging controls not captured here.

8. **Firewall default deny**: The firewalld rules only define `enabled` entries. The implicit default for firewalld is to deny all traffic not explicitly allowed, which is captured by rule-012.

9. **DBA SSH access to db hosts**: The `AllowGroups sudo dba` on db hosts means both sudo and dba groups can SSH in. The `dba` group is not listed in the `users` loop condition for db host provisioning, but the `AllowGroups` directive would still permit their SSH login if they were provisioned elsewhere. We model this as rule-003 permitting SSH login for both groups.

10. **Developer access to db hosts**: Developers are not in the `AllowGroups` for db hosts and are not provisioned on db hosts, but they can access PostgreSQL from the app subnet (rule-006 network permit + rule-008 db:login with NOSUPERUSER).
