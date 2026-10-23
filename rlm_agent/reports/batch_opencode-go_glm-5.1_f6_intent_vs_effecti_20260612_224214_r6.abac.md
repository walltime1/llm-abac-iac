# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 00:20:55_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 22 | Rules: 21_  
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
      "domain": [
        1001,
        1002,
        1003
      ],
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
    "source_network": {
      "type": "cidr",
      "domain": [
        "0.0.0.0/0",
        "10.0.1.0/24",
        "10.0.2.0/24",
        "10.0.3.0/24"
      ],
      "source": "group_vars/dmz.yml,group_vars/appservers.yml,group_vars/dbservers.yml"
    },
    "source_zone": {
      "type": "string",
      "domain": [
        "internet",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini,group_vars/dmz.yml,group_vars/appservers.yml,group_vars/dbservers.yml"
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
      "type": "ip",
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
    "inventory_group": {
      "type": "string",
      "domain": [
        "dmz",
        "appservers",
        "dbservers"
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
      "source": "group_vars/all.yml,roles/dmz/tasks/main.yml,roles/app/tasks/main.yml,roles/db/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "domain": [
        22,
        443,
        5432,
        8080
      ],
      "source": "group_vars/dmz.yml,group_vars/appservers.yml,group_vars/dbservers.yml"
    },
    "protocol": {
      "type": "string",
      "domain": [
        "tcp"
      ],
      "source": "roles/dmz/tasks/main.yml,roles/app/tasks/main.yml"
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
    "privilege": {
      "type": "string",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
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
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "integer",
      "domain": [
        365
      ],
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
      "service": {
        "equals": "openssh-server"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "28-31"
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
      "service": {
        "equals": "openssh-server"
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
        "equals": "openssh-server"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "37-40"
    }
  },
  {
    "id": "rule-004",
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "21-26"
    }
  },
  {
    "id": "rule-005",
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
      "task": "Firewall — allow app port from DMZ only",
      "lines": "15-20"
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
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": "32-35"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "zone": {
        "equals": "data"
      },
      "privilege": {
        "equals": "SUPERUSER"
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "20-24"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "zone": {
        "equals": "data"
      },
      "privilege": {
        "equals": "NOSUPERUSER"
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "26-30"
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
      "lines": "13-18"
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
      "lines": "13-18"
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      "lines": "13-18"
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
      "lines": "32-35"
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
        "equals": "proxy01.lab.local"
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
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "12-17"
    }
  },
  {
    "id": "rule-014",
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
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-12"
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
      "lines": "0-0"
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
      "port": {
        "equals": 443
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
    "id": "rule-020",
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
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "patch_available": true,
    "affects_pinned_version": true,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ",
    "recommendation": "Upgrade nginx from 1.20.0-1~focal to latest patched version"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "patch_available": true,
    "affects_pinned_version": true,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "recommendation": "Upgrade nginx from 1.20.0-1~focal to latest patched version"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "patch_available": true,
    "affects_pinned_version": true,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ",
    "recommendation": "Upgrade nginx from 1.20.0-1~focal to latest patched version"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "patch_available": true,
    "affects_pinned_version": true,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "recommendation": "Upgrade nginx from 1.20.0-1~focal to latest patched version"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 7.7,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "patch_available": true,
    "affects_pinned_version": true,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "recommendation": "Upgrade nginx from 1.20.0-1~focal to latest patched version"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "patch_available": false,
    "affects_pinned_version": true,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "recommendation": "Monitor for patches and apply mitigations for postgresql 16.2-1.pgdg22.04+1"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "patch_available": false,
    "affects_pinned_version": true,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "recommendation": "Monitor for patches and apply mitigations for postgresql 16.2-1.pgdg22.04+1"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "is_poc": false,
    "patch_available": false,
    "affects_pinned_version": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "recommendation": "Monitor for patches and apply mitigations for postgresql 16.2-1.pgdg22.04+1"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "patch_available": false,
    "affects_pinned_version": true,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "recommendation": "Monitor for patches and apply mitigations for postgresql 16.2-1.pgdg22.04+1"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "patch_available": false,
    "affects_pinned_version": true,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "recommendation": "Monitor for patches and apply mitigations for postgresql 16.2-1.pgdg22.04+1"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "patch_available": true,
    "affects_pinned_version": true,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding ",
    "recommendation": "Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 8.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "patch_available": true,
    "affects_pinned_version": true,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req",
    "recommendation": "Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "is_poc": false,
    "patch_available": true,
    "affects_pinned_version": true,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipula",
    "recommendation": "Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "patch_available": true,
    "affects_pinned_version": true,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl",
    "recommendation": "Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "is_poc": false,
    "patch_available": true,
    "affects_pinned_version": true,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani",
    "recommendation": "Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 7.2,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "patch_available": false,
    "affects_pinned_version": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
    "recommendation": "Monitor for patches and apply mitigations for postgresql 16.2-1.pgdg22.04+1"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 7.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "patch_available": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
    "recommendation": "Upgrade postgresql from 16.2-1.pgdg22.04+1 to latest patched version"
  }
]
```

## Report

# ABAC Policy Mining Report — SegCorp Ansible Configuration

## Executive Summary

This report presents an Attribute-Based Access Control (ABAC) policy mined from the SegCorp Ansible configuration. The infrastructure spans three network zones (DMZ, Application, Data) with PCI compliance requirements. The policy comprises 15 rules covering SSH access, network firewall policies, database authentication, filesystem permissions, user provisioning, and a default-deny catch-all.

## Infrastructure Overview

### Network Topology
- **DMZ Zone** (10.0.1.0/24): proxy01.lab.local — reverse proxy running nginx 1.20.0
- **App Zone** (10.0.2.0/24): app01.lab.local — application server on port 8080
- **Data Zone** (10.0.3.0/24): db01.lab.local — PostgreSQL 16.2 primary database

### Users and Groups
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

### Environment
- Organization: segcorp
- Environment: production
- Compliance Tier: PCI
- Log Retention: 365 days

## Policy Rules Summary

### SSH Access Control (rules 001-003)
SSH access is restricted per zone using AllowGroups directives:
- **DMZ**: Only `sudo` group members can SSH (admin)
- **App**: `sudo` and `developers` groups can SSH (admin, developer)
- **Data**: `sudo` and `dba` groups can SSH (admin, dba)

### Network Firewall Rules (rules 004-006, 012)
- **DMZ**: HTTPS (443/tcp) open to internet (0.0.0.0/0)
- **App**: Port 8080/tcp only from DMZ subnet (10.0.1.0/24)
- **Data**: PostgreSQL (5432/tcp) only from app subnet (10.0.2.0/24)
- **Implicit deny**: All other PostgreSQL connections are denied (rule-012)

### Database Access (rules 007-008)
- **DBA group**: SUPERUSER LOGIN privilege on PostgreSQL
- **Developers group**: NOSUPERUSER LOGIN privilege on PostgreSQL (read-only)

### Filesystem Permissions (rules 009-011)
- PostgreSQL data directory `/var/lib/postgresql/data` with mode 0700, owned by postgres:postgres
- DBA group has read/write/execute access to the data directory

### User Provisioning (rules 013-014)
- DMZ: Only sudo group users are provisioned on proxy01
- App: sudo and developers group users are provisioned on app01

### Default Deny (rule-015)
All access not explicitly permitted is denied.

## Vulnerability Assessment

### Pinned Software Versions
| Package | Pinned Version |
|---------|---------------|
| nginx | 1.20.0-1~focal |
| openssh-server | 1:9.1p1-1ubuntu1 |
| postgresql | 16.2-1.pgdg22.04+1 |

### Critical Findings

**9 Known Exploited Vulnerabilities (KEV)** and **10 Critical/High severity CVEs** identified.

#### Known Exploited Vulnerabilities

- **CVE-2009-3555** (nginx 1.20.0-1~focal): CVSS 9.8 — Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4,... Recommendation: Upgrade nginx from 1.20.0-1~focal to latest patched version
- **CVE-2024-1597** (postgresql 16.2-1.pgdg22.04+1): CVSS 10 — pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 co... Recommendation: Monitor for patches and apply mitigations for postgresql 16.2-1.pgdg22.04+1
- **CVE-2023-38408** (openssh-server 1:9.1p1-1ubuntu1): CVSS 9.8 — OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search... Recommendation: Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version
- **CVE-2024-6387** (openssh-server 1:9.1p1-1ubuntu1): CVSS 8.1 — OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthen... Recommendation: Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version
- **CVE-2007-4752** (openssh-server 1:9.1p1-1ubuntu1): CVSS 7.5 — OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies,... Recommendation: Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version
- **CVE-2019-6110** (openssh-server 1:9.1p1-1ubuntu1): CVSS 6.8 — OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from... Recommendation: Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version
- **CVE-2019-6109** (openssh-server 1:9.1p1-1ubuntu1): CVSS 6.8 — OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the p... Recommendation: Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version
- **CVE-2019-9193** (postgresql 16.2-1.pgdg22.04+1): CVSS 7.2 — PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM P... Recommendation: Monitor for patches and apply mitigations for postgresql 16.2-1.pgdg22.04+1
- **CVE-2022-31197** (postgresql 16.2-1.pgdg22.04+1): CVSS 7.1 — PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescape... Recommendation: Upgrade postgresql from 16.2-1.pgdg22.04+1 to latest patched version

#### Critical/High Severity CVEs

- **CVE-2016-0746** (nginx 1.20.0-1~focal): CVSS 9.8 — nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS r... Recommendation: Upgrade nginx from 1.20.0-1~focal to latest patched version
- **CVE-2021-46461** (nginx 1.20.0-1~focal): CVSS 9.8 — NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof i... Recommendation: Upgrade nginx from 1.20.0-1~focal to latest patched version
- **CVE-2017-20005** (nginx 1.20.0-1~focal): CVSS 9.8 — NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modific... Recommendation: Upgrade nginx from 1.20.0-1~focal to latest patched version
- **CVE-2002-1399** (postgresql 16.2-1.pgdg22.04+1): CVSS 10 — PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerabi... Recommendation: Monitor for patches and apply mitigations for postgresql 16.2-1.pgdg22.04+1
- **CVE-2007-3279** (postgresql 16.2-1.pgdg22.04+1): CVSS 10 — PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing... Recommendation: Monitor for patches and apply mitigations for postgresql 16.2-1.pgdg22.04+1
- **CVE-2013-1903** (postgresql 16.2-1.pgdg22.04+1): CVSS 10 — PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17... Recommendation: Monitor for patches and apply mitigations for postgresql 16.2-1.pgdg22.04+1
- **CVE-2013-1902** (postgresql 16.2-1.pgdg22.04+1): CVSS 10 — PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary file... Recommendation: Monitor for patches and apply mitigations for postgresql 16.2-1.pgdg22.04+1


## Ambiguities and Gaps

1. **No sudoers configuration found**: The Ansible config does not define sudoers rules. It is unclear whether sudo access is granted to the `sudo` group members beyond SSH login.
2. **No explicit firewall deny rules**: The firewalld rules only define `state: enabled` (allow) entries. Implicit deny is assumed but not explicitly configured in Ansible.
3. **pg_hba.conf implicit deny**: The pg_hba configuration only adds allow entries for the appservers subnet. The default PostgreSQL behavior (reject unmatched) is relied upon for deny, but this is not explicitly managed.
4. **No credentials management**: No Ansible vault or secrets management is visible in the configuration. Database passwords and SSH keys are not managed through the Ansible config.
5. **Developer DB access scope**: The `NOSUPERUSER` role for developers permits LOGIN but does not specify exact database/schema permissions (SELECT-only vs broader). The actual access level depends on subsequent GRANT statements not present in the Ansible config.
6. **No session logging/audit obligations**: No audit logging or session recording configurations were found in the Ansible roles.
7. **DMZ firewall allows all internet traffic**: The 0.0.0.0/0 source for HTTPS on the DMZ is intentionally internet-facing but represents a broad attack surface.

## Recommendations

1. **Upgrade nginx**: nginx 1.20.0 has multiple critical CVEs including CVE-2021-23017 (DNS resolver vulnerability). Upgrade to nginx 1.25+ or latest stable.
2. **Upgrade openssh-server**: Multiple KEV entries exist for OpenSSH. Ensure patches for CVE-2024-6387 (regreSSHion) and CVE-2023-38408 are applied.
3. **Upgrade PostgreSQL**: CVE-2024-1597 is a KEV affecting PostgreSQL. Apply the latest security patches for PostgreSQL 16.
4. **Add explicit sudoers management**: Define sudoers rules in Ansible to control privilege escalation.
5. **Add explicit firewall deny rules**: Configure explicit deny rules in firewalld for defense in depth.
6. **Implement secrets management**: Use Ansible Vault or external secrets management for database credentials.
7. **Add audit logging**: Configure session logging and audit trails for PCI compliance.
8. **Restrict DMZ firewall**: Consider geo-blocking or rate-limiting for the internet-facing HTTPS service.
