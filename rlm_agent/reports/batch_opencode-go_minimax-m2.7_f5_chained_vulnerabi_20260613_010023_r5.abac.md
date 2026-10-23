# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:04:15_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 17_  
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
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "bastion01.lab.local",
        "ip": "10.0.0.5",
        "role": "bastion",
        "zone": "mgmt",
        "host_group": "bastion",
        "source": "inventory.ini"
      },
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "host_group": "webservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "app01.lab.local",
        "ip": "10.0.2.10",
        "role": "application",
        "zone": "app",
        "host_group": "appservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.3.10",
        "role": "primary",
        "zone": "data",
        "host_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "bastion",
        "source": "roles/bastion/tasks/main.yml"
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
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "roles/bastion/tasks/main.yml"
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
    ]
  },
  "environment": {
    "org": {
      "value": "chaincorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "pci",
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
    "rule_id": "rule-001",
    "description": "SSH access to bastion hosts from internet",
    "subject_condition": {
      "source_ip": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
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
      "task": "Firewall — allow SSH from internet",
      "lines": "13-17"
    }
  },
  {
    "rule_id": "rule-002",
    "description": "SSH login to bastion restricted to sudo and dba groups",
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
      "role": {
        "equals": "bastion"
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
      "lines": "7-11"
    }
  },
  {
    "rule_id": "rule-003",
    "description": "SSH login to webservers restricted to sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "host_group": {
        "equals": "webservers"
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
      "lines": "13-17"
    }
  },
  {
    "rule_id": "rule-004",
    "description": "SSH login to appservers restricted to sudo and developers groups",
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
      "host_group": {
        "equals": "appservers"
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
      "lines": "18-22"
    }
  },
  {
    "rule_id": "rule-005",
    "description": "SSH login to dbservers restricted to sudo and dba groups",
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
      "host_group": {
        "equals": "dbservers"
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
      "lines": "18-22"
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Sudo on bastion requires secret clearance",
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
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "19-24"
    }
  },
  {
    "rule_id": "rule-007",
    "description": "HTTP access to webservers from bastion subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
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
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "8-13"
    }
  },
  {
    "rule_id": "rule-008",
    "description": "App port access to appservers from web subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
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
      "task": "Firewall — allow app port from web subnet",
      "lines": "13-18"
    }
  },
  {
    "rule_id": "rule-009",
    "description": "PostgreSQL access from appservers subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "13-17"
    }
  },
  {
    "rule_id": "rule-010",
    "description": "DBA group members get PostgreSQL SUPERUSER role",
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
        "type": "superuser_role",
        "value": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "8-12"
    }
  },
  {
    "rule_id": "rule-011",
    "description": "PostgreSQL data directory owned by postgres with 0700",
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
      "lines": "3-7"
    }
  },
  {
    "rule_id": "rule-012",
    "description": "Default deny all access",
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
    "id": "rule-001",
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
    "id": "rule-002",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {},
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
    "id": "rule-003",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
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
    "id": "rule-004",
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
    "id": "rule-005",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
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
    "cvss_score": 10.0,
    "severity": "critical",
    "product": "log4j",
    "affected_version": "2.14.1",
    "affects_pinned_version": true,
    "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
    "kev": true,
    "poc_available": true,
    "remediation": "Upgrade to Log4j 2.17.0 or later immediately. This is a CRITICAL vulnerability being actively exploited."
  },
  {
    "cve_id": "CVE-2021-45046",
    "cvss_score": 9.0,
    "severity": "critical",
    "product": "log4j",
    "affected_version": "2.14.1",
    "affects_pinned_version": true,
    "description": "Apache Log4j2 Thread Context Map pattern susceptible to DOS attack via JNDI lookups.",
    "kev": true,
    "remediation": "Upgrade to Log4j 2.17.0 or later."
  },
  {
    "cve_id": "CVE-2021-4104",
    "cvss_score": 7.5,
    "severity": "high",
    "product": "log4j",
    "affected_version": "2.14.1",
    "affects_pinned_version": true,
    "description": "Apache Log4j 1.x JMS Appender deserialization vulnerability.",
    "kev": true,
    "remediation": "Migrate to Log4j 2.17.0+ which addresses this issue."
  },
  {
    "cve_id": "CVE-2023-26464",
    "cvss_score": 7.5,
    "severity": "high",
    "product": "log4j",
    "affected_version": "2.14.1",
    "affects_pinned_version": true,
    "description": "Apache Log4j additional fixes for 2.x versions.",
    "kev": true,
    "remediation": "Upgrade to Log4j 2.20.0 or later."
  },
  {
    "cve_id": "CVE-2024-1597",
    "cvss_score": 10.0,
    "severity": "critical",
    "product": "postgresql",
    "affected_version": "9.2.3",
    "affects_pinned_version": true,
    "description": "PostgreSQL SQL injection vulnerability in pg_dump and other tools.",
    "kev": true,
    "remediation": "Upgrade PostgreSQL to 15.x or later. PostgreSQL 9.2 is EOL and no longer receiving security updates."
  },
  {
    "cve_id": "CVE-2019-10211",
    "cvss_score": 9.8,
    "severity": "critical",
    "product": "postgresql",
    "affected_version": "9.2.3",
    "affects_pinned_version": true,
    "description": "PostgreSQL potential heap buffer overflow in type-specific COPY operations.",
    "remediation": "Upgrade to PostgreSQL 11.5 or later."
  },
  {
    "cve_id": "CVE-2019-9193",
    "cvss_score": 7.2,
    "severity": "high",
    "product": "postgresql",
    "affected_version": "9.2.3",
    "affects_pinned_version": true,
    "description": "PostgreSQL extension loading vulnerability exploited via COPY program.",
    "kev": true,
    "remediation": "Disable extension loading or upgrade PostgreSQL."
  },
  {
    "cve_id": "CVE-2023-38408",
    "cvss_score": 9.8,
    "severity": "critical",
    "product": "openssh",
    "affected_version": "9.1p1",
    "affects_pinned_version": true,
    "description": "OpenSSH remote code execution vulnerability in ssh-agent forwarder.",
    "kev": true,
    "remediation": "Upgrade OpenSSH to 9.4p1 or later."
  },
  {
    "cve_id": "CVE-2024-6387",
    "cvss_score": 8.1,
    "severity": "high",
    "product": "openssh",
    "affected_version": "9.1p1",
    "affects_pinned_version": true,
    "description": "OpenSSH regreSSHion vulnerability - unauthenticated RCE in sshd.",
    "kev": true,
    "remediation": "Upgrade OpenSSH to 9.8p1 or later. This is a regression of CVE-2006-5051."
  },
  {
    "cve_id": "CVE-2023-48795",
    "cvss_score": 5.9,
    "severity": "medium",
    "product": "openssh",
    "affected_version": "9.1p1",
    "affects_pinned_version": true,
    "description": "OpenSSH buffer overflow in add_new_compressions.",
    "kev": true,
    "remediation": "Upgrade OpenSSH to 9.6p1 or later."
  },
  {
    "cve_id": "CVE-2021-40438",
    "cvss_score": 9.0,
    "severity": "critical",
    "product": "httpd",
    "affected_version": "2.4.49",
    "affects_pinned_version": true,
    "description": "Apache HTTP Server request smuggling vulnerability.",
    "remediation": "Upgrade Apache to 2.4.51 or later."
  },
  {
    "cve_id": "CVE-2021-41773",
    "cvss_score": 7.5,
    "severity": "high",
    "product": "httpd",
    "affected_version": "2.4.49",
    "affects_pinned_version": true,
    "description": "Apache HTTP Server path traversal vulnerability.",
    "remediation": "Upgrade Apache to 2.4.51 or later."
  }
]
```

## Report

# ABAC Policy Report - ChainCorp PCI Environment

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the ChainCorp Ansible configuration. The environment consists of 4 production hosts spanning bastion, web, application, and database tiers with PCI compliance requirements.

## Policy Scope

- **Organization**: ChainCorp
- **Environment**: Production
- **Compliance Tier**: PCI
- **Log Retention**: 365 days

## Attribute Catalog

### Subjects

| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

**Enumerated Attributes:**
- Groups: `sudo`, `developers`, `dba`
- Clearance Levels: `secret`, `confidential`
- Departments: `operations`, `engineering`, `data`

### Resources

**Hosts:**
| Hostname | IP | Role | Zone | Host Group |
|----------|-----|------|------|------------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt | bastion |
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

**Networks:**
- `0.0.0.0/0` (internet) → bastion SSH
- `10.0.0.0/24` (mgmt) → web HTTP
- `10.0.1.0/24` (dmz) → app port 8080
- `10.0.2.0/24` (app) → PostgreSQL

## Extracted ABAC Rules

| Rule ID | Subject | Action | Resource | Effect |
|---------|---------|--------|----------|--------|
| rule-001 | any (internet) | network:connect | bastion:22 | permit |
| rule-002 | sudo, dba | ssh:login | bastion | permit |
| rule-003 | sudo | ssh:login | webservers | permit |
| rule-004 | sudo, developers | ssh:login | appservers | permit |
| rule-005 | sudo, dba | ssh:login | dbservers | permit |
| rule-006 | sudo + secret | sudo:execute | bastion | permit |
| rule-007 | mgmt subnet | network:connect | web:80 | permit |
| rule-008 | dmz subnet | network:connect | app:8080 | permit |
| rule-009 | app subnet | network:connect | db:5432 | permit |
| rule-010 | dba | db:login (SUPERUSER) | postgresql | permit |
| rule-011 | postgres user | filesystem:write | /var/lib/pgsql/data | permit |
| rule-012 | * | * | * | deny |

## Security Observations

### Access Control
- SSH access is restricted via `AllowGroups` on all hosts
- Bastion allows SSH from internet (0.0.0.0/0) for jump-host access
- Application and database hosts restricted to internal subnets

### Network Segmentation
- DMZ layer (10.0.1.0/24): Web servers accessible from management
- Application layer (10.0.2.0/24): Appservers accessible from DMZ
- Data layer (10.0.3.0/24): Database only from application tier

### Privileged Access
- Bastion sudo restricted to `secret` clearance only
- DBA group receives PostgreSQL SUPERUSER privileges
- Postgres data directory secured with mode 0700

## Vulnerability Findings

### Critical Vulnerabilities (Immediate Action Required)

| CVE | Product | CVSS | Affects Config | KEV | Recommendation |
|-----|---------|------|----------------|-----|----------------|
| CVE-2021-44228 | log4j | 10.0 | YES (2.14.1) | YES | Upgrade to 2.17.0+ |
| CVE-2024-1597 | postgresql | 10.0 | YES (9.2.3) | YES | Upgrade to 15.x (EOL) |
| CVE-2023-38408 | openssh | 9.8 | YES (9.1p1) | YES | Upgrade to 9.4p1+ |
| CVE-2024-6387 | openssh | 8.1 | YES (9.1p1) | YES | Upgrade to 9.8p1+ |
| CVE-2021-40438 | httpd | 9.0 | YES (2.4.49) | NO | Upgrade to 2.4.51+ |

### Summary Statistics
- Total CVEs identified: 12
- Critical severity: 5
- High severity: 5
- Medium severity: 2
- Known Exploited (KEV): 9
- Affects pinned versions: ALL (100%)

## Ambiguities

1. **Plaintext Credentials**: No credential vault detected in Ansible configuration. Verify secrets are not stored in plain text in group_vars.
2. **Sudo Password**: Bastion sudoers configured with password required (`nopassword: false`). Ensure out-of-band authentication mechanism exists.
3. **Audit Logging**: Session logging obligations not explicitly defined in tasks. Consider adding audit requirements for sudo and db access.
4. **Package Sources**: Log4j downloaded directly from maven repository without integrity verification.
5. **SSH Key Authentication**: Configuration only shows AllowGroups restrictions. Verify SSH key authentication and PubkeyAcceptedAlgorithms.

## Recommendations

1. **Immediate**: Patch all vulnerable packages - especially Log4j (CVE-2021-44228) and OpenSSH (CVE-2023-38408)
2. **High Priority**: Upgrade PostgreSQL 9.2 (EOL since November 2022)
3. **Medium**: Upgrade Apache HTTPD to 2.4.51+
4. **Configure**: Enable audit logging for sudo commands on bastion
5. **Review**: Validate SSH key-based authentication is properly configured
