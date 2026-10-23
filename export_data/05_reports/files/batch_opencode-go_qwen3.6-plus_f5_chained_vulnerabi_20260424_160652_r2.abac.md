# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:17:11_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 12 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "users": {
    "domain": "list",
    "source": "group_vars/all.yml",
    "values": [
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
    ]
  },
  "groups": {
    "domain": [
      "sudo",
      "developers",
      "dba"
    ],
    "source": "group_vars/all.yml,group_vars/appservers.yml,group_vars/bastion.yml,group_vars/dbservers.yml,group_vars/webservers.yml",
    "values": [
      "sudo",
      "developers",
      "dba"
    ]
  },
  "clearance_levels": {
    "domain": [
      "secret",
      "confidential"
    ],
    "source": "group_vars/all.yml",
    "values": [
      "secret",
      "confidential"
    ]
  },
  "departments": {
    "domain": [
      "operations",
      "engineering",
      "data"
    ],
    "source": "group_vars/all.yml",
    "values": [
      "operations",
      "engineering",
      "data"
    ]
  },
  "hosts": {
    "domain": "list",
    "source": "inventory.ini",
    "values": [
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
  "services": {
    "domain": "list",
    "source": "inventory.ini,group_vars/*.yml",
    "values": [
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all",
        "source": "group_vars/*.yml"
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
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      }
    ]
  },
  "paths": {
    "domain": "list",
    "source": "roles/db/tasks/main.yml",
    "values": [
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
    "domain": "list",
    "source": "group_vars/*.yml",
    "values": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/bastion.yml"
      },
      {
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "bastion-subnet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web-subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app-subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "db-subnet",
        "source": "inferred"
      }
    ]
  },
  "environment": {
    "domain": [
      "production"
    ],
    "source": "inventory.ini",
    "values": {
      "org": "chaincorp",
      "environment": "production",
      "compliance_tier": "pci",
      "default_log_retention_days": 365
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
      "role": {
        "equals": "bastion"
      },
      "port": {
        "equals": 22
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        8,
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
      "role": {
        "equals": "bastion"
      },
      "port": {
        "equals": 22
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        14,
        20
      ]
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
      "applies_to": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        22,
        29
      ]
    },
    "obligations": [
      {
        "type": "audit",
        "description": "nopassword: false - password required for sudo"
      }
    ]
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "port": {
        "equals": 22
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        21,
        25
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "port": {
        "equals": 80
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        13,
        19
      ]
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
      "role": {
        "equals": "application"
      },
      "port": {
        "equals": 22
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        31,
        35
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "application"
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
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        23,
        29
      ]
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
      "role": {
        "equals": "primary"
      },
      "port": {
        "equals": 22
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        29,
        33
      ]
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
      "role": {
        "equals": "primary"
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
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        16,
        21
      ]
    },
    "obligations": [
      {
        "type": "privilege",
        "description": "SUPERUSER role attribute granted"
      },
      {
        "type": "filesystem_acl",
        "description": "Data dir /var/lib/postgresql/data mode 0700 owner/group postgres (system account)"
      }
    ]
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
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
      "lines": [
        23,
        27
      ]
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
    "id": "rule-012",
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
    "id": "rule-013",
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
    "id": "rule-014",
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
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cve_id": "CVE-2021-44228",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "description": "Log4Shell: RCE via unprotected JNDI lookups in log messages",
    "recommendation": "Upgrade to log4j 2.17.0+ or apply mitigation: set log4j2.formatMsgNoLookups=true"
  },
  {
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cve_id": "CVE-2021-45046",
    "cvss_score": 9.0,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "description": "Thread Context Lookup Pattern RCE in non-default configurations",
    "recommendation": "Upgrade to log4j 2.17.0+"
  },
  {
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cve_id": "CVE-2021-44832",
    "cvss_score": 6.6,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "description": "RCE via unsafe JNDI LDAP data source URI in JDBCAppender",
    "recommendation": "Upgrade to log4j 2.17.0+ or restrict JdbcAppender configuration access"
  },
  {
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cve_id": "CVE-2021-45105",
    "cvss_score": 5.9,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "description": "DoS via uncontrolled recursion from self-referential lookups",
    "recommendation": "Upgrade to log4j 2.17.0+"
  },
  {
    "product": "apache",
    "pinned_version": "2.4.49",
    "cve_id": "CVE-2021-41773",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Path traversal via flawed path normalization in 2.4.49",
    "recommendation": "Upgrade to Apache 2.4.51+"
  },
  {
    "product": "apache",
    "pinned_version": "2.4.49",
    "cve_id": "CVE-2021-42013",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Path traversal affecting 2.4.49 and 2.4.50",
    "recommendation": "Upgrade to Apache 2.4.51+"
  },
  {
    "product": "apache",
    "pinned_version": "2.4.49",
    "cve_id": "CVE-2021-44790",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Buffer overflow in mod_lua multipart parser (affects <=2.4.51)",
    "recommendation": "Upgrade to Apache 2.4.52+"
  },
  {
    "product": "apache",
    "pinned_version": "2.4.49",
    "cve_id": "CVE-2022-22720",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Request smuggling via failure to close inbound connections on errors",
    "recommendation": "Upgrade to Apache 2.4.53+"
  },
  {
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cve_id": "CVE-2021-32027",
    "cvss_score": 8.8,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Buffer overflow from missing bounds checks in SQL array value modifications (affects < 9.6.22)",
    "recommendation": "Upgrade to PostgreSQL 13.3+ or at minimum 9.6.22+"
  },
  {
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cve_id": "CVE-2021-23214",
    "cvss_score": 8.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "MITM via SQL injection during SSL connection negotiation with trust/cert auth",
    "recommendation": "Upgrade PostgreSQL and enforce scram-sha-256 authentication"
  },
  {
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cve_id": "CVE-2022-1552",
    "cvss_score": 8.8,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Privilege escalation via late/missing protection activation during object operations",
    "recommendation": "Upgrade to a supported PostgreSQL version"
  },
  {
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cve_id": "CVE-2023-2454",
    "cvss_score": 7.2,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Schema_element defeats protective search_path changes allowing privilege escalation",
    "recommendation": "Upgrade to a supported PostgreSQL version"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1-1ubuntu1",
    "host": "bastion01.lab.local",
    "cve_id": "CVE-2023-38408",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "RCE via insufficiently trustworthy search path in PKCS#11 feature of ssh-agent (affects < 9.3p2)",
    "recommendation": "Upgrade OpenSSH to 9.3p2+ on bastion"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1-1ubuntu1",
    "host": "bastion01.lab.local",
    "cve_id": "CVE-2024-6387",
    "cvss_score": 8.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "Race condition in sshd signal handling allows unauthenticated remote RCE (affects < 9.8p1)",
    "recommendation": "Upgrade OpenSSH to 9.8p1+ on bastion"
  }
]
```

## Report

# ABAC Policy Report — ChainCorp Infrastructure

## Executive Summary

This report documents the mined Attribute-Based Access Control (ABAC) policy from the ChainCorp Ansible configuration. The infrastructure is a PCI-compliant production environment with 4 hosts across 4 security zones, 3 named users, and 3 access-control groups.

**Key findings:**
- **11 access rules** extracted (10 permit + 1 default-deny)
- **14 vulnerabilities** identified across 4 pinned packages — all affect the deployed versions
- **4 KEV (Known Exploited Vulnerabilities)** found, all in Log4j 2.14.1
- Critical risk: Log4j 2.14.1 (CVE-2021-44228, CVSS 10.0) and Apache 2.4.49 (CVE-2021-41773, CVSS 9.8) are actively exploitable

## Environment

| Attribute | Value |
|---|---|
| Organization | chaincorp |
| Environment | production |
| Compliance Tier | PCI |
| Default Log Retention | 365 days |

## Subjects

### Users

| User | UID | Groups | Department | Clearance |
|---|---|---|---|---|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

### Groups
- `sudo` — administrative access
- `developers` — engineering team
- `dba` — database administration

### Clearance Levels
- `secret` (admin, dba)
- `confidential` (developer)

## Resources

### Hosts

| Hostname | IP | Role | Zone | Group |
|---|---|---|---|---|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt | bastion |
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

### Network Segments

| CIDR | Zone | Label |
|---|---|---|
| 0.0.0.0/0 | external | internet |
| 10.0.0.0/24 | mgmt | bastion-subnet |
| 10.0.1.0/24 | dmz | web-subnet |
| 10.0.2.0/24 | app | app-subnet |

## Access Rules Summary

| Rule ID | Action | Subject | Resource | Effect |
|---|---|---|---|---|
| rule-001 | ssh:login | groups: [sudo, dba] | bastion:22/tcp | permit |
| rule-002 | network:connect | source: 0.0.0.0/0 | bastion:22/tcp | permit |
| rule-003 | sudo:execute | groups: [sudo] + clearance: secret | all hosts | permit |
| rule-004 | ssh:login | groups: [sudo] | frontend:22/tcp | permit |
| rule-005 | network:connect | source: 10.0.0.0/24 | frontend:80/tcp | permit |
| rule-006 | ssh:login | groups: [sudo, developers] | application:22/tcp | permit |
| rule-007 | network:connect | source: 10.0.1.0/24 | application:8080/tcp | permit |
| rule-008 | ssh:login | groups: [sudo, dba] | primary:22/tcp | permit |
| rule-009 | db:login | groups: [dba] | primary:postgresql:5432 | permit |
| rule-010 | network:connect | source: 10.0.2.0/24 | primary:postgresql:5432 | permit |
| rule-011 | * | all | all | deny |

## Vulnerability Assessment

### Critical Findings

| CVE | Product | Pinned Version | CVSS | KEV | Affects |
|---|---|---|---|---|---|
| CVE-2021-44228 | log4j | 2.14.1 | 10.0 | ✅ | ✅ |
| CVE-2021-45046 | log4j | 2.14.1 | 9.0 | ✅ | ✅ |
| CVE-2021-41773 | apache | 2.4.49 | 9.8 | ❌ | ✅ |
| CVE-2021-42013 | apache | 2.4.49 | 9.8 | ❌ | ✅ |
| CVE-2021-44790 | apache | 2.4.49 | 9.8 | ❌ | ✅ |
| CVE-2022-22720 | apache | 2.4.49 | 9.8 | ❌ | ✅ |
| CVE-2023-38408 | openssh | 9.1p1 | 9.8 | ❌ | ✅ |
| CVE-2021-44832 | log4j | 2.14.1 | 6.6 | ✅ | ✅ |
| CVE-2021-45105 | log4j | 2.14.1 | 5.9 | ✅ | ✅ |
| CVE-2021-32027 | postgresql | 9.2.3 | 8.8 | ❌ | ✅ |
| CVE-2022-1552 | postgresql | 9.2.3 | 8.8 | ❌ | ✅ |
| CVE-2021-23214 | postgresql | 9.2.3 | 8.1 | ❌ | ✅ |
| CVE-2023-2454 | postgresql | 9.2.3 | 7.2 | ❌ | ✅ |
| CVE-2024-6387 | openssh | 9.1p1 | 8.1 | ❌ | ✅ |

### Remediation Priority

1. **URGENT**: Upgrade Log4j from 2.14.1 to 2.17.0+ — CVE-2021-44228 (Log4Shell) is in KEV and CVSS 10.0
2. **URGENT**: Upgrade Apache from 2.4.49 to 2.4.53+ — multiple critical RCE/path-traversal CVEs
3. **HIGH**: Upgrade OpenSSH on bastion from 9.1p1 to 9.8p1+ — CVE-2024-6387 (regreSSHion) allows unauthenticated RCE
4. **HIGH**: Upgrade PostgreSQL from 9.2.3 to a supported version (13.3+) — 9.2 is EOL with multiple known exploits

## Ambiguities & Observations

1. **Credentials in templates**: The pg_hba.conf task uses `scram-sha-256` auth but no password provisioning is visible in the configuration. Password management for the DBA users is not explicit.
2. **No explicit deny rules**: The configuration relies on implicit deny (default-deny is not configured in any file — rule-011 is inferred).
3. **Bastion SSH from 0.0.0.0/0**: The bastion allows SSH from the entire internet (rule-002). This is intentional for a bastion host but requires strong SSH key enforcement not visible here.
4. **No explicit user:create tasks**: Users are referenced from `group_vars/all.yml` but no `user:` module tasks were found in roles — user provisioning may happen outside this configuration.
5. **Shared SSH version variable**: `ssh_version` (9.9p1) is used on non-bastion hosts, which is recent enough to mitigate known CVEs. Only the bastion's pinned `ssh_version_bastion` (9.1p1) is vulnerable.
6. **PostgreSQL data directory**: Mode 0700 owned by `postgres:postgres` is a best-practice filesystem ACL for DB data directories.

## Source Files

| File | Purpose |
|---|---|
| inventory.ini | Host inventory, zones, compliance tier |
| group_vars/all.yml | Users, clearance, package versions, org settings |
| group_vars/bastion.yml | Bastion SSH groups, firewall sources |
| group_vars/webservers.yml | Web server HTTP port, firewall sources |
| group_vars/appservers.yml | App server port, firewall sources |
| group_vars/dbservers.yml | PostgreSQL port, data dir, DB allow sources |
| roles/bastion/tasks/main.yml | SSH restriction, firewall, sudoers |
| roles/web/tasks/main.yml | Apache/SSH install, firewall, SSH restriction |
| roles/app/tasks/main.yml | Log4j deployment, firewall, SSH restriction |
| roles/db/tasks/main.yml | PostgreSQL install, data dir ACL, DB user, pg_hba, SSH restriction |
