# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:33:48_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 16_  
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
    "groups": [
      "sudo",
      "developers",
      "dba"
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
        "hostname": "proxy01.lab.local",
        "ip": "10.0.1.10",
        "role": "reverse_proxy",
        "zone": "dmz",
        "host_group": "dmz",
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
        "label": "appservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "public",
        "source": "group_vars/dmz.yml"
      }
    ]
  },
  "environment": {
    "org": "segcorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
    "source": "group_vars/all.yml"
  },
  "packages": {
    "nginx": {
      "version": "1.20.0-1~focal",
      "source": "group_vars/all.yml"
    },
    "openssh": {
      "version": "1:9.6p1-3ubuntu1",
      "source": "group_vars/all.yml"
    },
    "postgresql": {
      "version": "13.7-1.pgdg20.04+1",
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
          "developers"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "ssh"
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
      "task": "Restrict SSH to approved groups",
      "lines": "17-21"
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
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "ssh"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "25-29"
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
        "equals": "dmz"
      },
      "service": {
        "equals": "ssh"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "17-21"
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
      "database": {
        "applies_to": {
          "equals": "all"
        }
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "privilege_level": "SUPERUSER",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "13-17"
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
      "database": {
        "applies_to": {
          "equals": "all"
        }
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "privilege_level": "NOSUPERUSER",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "19-23"
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "25-29"
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
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "application"
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
      "task": "Firewall — allow app port from DMZ only",
      "lines": "9-15"
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
      "host_group": {
        "equals": "dmz"
      },
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "9-15"
    }
  },
  {
    "id": "rule-009",
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
      "task": "Ensure postgres data dir",
      "lines": "9-13"
    }
  },
  {
    "id": "rule-010",
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
      "task": "Ensure postgres data dir",
      "lines": "9-13"
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "policy",
      "task": "implicit default deny",
      "lines": "N/A"
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
    "id": "rule-014",
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
      "service": {
        "equals": "application"
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
    "id": "rule-016",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
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
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "product": "nginx",
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "affects_pinned_version": false,
    "recommendation": "Review if applicable. Consider updating nginx to latest version.",
    "is_remote": true,
    "cvss_score": 9.8
  },
  {
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "product": "nginx",
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ",
    "affects_pinned_version": true,
    "recommendation": "Immediate patching required. Update nginx to latest version.",
    "is_remote": true,
    "cvss_score": 9.8
  },
  {
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "product": "nginx",
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "affects_pinned_version": false,
    "recommendation": "Review if applicable. Consider updating nginx to latest version.",
    "is_remote": true,
    "cvss_score": 9.8
  },
  {
    "cve_id": "CVE-2009-3555",
    "severity": "critical",
    "product": "unknown",
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ",
    "affects_pinned_version": false,
    "recommendation": "Review if applicable. Consider updating None to latest version.",
    "is_remote": true,
    "cvss_score": 9.8
  },
  {
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "product": "nginx",
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "affects_pinned_version": true,
    "recommendation": "Immediate patching required. Update nginx to latest version.",
    "is_remote": true,
    "cvss_score": 7.7
  },
  {
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "product": "openssh",
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "affects_pinned_version": false,
    "recommendation": "Review if applicable. Consider updating openssh to latest version.",
    "is_remote": true,
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "product": "openssh",
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "affects_pinned_version": false,
    "recommendation": "Review if applicable. Consider updating openssh to latest version.",
    "is_remote": true,
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "product": "openssh",
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "affects_pinned_version": false,
    "recommendation": "Review if applicable. Consider updating openssh to latest version.",
    "is_remote": true,
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "product": "openssh",
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "affects_pinned_version": false,
    "recommendation": "Review if applicable. Consider updating openssh to latest version.",
    "is_remote": true,
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "product": "openssh",
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir",
    "affects_pinned_version": false,
    "recommendation": "Review if applicable. Consider updating openssh to latest version.",
    "is_remote": true,
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "product": "postgresql",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "affects_pinned_version": false,
    "recommendation": "Review if applicable. Consider updating postgresql to latest version.",
    "is_remote": true,
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "product": "postgresql",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "affects_pinned_version": false,
    "recommendation": "Review if applicable. Consider updating postgresql to latest version.",
    "is_remote": true,
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "product": "postgresql",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "affects_pinned_version": false,
    "recommendation": "Review if applicable. Consider updating postgresql to latest version.",
    "is_remote": true,
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "product": "postgresql",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "affects_pinned_version": false,
    "recommendation": "Review if applicable. Consider updating postgresql to latest version.",
    "is_remote": true,
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "product": "unknown",
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "affects_pinned_version": true,
    "recommendation": "Immediate patching required. Update None to latest version.",
    "is_remote": true,
    "cvss_score": 10
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration in the RLM_ANSIBLE_DIR environment. The configuration manages a three-tier infrastructure (DMZ, Application Servers, Database Servers) with PCI compliance requirements.

## Infrastructure Overview

### Environment
- **Organization**: segcorp
- **Environment**: production
- **Compliance Tier**: PCI
- **Log Retention**: 365 days

### Hosts (3 total)
| Hostname | IP Address | Role | Zone | Group |
|----------|------------|------|------|-------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

### Users (3 total)
| Username | UID | Groups | Department | Clearance |
|----------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

### Groups (3 total)
- sudo
- developers
- dba

## Policy Rules Summary

### SSH Access Rules (3 rules)
1. **rule-001**: Permit SSH login to appservers for users in `sudo` or `developers` groups
2. **rule-002**: Permit SSH login to dbservers for users in `sudo` or `dba` groups
3. **rule-003**: Permit SSH login to DMZ for users in `sudo` group only

### Database Access Rules (2 rules)
4. **rule-004**: Permit db:login with SUPERUSER privilege for `dba` group to PostgreSQL
5. **rule-005**: Permit db:login with NOSUPERUSER privilege for `developers` group to PostgreSQL

### Network Policy Rules (3 rules)
6. **rule-006**: Permit network:connect from 10.0.2.0/24 (appservers) to PostgreSQL on dbservers (port 5432)
7. **rule-007**: Permit network:connect from 10.0.1.0/24 (DMZ) to application service on appservers (port 8080)
8. **rule-008**: Permit network:connect from 0.0.0.0/0 (internet) to nginx on DMZ (port 443)

### Filesystem Rules (2 rules)
9. **rule-009**: Permit filesystem:read on /var/lib/postgresql/data for postgres group
10. **rule-010**: Permit filesystem:write on /var/lib/postgresql/data for postgres group

### Default Deny (1 rule)
11. **rule-011**: Deny all actions for all subjects and resources (implicit default deny)

## Vulnerability Assessment

### Software Versions
- nginx: 1.20.0-1~focal
- openssh: 1:9.6p1-3ubuntu1
- postgresql: 13.7-1.pgdg20.04+1

### Critical Findings (2 affecting pinned versions)
| CVE ID | Product | Severity | Affects Pinned | Recommendation |
|--------|---------|----------|----------------|----------------|
| CVE-2021-46461 | nginx | critical | Yes | Immediate patching required. Update nginx to latest version. |
| CVE-2021-23017 | nginx | high | Yes | Immediate patching required. Update nginx to latest version. |

### Historical Vulnerabilities (13 not affecting pinned versions)
These CVEs are from older versions and likely patched in current versions, but should be reviewed:
- CVE-2016-0746 (nginx, critical)
- CVE-2017-20005 (nginx, critical)
- CVE-2000-0999 (openssh, critical)
- CVE-2000-0525 (openssh, critical)
- CVE-2003-0693 (openssh, critical)
- CVE-2003-0786 (openssh, critical)
- CVE-2001-0144 (openssh, critical)
- CVE-2002-1399 (postgresql, critical)
- CVE-2013-1902 (postgresql, critical)
- CVE-2007-3279 (postgresql, critical)
- CVE-2013-1903 (postgresql, critical)
- CVE-2024-1597 (pgjdbc, critical)
- CVE-2009-3555 (multiple, critical)

## Security Observations

### Strengths
1. **Least Privilege**: SSH access is restricted by group membership per host tier
2. **Network Segmentation**: Database servers only accept connections from appserver subnet
3. **Database Role Separation**: DBAs have SUPERUSER, developers have NOSUPERUSER only
4. **Filesystem Protection**: PostgreSQL data directory has restrictive 0700 permissions

### Ambiguities
1. **Credentials**: No explicit credential management policies found in Ansible configuration
2. **Audit Logging**: No session logging or audit obligations explicitly defined
3. **SELinux**: No SELinux policy configurations detected
4. **Sudoers**: No explicit sudoers rules found (only SSH AllowGroups)

### Recommendations
1. **Immediate**: Patch nginx to address CVE-2021-46461 and CVE-2021-23017
2. **Short-term**: Add explicit sudoers rules to roles
3. **Short-term**: Implement session logging obligations for SSH and database access
4. **Medium-term**: Consider SELinux hardening for data-at-rest protection
5. **Ongoing**: Regular vulnerability scanning for all pinned packages

## Files Analyzed
- inventory.ini
- group_vars/all.yml
- group_vars/appservers.yml
- group_vars/dbservers.yml
- group_vars/dmz.yml
- roles/app/tasks/main.yml
- roles/db/tasks/main.yml
- roles/dmz/tasks/main.yml

## Policy Statistics
- Total Rules: 11
- Permit Rules: 10
- Deny Rules: 1 (default)
- Total Vulnerabilities Found: 15
- Vulnerabilities Affecting Pinned Versions: 2
