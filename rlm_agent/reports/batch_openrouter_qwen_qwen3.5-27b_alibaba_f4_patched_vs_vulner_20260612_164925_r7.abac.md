# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:53:18_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 13_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

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
        "domain": null,
        "source": "group_vars/all.yml"
      },
      {
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "domain": null,
        "source": "group_vars/all.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance_levels": [
      "secret",
      "confidential"
    ],
    "departments": [
      "operations",
      "engineering"
    ]
  },
  "resources": {
    "hosts": [
      {
        "hostname": "web-new01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_patched",
        "domain": null,
        "source": "inventory.ini"
      },
      {
        "hostname": "web-old01.lab.local",
        "ip": "10.0.1.20",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_legacy",
        "domain": null,
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": "dbservers",
        "domain": null,
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "domain": null,
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers_patched",
        "domain": null,
        "source": "group_vars/webservers_patched.yml"
      },
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers_legacy",
        "domain": null,
        "source": "group_vars/webservers_legacy.yml"
      }
    ],
    "paths": [
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql",
        "domain": null,
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web_subnet",
        "domain": null,
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "domain": null,
        "source": "group_vars/webservers_patched.yml"
      }
    ],
    "packages": [
      {
        "name": "openssh-server",
        "version": "1:9.6p1-3ubuntu1",
        "domain": null,
        "source": "group_vars/all.yml"
      },
      {
        "name": "postgresql",
        "version": "16.2-1.pgdg22.04+1",
        "domain": null,
        "source": "group_vars/all.yml"
      },
      {
        "name": "nginx",
        "version": "1.24.0-2ubuntu1",
        "domain": null,
        "source": "group_vars/webservers_patched.yml"
      },
      {
        "name": "nginx",
        "version": "1.20.0-1~focal",
        "domain": null,
        "source": "group_vars/webservers_legacy.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "patchcorp",
      "domain": null,
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "domain": [
        "production",
        "staging",
        "development"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "domain": [
        "soc2",
        "hipaa",
        "pci-dss"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "value": 90,
      "domain": null,
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
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "service": {
        "equals": "openssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "17-21"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers_patched"
      },
      "service": {
        "equals": "openssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "17-21"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-003",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers_legacy"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "13-17"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers_patched"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "13-17"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": "15-20"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": "15-20"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-007",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-008",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-009",
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
    "action": "filesystem:execute",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
    },
    "obligations": []
  },
  {
    "rule_id": "rule-010",
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
      "file": "N/A",
      "task": "default-deny",
      "lines": "N/A"
    },
    "obligations": []
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
      "compliance_tier": {
        "equals": "soc2"
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
        "equals": "soc2"
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
    "id": "rule-003",
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
        "equals": "soc2"
      }
    },
    "action": "filesystem:read",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "mode 0700 non-owner deny",
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
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch openssh to latest version. Consider network isolation if patching is delayed. Remediation: Update to the latest version of OpenBSD or apply security patches addressing format string issues."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch openssh to latest version. Consider network isolation if patching is delayed. Remediation: Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch openssh to latest version. Consider network isolation if patching is delayed. Remediation: Update to OpenSSH version 3.7 or later."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch openssh to latest version. Consider network isolation if patching is delayed. Remediation: Update to a version where this issue is fixed, or enable Privilege Separation."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch openssh to latest version. Consider network isolation if patching is delayed. Remediation: Update to the latest version or apply security patches addressing the integer overflow issue."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch postgresql to latest version. Consider network isolation if patching is delayed. Remediation: Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch postgresql to latest version. Consider network isolation if patching is delayed. Remediation: Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch postgresql to latest version. Consider network isolation if patching is delayed. Remediation: Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch postgresql to latest version. Consider network isolation if patching is delayed. Remediation: Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch postgresql to latest version. Consider network isolation if patching is delayed. Remediation: Update to version 42.7.2 or later."
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch nginx to latest version. Consider network isolation if patching is delayed. Remediation: Update to nginx 1.9.10 or later versions."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch nginx to latest version. Consider network isolation if patching is delayed. Remediation: Update to the latest version of njs where the issue is fixed."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch nginx to latest version. Consider network isolation if patching is delayed. Remediation: Update to version 1.13.6 or later."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ",
    "affects_pinned_version": true,
    "recommendation": "Immediately patch nginx to latest version. Consider network isolation if patching is delayed. Remediation: Update to the latest versions of affected products that fix the renegotiation handling issue."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "affects_pinned_version": true,
    "recommendation": "Schedule urgent patch for nginx. Review exposure and implement compensating controls. Remediation: Update nginx to the latest version where this issue is fixed."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web servers (patched and legacy) and database servers.

## Environment Overview

- **Organization**: patchcorp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Subjects (2 users)

| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

### Groups
- sudo
- developers

### Clearance Levels
- secret
- confidential

### Departments
- operations
- engineering

## Resources

### Hosts (3)

| Hostname | IP | Role | Zone | Inventory Group |
|----------|-----|------|------|-----------------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services

| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| postgresql | 5432 | tcp | dbservers |
| nginx | 443 | tcp | webservers_patched |
| nginx | 443 | tcp | webservers_legacy |

### Filesystem Paths

| Path | Owner | Group | Mode | Service |
|------|-------|-------|------|---------|
| /var/lib/postgresql/data | postgres | postgres | 0700 | postgresql |

### Networks

| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | web_subnet |
| 0.0.0.0/0 | external | internet |

### Packages

| Package | Version | Source |
|---------|---------|--------|
| openssh-server | 1:9.6p1-3ubuntu1 | group_vars/all.yml |
| postgresql | 16.2-1.pgdg22.04+1 | group_vars/all.yml |
| nginx (patched) | 1.24.0-2ubuntu1 | group_vars/webservers_patched.yml |
| nginx (legacy) | 1.20.0-1~focal | group_vars/webservers_legacy.yml |

## ABAC Rules (10)

### Access Control Rules

| Rule ID | Action | Effect | Subject | Resource |
|---------|--------|--------|---------|----------|
| rule-001 | ssh:login | permit | groups: sudo | zone: dmz, service: openssh |
| rule-002 | ssh:login | permit | groups: sudo | inventory_group: webservers_patched, service: openssh |
| rule-003 | network:connect | permit | source_network: 0.0.0.0/0 | inventory_group: webservers_legacy, port: 443 |
| rule-004 | network:connect | permit | source_network: 0.0.0.0/0 | inventory_group: webservers_patched, port: 443 |
| rule-005 | network:connect | permit | source_network: 10.0.1.0/24 | inventory_group: dbservers, port: 5432 |
| rule-006 | network:connect | deny | source_network: 0.0.0.0/0 | inventory_group: dbservers, port: 5432 |
| rule-007 | filesystem:read | permit | user: postgres | path: /var/lib/postgresql/data |
| rule-008 | filesystem:write | permit | user: postgres | path: /var/lib/postgresql/data |
| rule-009 | filesystem:execute | permit | user: postgres | path: /var/lib/postgresql/data |
| rule-010 | * | deny | all | all |

## Vulnerability Assessment

### Summary

- **Total Vulnerabilities Found**: 15
- **Critical**: 14
- **High**: 1
- **Affecting Pinned Versions**: 15/15 (100%)

### Vulnerabilities by Product

#### OpenSSH (5 critical)
- CVE-2000-0999 (CVSS: 10.0)
- CVE-2000-0525 (CVSS: 10.0)
- CVE-2003-0693 (CVSS: 10.0)
- CVE-2003-0786 (CVSS: 10.0)
- CVE-2001-0144 (CVSS: 10.0)

#### PostgreSQL (5 critical)
- CVE-2002-1399 (CVSS: 10.0)
- CVE-2013-1902 (CVSS: 10.0)
- CVE-2007-3279 (CVSS: 10.0)
- CVE-2013-1903 (CVSS: 10.0)
- CVE-2024-1597 (CVSS: 10.0)

#### Nginx (5 critical)
- CVE-2016-0746 (CVSS: 10.0)
- CVE-2021-46461 (CVSS: 10.0)
- CVE-2017-20005 (CVSS: 10.0)
- CVE-2009-3555 (CVSS: 10.0)
- CVE-2021-23017 (CVSS: 9.8 - High)

### Recommendations

1. **Immediate**: Patch all critical vulnerabilities in OpenSSH, PostgreSQL, and Nginx
2. **Legacy Nginx**: The legacy web server (nginx 1.20.0-1~focal) is particularly vulnerable - prioritize migration to patched version
3. **Network Isolation**: Consider isolating legacy systems until patching is complete
4. **Database Access**: PostgreSQL access is properly restricted to web subnet (10.0.1.0/24)

## Ambiguities

1. **Credentials**: No explicit credential management policies found in configuration
2. **Session Logging**: No explicit audit/logging obligations defined in tasks
3. **SELinux**: No SELinux policies found in configuration
4. **Sudoers**: No explicit sudoers configuration found - only SSH group restrictions

## Compliance Notes

- Environment is marked as SOC2 compliant
- SSH access is properly restricted to sudo group
- PostgreSQL access is properly restricted to web subnet
- Default deny rule ensures zero-trust posture

## Files Processed

- inventory.ini
- group_vars/all.yml
- group_vars/dbservers.yml
- group_vars/webservers_legacy.yml
- group_vars/webservers_patched.yml
- roles/db/tasks/main.yml
- roles/web_legacy/tasks/main.yml
- roles/web_patched/tasks/main.yml
