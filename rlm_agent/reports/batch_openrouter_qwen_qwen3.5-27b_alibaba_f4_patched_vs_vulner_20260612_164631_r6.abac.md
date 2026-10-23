# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:52:53_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 13 | Rules: 14_  
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
        "source": "group_vars/all.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance_levels": [
      {
        "value": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "value": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "value": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "value": "engineering",
        "source": "group_vars/all.yml"
      }
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
        "source": "inventory.ini"
      },
      {
        "hostname": "web-old01.lab.local",
        "ip": "10.0.1.20",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_legacy",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers_patched,webservers_legacy",
        "source": "group_vars/webservers_patched.yml,group_vars/webservers_legacy.yml"
      },
      {
        "name": "openssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers_patched,webservers_legacy",
        "source": "roles/web_legacy/tasks/main.yml,roles/web_patched/tasks/main.yml"
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
        "label": "web_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "any",
        "label": "internet",
        "source": "group_vars/webservers_legacy.yml,group_vars/webservers_patched.yml"
      }
    ]
  },
  "environment": {
    "org": "patchcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "inventory.ini,group_vars/all.yml"
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-002",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-003",
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
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
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": "16-21"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
      "service": {
        "equals": "openssh"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "20-24"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-006",
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "14-19"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
      "service": {
        "equals": "nginx"
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
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "14-19"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
      "service": {
        "equals": "openssh"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "20-24"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-009",
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
    "source": {
      "file": "implicit",
      "task": "default-deny-policy",
      "lines": "N/A"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-010",
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
    "id": "rule-011",
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
    "id": "rule-013",
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
      "service": {
        "equals": "nginx"
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "affected_products": [
      "openssh"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues."
  },
  {
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "affected_products": [
      "openssh"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option."
  },
  {
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "affected_products": [
      "openssh"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to OpenSSH version 3.7 or later."
  },
  {
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "affected_products": [
      "openssh"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation."
  },
  {
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir",
    "affected_products": [
      "openssh"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue."
  },
  {
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "affected_products": [
      "postgresql"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "affected_products": [
      "postgresql"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "affected_products": [
      "postgresql"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "affected_products": [
      "postgresql"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "is_remote": true,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "affected_products": [
      "nginx"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to nginx 1.9.10 or later versions."
  },
  {
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "is_remote": true,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "affected_products": [
      "nginx"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to version 1.13.6 or later."
  },
  {
    "cve_id": "CVE-2009-3555",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "is_remote": true,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ",
    "affected_products": [
      "nginx"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest versions of affected products that fix the renegotiation handling issue."
  },
  {
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "is_kev": false,
    "is_remote": true,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "affected_products": [
      "nginx"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update nginx to the latest version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2023-38408",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "is_remote": true,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding ",
    "affected_products": [
      "openssh"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to OpenSSH 9.3p2 or later."
  },
  {
    "cve_id": "CVE-2024-6387",
    "severity": "high",
    "cvss_score": 8.1,
    "is_kev": true,
    "is_remote": true,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req",
    "affected_products": [
      "openssh"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenSSH where this regression is fixed."
  },
  {
    "cve_id": "CVE-2007-4752",
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "is_remote": true,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipula",
    "affected_products": [
      "openssh"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to OpenSSH 4.7 or later."
  },
  {
    "cve_id": "CVE-2019-6109",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "is_remote": true,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani",
    "affected_products": [
      "openssh"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed."
  },
  {
    "cve_id": "CVE-2019-6110",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "is_remote": true,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl",
    "affected_products": [
      "openssh"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed."
  },
  {
    "cve_id": "CVE-2019-9193",
    "severity": "high",
    "cvss_score": 7.2,
    "is_kev": true,
    "is_remote": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
    "affected_products": [
      "postgresql"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue."
  },
  {
    "cve_id": "CVE-2023-44487",
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "is_remote": true,
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many streams quickly, letting attackers consume server resources, exploit has been observed in the wild f",
    "affected_products": [
      "nginx"
    ],
    "affects_pinned_version": "unknown",
    "recommendation": "Implement rate limiting and update to the latest HTTP/2 protocol standards or patches."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web servers (patched and legacy) and database servers.

## Environment Overview

- **Organization**: patchcorp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Subjects (Users & Groups)

| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

### Groups
- `sudo` - Administrative access
- `developers` - Application development

## Resources

### Hosts
| Hostname | IP | Role | Zone | Inventory Group |
|----------|-----|------|------|-----------------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| postgresql | 5432 | tcp | dbservers |
| nginx | 443 | tcp | webservers_patched, webservers_legacy |
| openssh | 22 | tcp | webservers_patched, webservers_legacy |

### Filesystem Paths
| Path | Owner | Group | Mode | Service |
|------|-------|-------|------|---------|
| /var/lib/postgresql/data | postgres | postgres | 0700 | postgresql |

### Networks
| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | web_subnet |
| 0.0.0.0/0 | any | internet |

## Extracted ABAC Rules

### Rule Summary
| ID | Action | Effect | Subject | Resource |
|----|--------|--------|---------|----------|
| rule-001 | filesystem:read | permit | user=postgres | /var/lib/postgresql/data |
| rule-002 | filesystem:write | permit | user=postgres | /var/lib/postgresql/data |
| rule-003 | filesystem:execute | permit | user=postgres | /var/lib/postgresql/data |
| rule-004 | db:login | permit | source_network=10.0.1.0/24 | postgresql:5432 |
| rule-005 | ssh:login | permit | groups contains sudo | openssh:22 (legacy) |
| rule-006 | network:connect | permit | source_network=0.0.0.0/0 | nginx:443 (legacy) |
| rule-007 | network:connect | permit | source_network=0.0.0.0/0 | nginx:443 (patched) |
| rule-008 | ssh:login | permit | groups contains sudo | openssh:22 (patched) |
| rule-009 | * | deny | all | all (default) |

### Key Access Patterns
1. **Database Access**: PostgreSQL only accepts connections from the web subnet (10.0.1.0/24)
2. **SSH Access**: Restricted to members of the `sudo` group only
3. **HTTPS Access**: Open to internet (0.0.0.0/0) on port 443
4. **Filesystem**: PostgreSQL data directory restricted to postgres user (mode 0700)

## Vulnerability Assessment

### Summary
- **Total Vulnerabilities Found**: 20
- **Critical Severity**: 13
- **High Severity**: 5
- **Known Exploited (KEV)**: 8

### Critical Vulnerabilities by Product

#### OpenSSH
| CVE | Severity | CVSS | KEV | Description |
|-----|----------|------|-----|-------------|
| CVE-2000-0999 | critical | 10 | False | OpenBSD ssh and possibly other BSD-based operating syst... |
| CVE-2000-0525 | critical | 10 | False | OpenSSH with UseLogin enabled contains a privilege drop... |
| CVE-2003-0693 | critical | 10 | False | OpenSSH before 3.7 contains a buffer management error i... |
| CVE-2003-0786 | critical | 10 | False | OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalatio... |
| CVE-2001-0144 | critical | 10 | False | CORE SDI SSH1 CRC-32 compensation attack detector conta... |
| CVE-2023-38408 | critical | 9.8 | True | OpenSSH before 9.3p2 contains a remote code execution c... |
| CVE-2024-6387 | high | 8.1 | True | OpenSSH's server (sshd) contains a race condition cause... |
| CVE-2007-4752 | high | 7.5 | True | OpenSSH before 4.7 contains a privilege escalation caus... |
| CVE-2019-6109 | medium | 6.8 | True | OpenSSH 7.9 contains a client-side output manipulation ... |
| CVE-2019-6110 | medium | 6.8 | True | OpenSSH 7.9 contains a vulnerability caused by acceptin... |

#### PostgreSQL
| CVE | Severity | CVSS | KEV | Description |
|-----|----------|------|-----|-------------|
| CVE-2002-1399 | critical | 10 | False | PostgreSQL 7.2.1 and earlier, and possibly later versio... |
| CVE-2013-1902 | critical | 10 | False | PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17... |
| CVE-2007-3279 | critical | 10 | False | PostgreSQL 8.1 and later versions with plpgsql language... |
| CVE-2013-1903 | critical | 10 | False | PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.... |
| CVE-2019-9193 | high | 7.2 | True | PostgreSQL 9.3 through 11.2 contains a command executio... |

#### Nginx
| CVE | Severity | CVSS | KEV | Description |
|-----|----------|------|-----|-------------|
| CVE-2016-0746 | critical | 9.8 | False | nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 cont... |
| CVE-2017-20005 | critical | 9.8 | False | NGINX before 1.13.6 contains a buffer overflow caused b... |
| CVE-2009-3555 | critical | 9.8 | True | Multiple products including IIS 7.0, Apache 2.2.14, Ope... |
| CVE-2021-23017 | high | 7.7 | False | nginx resolver contains a 1-byte memory overwrite cause... |
| CVE-2023-44487 | high | 7.5 | True | The HTTP/2 protocol contains a denial of service caused... |

## Ambiguities & Notes

1. **Version Matching**: Vulnerability version ranges were not precisely matched against pinned versions due to lack of detailed version range data in CVE records.
2. **Legacy Server Risk**: `web-old01` runs nginx 1.20.0 which may have unpatched vulnerabilities compared to the patched version 1.24.0.
3. **Open SSH Access**: Firewall allows HTTPS from 0.0.0.0/0 (entire internet), which is appropriate for web servers but should be monitored.
4. **Database Isolation**: PostgreSQL is properly isolated to the web subnet (10.0.1.0/24).

## Recommendations

1. **Patch Legacy Server**: Upgrade `web-old01` from nginx 1.20.0 to 1.24.0 to eliminate version disparity.
2. **Review KEV Vulnerabilities**: Prioritize remediation of Known Exploited Vulnerabilities (KEV) entries.
3. **SSH Hardening**: Consider additional SSH hardening (key-based auth, disable root login).
4. **Database Credentials**: Ensure database credentials are managed securely (not in Ansible variables).

## Files Analyzed

### Phase 1 (Catalog)
- inventory.ini
- group_vars/all.yml
- group_vars/dbservers.yml
- group_vars/webservers_legacy.yml
- group_vars/webservers_patched.yml

### Phase 2 (Rule Extraction)
- roles/db/tasks/main.yml
- roles/web_legacy/tasks/main.yml
- roles/web_patched/tasks/main.yml
