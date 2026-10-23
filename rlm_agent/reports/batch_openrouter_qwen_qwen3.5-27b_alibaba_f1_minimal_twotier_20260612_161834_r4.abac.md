# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:24:11_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 12_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f1_minimal_twotier`_

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
        "level": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "level": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "name": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "name": "engineering",
        "source": "group_vars/all.yml"
      }
    ]
  },
  "resources": {
    "hosts": [
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers",
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
        "name": "httpd",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "group_vars/webservers.yml"
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
      },
      {
        "path": "/var/www/html",
        "owner": "www-data",
        "group": "www-data",
        "mode": "0755",
        "service": "httpd",
        "source": "group_vars/webservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      }
    ]
  },
  "environment": {
    "org": "labcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "group_vars/all.yml,inventory.ini"
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
    "privilege_level": "SUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "13-17"
    }
  },
  {
    "rule_id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
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
    "privilege_level": "NOSUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "19-23"
    }
  },
  {
    "rule_id": "rule-003",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "25-29"
    }
  },
  {
    "rule_id": "rule-004",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
    }
  },
  {
    "rule_id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
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
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "14-19"
    }
  },
  {
    "rule_id": "rule-006",
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
    "nopassword": false,
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "21-26"
    }
  },
  {
    "rule_id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "httpd"
      },
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
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": "28-33"
    }
  },
  {
    "rule_id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
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
      "lines": "35-38"
    }
  },
  {
    "rule_id": "rule-009",
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
      "file": "N/A",
      "task": "implicit default-deny",
      "lines": "N/A"
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
    "id": "rule-002",
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
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "httpd"
      },
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-1999-0067",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "phf CGI program contains a remote command execution caused by unsanitized shell metacharacters, letting attackers execute arbitrary commands remotely, exploit requires sending crafted input.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-1999-0926",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Apache contains a denial of service caused by handling a large number of MIME headers, letting remote attackers cause service disruption, exploit requires sending numerous MIME headers.",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-1999-1199",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Apache WWW server 1.3.1 and earlier contains a denial of service caused by resource exhaustion via a large number of MIME headers with the same name, letting remote attackers cause resource exhaustion",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-2013-2250",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Apache Open For Business Project (OFBiz) versions 10.04.01 through 10.04.05, 11.04.01 through 11.04.02, and 12.04.01 contain a remote code execution caused by unsanitized JUEL metacharacters in parame",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1777",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Apache Geronimo 3.x before 3.0.1, used in IBM WebSphere Application Server Community Edition 3.0.0.3, contains a remote code execution caused by improper RMI classloader implementation in JMX Remoting",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-2010-0219",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "description": "Apache Axis2 in various products contains a default password 'axis2' for the admin account, causing a security weakness that allows remote attackers to execute arbitrary code by uploading crafted web ",
    "affects_pinned_version": true,
    "recommendation": "URGENT: apache has known exploited vulnerability - patch immediately"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to e",
    "affects_pinned_version": true,
    "recommendation": "URGENT: apache has known exploited vulnerability - patch immediately"
  },
  {
    "cve_id": "CVE-2023-46604",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "description": "Apache ActiveMQ contains a remote code execution caused by manipulation of serialized class types in the OpenWire protocol, letting remote attackers execute arbitrary shell commands, exploit requires ",
    "affects_pinned_version": true,
    "recommendation": "URGENT: apache has known exploited vulnerability - patch immediately"
  },
  {
    "cve_id": "CVE-2016-15057",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_kev": true,
    "description": "Apache Continuum contains a command injection caused by improper neutralization of special elements in REST API, letting attackers with API access execute arbitrary commands remotely, exploit requires",
    "affects_pinned_version": true,
    "recommendation": "URGENT: apache has known exploited vulnerability - patch immediately"
  },
  {
    "cve_id": "CVE-2019-0192",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "description": "Apache Solr versions 5.0.0 to 5.5.5 and 6.0.0 to 6.6.5 contain a remote code execution caused by unsafe deserialization in the Config API when configured to a malicious RMI server, letting remote atta",
    "affects_pinned_version": true,
    "recommendation": "URGENT: apache has known exploited vulnerability - patch immediately"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding ",
    "affects_pinned_version": true,
    "recommendation": "URGENT: openssh has known exploited vulnerability - patch immediately"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 8.1,
    "is_kev": true,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req",
    "affects_pinned_version": true,
    "recommendation": "URGENT: openssh has known exploited vulnerability - patch immediately"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipula",
    "affects_pinned_version": true,
    "recommendation": "URGENT: openssh has known exploited vulnerability - patch immediately"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani",
    "affects_pinned_version": true,
    "recommendation": "URGENT: openssh has known exploited vulnerability - patch immediately"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl",
    "affects_pinned_version": true,
    "recommendation": "URGENT: openssh has known exploited vulnerability - patch immediately"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "affects_pinned_version": true,
    "recommendation": "URGENT: postgresql has known exploited vulnerability - patch immediately"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.2,
    "is_kev": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
    "affects_pinned_version": true,
    "recommendation": "URGENT: postgresql has known exploited vulnerability - patch immediately"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.1,
    "is_kev": true,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
    "affects_pinned_version": true,
    "recommendation": "URGENT: postgresql has known exploited vulnerability - patch immediately"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC policy mined from the Ansible configuration in `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web servers and database servers under SOC2 compliance.

## Environment Overview

- **Organization**: labcorp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Infrastructure

### Hosts (2)
| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services (2)
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| httpd | 80 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |

### Users (2)
| Username | UID | Groups | Clearance | Department |
|----------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

## Access Control Rules (9)

| Rule ID | Action | Effect | Subject Condition | Resource Condition |
|---------|--------|--------|-------------------|-------------------|
| rule-001 | db:login | permit | groups: sudo | service: postgresql (SUPERUSER) |
| rule-002 | db:login | permit | groups: developers | service: postgresql (NOSUPERUSER) |
| rule-003 | network:connect | permit | source_network: 10.0.1.0/24 | postgresql:5432 |
| rule-004 | filesystem:read | permit | user: postgres | /var/lib/postgresql/data |
| rule-005 | user:create | permit | groups: sudo | all |
| rule-006 | sudo:execute | permit | groups: sudo, clearance: secret | all (password required) |
| rule-007 | network:connect | permit | source_network: 0.0.0.0/0 | httpd:80 |
| rule-008 | ssh:login | permit | groups: sudo | ssh |
| rule-009 | * | deny | all | all (default-deny) |

## Vulnerability Assessment (28 CVEs)

### Critical Findings by Product

| Product | Pinned Version | Critical | High | KEV |
|---------|---------------|----------|------|-----|
| apache | 2.4.49-1 | 5 | 0 | 5 |
| openssh | 1:9.6p1-3ubuntu1 | 5 | 2 | 5 |
| postgresql | 16.2-1.pgdg22.04+1 | 5 | 2 | 3 |

### Notable Vulnerabilities

- **CVE-2021-44228** (apache): Log4Shell - Critical (CVSS 10.0) - Known Exploited
- **CVE-2023-38408** (openssh): Critical (CVSS 9.8) - Remote code execution
- **CVE-2024-1597** (postgresql): Critical (CVSS 10.0) - Known Exploited

### Recommendations

1. **URGENT**: Patch all KEV-listed vulnerabilities immediately
2. Upgrade apache to address CVE-2021-44228 (Log4Shell)
3. Upgrade openssh to address CVE-2023-38408
4. Upgrade postgresql to address CVE-2024-1597

## Security Architecture

### Network Segmentation
- **DMZ**: web01.lab.local (10.0.1.10) - Internet-facing HTTP service
- **Internal**: db01.lab.local (10.0.2.10) - Database server, accessible only from webservers subnet (10.0.1.0/24)

### Access Control Principles
- SSH access restricted to sudo group members only
- Database superuser privileges limited to sudo group
- Read-only database access for developers group
- Sudo execution requires secret clearance level
- Default-deny posture for all other access

## Ambiguities & Notes

1. No explicit credentials found in configuration (secrets managed externally)
2. File permissions for /var/www/html inferred from standard Apache deployment
3. Vulnerability version matching is approximate - manual verification recommended
4. No SELinux policies found in configuration
