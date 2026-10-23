# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 19:40:40_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 9 | Rules: 10_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f1_minimal_twotier`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "type": "string",
      "domain": [
        "admin",
        "appuser"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "number",
      "domain": [
        1001,
        1002
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers"
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
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "source_ip": {
      "type": "string",
      "source": "inventory.ini"
    },
    "source_network": {
      "type": "string",
      "source": "group_vars/dbservers.yml, group_vars/webservers.yml, roles/db/tasks/main.yml, roles/web/tasks/main.yml"
    },
    "source_zone": {
      "type": "string",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "applies_to": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "synthetic"
    }
  },
  "resources": {
    "hostname": {
      "type": "string",
      "domain": [
        "web01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "source": "inventory.ini"
    },
    "role": {
      "type": "string",
      "domain": [
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "string",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "inventory_group": {
      "type": "string",
      "domain": [
        "webservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "string",
      "domain": [
        "webservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "string",
      "domain": [
        "postgresql",
        "apache2",
        "openssh-server"
      ],
      "source": "roles/db/tasks/main.yml, roles/web/tasks/main.yml"
    },
    "port": {
      "type": "string",
      "domain": [
        "5432",
        "80"
      ],
      "source": "group_vars/dbservers.yml, group_vars/webservers.yml"
    },
    "protocol": {
      "type": "string",
      "domain": [
        "tcp"
      ],
      "source": "roles/db/tasks/main.yml, roles/web/tasks/main.yml"
    },
    "path": {
      "type": "string",
      "source": "roles/db/tasks/main.yml, roles/web/tasks/main.yml"
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
    "database_role": {
      "type": "string",
      "domain": [
        "superuser",
        "nosuperuser"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "cidr": {
      "type": "string",
      "source": "group_vars/dbservers.yml, group_vars/webservers.yml"
    },
    "applies_to": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "synthetic"
    }
  },
  "environment": {
    "org": {
      "type": "string",
      "domain": [
        "labcorp"
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
        "soc2"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "number",
      "domain": [
        90
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
        "equals": "postgresql"
      },
      "database_role": {
        "equals": "superuser"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "16-22"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database_role": {
        "equals": "nosuperuser"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "23-29"
    }
  },
  {
    "id": "rule-003",
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
        "equals": "5432"
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "13-21"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "nopassword": false,
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "22-30"
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
      "port": {
        "equals": "80"
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": "31-38"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "openssh-server"
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "39-43"
    }
  },
  {
    "id": "rule-008",
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
      "file": "synthetic",
      "task": "default-deny",
      "lines": "n/a"
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
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": "5432"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
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
    "id": "rule-010",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": "80"
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
        "equals": "soc2"
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
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requires sending crafted CRC-32 data."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires remote network access."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": true,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding agent, exploit requires agent forwarding to attacker-controlled system."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "high",
    "cvss_score": 8.1,
    "kev": true,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit requires no authentication."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "high",
    "cvss_score": 7.5,
    "kev": true,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipulate cookie creation."
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "medium",
    "cvss_score": 6.8,
    "kev": true,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to manipulate client output, exploit requires man-in-the-middle position."
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "medium",
    "cvss_score": 6.8,
    "kev": true,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, exploit requires man-in-the-middle position."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "kev": true,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeholder construction."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers potentially access sensitive credentials, exploit requires access to installer scripts."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "high",
    "cvss_score": 7.2,
    "kev": true,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit requires superuser or group membership."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "high",
    "cvss_score": 7.1,
    "kev": true,
    "epss": "unknown",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to latest patched version immediately.",
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the application invokes this method and queries malicious schemas, exploit requires tricking the user into executing SQL on malicious schema."
  }
]
```

## Report

# ABAC Policy Mining Report — Ansible: labcorp production

## 1. Scope & Sources
- **Inventory / Group Vars**: `inventory.ini`, `group_vars/all.yml`, `group_vars/dbservers.yml`, `group_vars/webservers.yml`
- **Security-relevant Role Tasks**: `roles/db/tasks/main.yml`, `roles/web/tasks/main.yml`
- **Policy slice requested**: `all`

## 2. Attribute Catalog Summary
### Subjects
- **user** (string) domain=['admin', 'appuser']
- **uid** (number) domain=[1001, 1002]
- **groups** (set) domain=['sudo', 'developers']
- **clearance** (string) domain=['secret', 'confidential']
- **department** (string) domain=['operations', 'engineering']
- **source_ip** (string)
- **source_network** (string)
- **source_zone** (string) domain=['dmz', 'internal']
- **applies_to** (string) domain=['all']

### Resources
- **hostname** (string) domain=['web01.lab.local', 'db01.lab.local']
- **ip** (string)
- **role** (string) domain=['frontend', 'primary']
- **zone** (string) domain=['dmz', 'internal']
- **inventory_group** (string) domain=['webservers', 'dbservers', 'prod']
- **host_group** (string) domain=['webservers', 'dbservers']
- **service** (string) domain=['postgresql', 'apache2', 'openssh-server']
- **port** (string) domain=['5432', '80']
- **protocol** (string) domain=['tcp']
- **path** (string)
- **owner** (string) domain=['postgres']
- **group** (string) domain=['postgres']
- **mode** (string) domain=['0700']
- **database** (string) domain=['all']
- **database_role** (string) domain=['superuser', 'nosuperuser']
- **cidr** (string)
- **applies_to** (string) domain=['all']

### Environment
- **org** (string) domain=['labcorp']
- **environment** (string) domain=['production']
- **compliance_tier** (string) domain=['soc2']
- **default_log_retention_days** (number) domain=[90]

## 3. Extracted Rules
| ID | Effect | Action | Subject | Resource | Env | Source File |
|----|--------|--------|---------|----------|-----|-------------|
| rule-001 | permit | `db:login` | `{"groups": {"any_of": ["sudo"]}}` | `{"service": {"equals": "postgresql"}, "database_role": {"equals": "superuser"}}` | `{"environment": {"equals": "production"}, "compliance_tier": {"equals": "soc2"}}` | `roles/db/tasks/main.yml` |
| rule-002 | permit | `db:login` | `{"groups": {"any_of": ["developers"]}}` | `{"service": {"equals": "postgresql"}, "database_role": {"equals": "nosuperuser"}}` | `{"environment": {"equals": "production"}, "compliance_tier": {"equals": "soc2"}}` | `roles/db/tasks/main.yml` |
| rule-003 | permit | `network:connect` | `{"source_network": {"equals": "10.0.1.0/24"}}` | `{"service": {"equals": "postgresql"}, "port": {"equals": "5432"}, "protocol": {"equals": "tcp"}}` | `{"environment": {"equals": "production"}, "compliance_tier": {"equals": "soc2"}}` | `roles/db/tasks/main.yml` |
| rule-004 | permit | `user:create` | `{"groups": {"any_of": ["sudo"]}}` | `{"host_group": {"equals": "webservers"}}` | `{"environment": {"equals": "production"}, "compliance_tier": {"equals": "soc2"}}` | `roles/web/tasks/main.yml` |
| rule-005 | permit | `sudo:execute` | `{"groups": {"any_of": ["sudo"]}, "clearance": {"equals": "secret"}}` | `{"host_group": {"equals": "webservers"}}` | `{"environment": {"equals": "production"}, "compliance_tier": {"equals": "soc2"}}` | `roles/web/tasks/main.yml` |
| rule-006 | permit | `network:connect` | `{"source_network": {"equals": "0.0.0.0/0"}}` | `{"port": {"equals": "80"}, "protocol": {"equals": "tcp"}, "host_group": {"equals": "webservers"}}` | `{"environment": {"equals": "production"}, "compliance_tier": {"equals": "soc2"}}` | `roles/web/tasks/main.yml` |
| rule-007 | permit | `ssh:login` | `{"groups": {"any_of": ["sudo"]}}` | `{"service": {"equals": "openssh-server"}, "host_group": {"equals": "webservers"}}` | `{"environment": {"equals": "production"}, "compliance_tier": {"equals": "soc2"}}` | `roles/web/tasks/main.yml` |
| rule-008 | deny | `*` | `{"applies_to": {"equals": "all"}}` | `{"applies_to": {"equals": "all"}}` | `{"applies_to": {"equals": "all"}}` | `synthetic` |

## 4. Vulnerability Assessment
Pinned packages discovered in `group_vars/all.yml`:
- `httpd` = 2.4.49-1
- `openssh` = 1:9.6p1-3ubuntu1
- `postgresql` = 16.2-1.pgdg22.04+1

| CVE | Product | Severity | CVSS | KEV | Affects Pinned? | Recommendation |
|-----|---------|----------|------|-----|-----------------|----------------|
| CVE-2000-0999 | openssh | critical | 10 | No | Yes | Upgrade to latest patched version immediately. |
| CVE-2001-0144 | openssh | critical | 10 | No | Yes | Upgrade to latest patched version immediately. |
| CVE-2000-0525 | openssh | critical | 10 | No | Yes | Upgrade to latest patched version immediately. |
| CVE-2003-0693 | openssh | critical | 10 | No | Yes | Upgrade to latest patched version immediately. |
| CVE-2003-0786 | openssh | critical | 10 | No | Yes | Upgrade to latest patched version immediately. |
| CVE-2023-38408 | openssh | critical | 9.8 | Yes | Yes | Upgrade to latest patched version immediately. |
| CVE-2024-6387 | openssh | high | 8.1 | Yes | Yes | Upgrade to latest patched version immediately. |
| CVE-2007-4752 | openssh | high | 7.5 | Yes | Yes | Upgrade to latest patched version immediately. |
| CVE-2019-6109 | openssh | medium | 6.8 | Yes | Yes | Upgrade to latest patched version immediately. |
| CVE-2019-6110 | openssh | medium | 6.8 | Yes | Yes | Upgrade to latest patched version immediately. |
| CVE-2007-3279 | postgresql | critical | 10 | No | Yes | Upgrade to latest patched version immediately. |
| CVE-2002-1399 | postgresql | critical | 10 | No | Yes | Upgrade to latest patched version immediately. |
| CVE-2024-1597 | postgresql | critical | 10 | Yes | Yes | Upgrade to latest patched version immediately. |
| CVE-2013-1902 | postgresql | critical | 10 | No | Yes | Upgrade to latest patched version immediately. |
| CVE-2013-1903 | postgresql | critical | 10 | No | Yes | Upgrade to latest patched version immediately. |
| CVE-2019-9193 | postgresql | high | 7.2 | Yes | Yes | Upgrade to latest patched version immediately. |
| CVE-2022-31197 | postgresql | high | 7.1 | Yes | Yes | Upgrade to latest patched version immediately. |

## 5. Ambiguities & Gaps
1. **Filesystem ACL (postgres data dir)**: The DB role sets `/var/lib/postgresql/data` to `owner=postgres`, `group=postgres`, `mode=0700`. The system user `postgres` is not modeled in the Phase-1 subject catalog (users list), and no group-based mapping exists, so a filesystem ACL rule was not attribute-mined without inventing a subject.
2. **SSH firewall exposure**: The web role restricts SSH via `AllowGroups` but does **not** add a `firewalld` rule for port 22; only HTTP (tcp/80) is explicitly allowed. It is ambiguous whether SSH is reachable due to host-level or upstream firewall rules outside Ansible.
3. **pg_hba implicit deny**: The DB role appends an allow line to `pg_hba.conf` but does not emit an explicit reject/deny line. The implicit default-deny is represented by the global catch-all deny rule (`rule-008`).
4. **Credentials management**: No password hashes, Ansible Vault files, or key material were found in the mined files. Credential provisioning (e.g., `postgresql_user` passwords) is not configured here.
5. **Vulnerability version-matching**: `affects_pinned_version` is based on a heuristic keyword match against CVE descriptions/affected-products strings; precise CPE range evaluation was not available.

## 6. Recommendations
- Prioritize patching **OpenSSH** and **PostgreSQL** because critical/KEV CVEs were identified against the pinned versions.
- Add an explicit `firewalld` or `ufw` rule for SSH if remote admin access is required, or document the compensating network controls.
- Extend the subject catalog to include service accounts (e.g., `postgres`) if filesystem ACL rules are required.
- Consider using Ansible Vault or an external secret store for any future credential tasks.
- Review `pg_hba.conf` to add explicit `reject` rules for known-untrusted networks instead of relying solely on implicit deny.