# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 21:43:26_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 13 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f3_privsep_service_accounts`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "domain": [
        "admin",
        "developer",
        "postgres",
        "redis",
        "www-data"
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "domain": [
        "developers",
        "postgres",
        "redis",
        "sudo",
        "www-data"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "engineering",
        "operations"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "domain": [
        33,
        1001,
        1002
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "domain": [
        "0.0.0.0/0",
        "10.0.1.0/24"
      ],
      "source": "group_vars/all.yml"
    },
    "source_zone": {
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "source_ip": {
      "domain": [
        "10.0.1.10",
        "10.0.2.10",
        "10.0.2.20"
      ],
      "source": "inventory.ini"
    }
  },
  "resources": {
    "hostname": {
      "domain": [
        "web01.lab.local",
        "db01.lab.local",
        "cache01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "domain": [
        "cache",
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "domain": [
        "cacheservers",
        "dbservers",
        "prod",
        "webservers"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "domain": [
        "nginx",
        "postgresql",
        "redis",
        "ssh",
        "sudo"
      ],
      "source": "group_vars/all.yml"
    },
    "port": {
      "domain": [
        443,
        5432,
        6379
      ],
      "source": "group_vars/all.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "group_vars/all.yml"
    },
    "path": {
      "domain": [
        "/var/lib/postgresql/data",
        "/var/www/html"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "domain": [
        "postgres",
        "www-data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "domain": [
        "postgres",
        "www-data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "domain": [
        "0700",
        "0750"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "privsep-corp"
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
        "soc2"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "43-48"
    },
    "id": "rule-001"
  },
  {
    "subject_condition": {
      "user": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sudo"
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
    "action": "sudo:execute",
    "effect": "deny",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure www-data has NO sudo access",
      "lines": "49-52"
    },
    "id": "rule-002"
  },
  {
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
      },
      "database": {
        "equals": "all"
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "21-25"
    },
    "id": "rule-003"
  },
  {
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "redis"
      },
      "port": {
        "equals": 6379
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
    "effect": "permit",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": "20-26"
    },
    "id": "rule-004"
  },
  {
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
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "35-42"
    },
    "id": "rule-005"
  },
  {
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "8-15"
    },
    "id": "rule-006"
  },
  {
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "8-15"
    },
    "id": "rule-007"
  },
  {
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "8-15"
    },
    "id": "rule-008"
  },
  {
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/www/html"
      },
      "owner": {
        "equals": "www-data"
      },
      "group": {
        "equals": "www-data"
      },
      "mode": {
        "equals": "0750"
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
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "27-34"
    },
    "id": "rule-009"
  },
  {
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/www/html"
      },
      "owner": {
        "equals": "www-data"
      },
      "group": {
        "equals": "www-data"
      },
      "mode": {
        "equals": "0750"
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "27-34"
    },
    "id": "rule-010"
  },
  {
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/www/html"
      },
      "owner": {
        "equals": "www-data"
      },
      "group": {
        "equals": "www-data"
      },
      "mode": {
        "equals": "0750"
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "27-34"
    },
    "id": "rule-011"
  },
  {
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
      "file": "policy",
      "task": "default-deny",
      "lines": "0-0"
    },
    "id": "rule-012"
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
      "environment": {
        "equals": "production"
      },
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
    "id": "rule-014",
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
    "id": "rule-015",
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
    "id": "rule-016",
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
      "database": {
        "equals": "all"
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
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "redis"
      },
      "port": {
        "equals": 6379
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
    "id": "rule-018",
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses related to CNAME processing, exploit requires sending malicious DNS responses."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit requires crafted input."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denial of service or potentially execute arbitrary code, exploit requires processing of specially crafted files with large modification dates."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": true,
    "severity": "high",
    "cvss_score": 7.7,
    "kev": false,
    "recommendation": "Review vendor advisory and upgrade to the latest patched version.",
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP packets from DNS server."
  },
  {
    "cve_id": "CVE-2016-0742",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.5,
    "kev": false,
    "recommendation": "Review vendor advisory and upgrade to the latest patched version.",
    "description": "nginx before 1.8.1 and 1.9.x before 1.9.10 contain a denial of service caused by invalid pointer dereference in resolver when processing crafted UDP DNS responses, letting remote attackers crash worker processes, exploit requires sending malicious DNS responses."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requires sending crafted CRC-32 data."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires remote network access."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": true,
    "recommendation": "URGENT: Actively exploited in the wild. Patch or mitigate immediately per CISA KEV guidance.",
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeholder construction."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers potentially access sensitive credentials, exploit requires access to installer scripts."
  },
  {
    "cve_id": "CVE-2015-4335",
    "product": "redis",
    "pinned_version": "7.0.11",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "Redis < 2.8.21 and 3.x < 3.0.2 contain a remote code execution caused by unsafe eval command processing, letting attackers execute arbitrary Lua bytecode remotely, exploit requires network access to Redis server."
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "pinned_version": "7.0.11",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": true,
    "recommendation": "URGENT: Actively exploited in the wild. Patch or mitigate immediately per CISA KEV guidance.",
    "description": "Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment, letting attackers load arbitrary libraries, exploit requires attacker to execute malicious Lua code."
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "pinned_version": "7.0.11",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.9,
    "kev": true,
    "recommendation": "URGENT: Actively exploited in the wild. Patch or mitigate immediately per CISA KEV guidance.",
    "description": "Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts, letting authenticated users potentially achieve remote code execution, exploit requires authentication."
  },
  {
    "cve_id": "CVE-2017-15047",
    "product": "redis",
    "pinned_version": "7.0.11",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "Redis 4.0.2 contains a denial of service caused by out-of-bounds array index in clusterLoadConfig function in cluster.c, letting attackers cause application crash, exploit requires limited access to the machine."
  },
  {
    "cve_id": "CVE-2016-8339",
    "product": "redis",
    "pinned_version": "7.0.11",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "recommendation": "Critical severity. Prioritize patching and validate mitigating controls.",
    "description": "Redis 3.2.x prior to 3.2.4 contains a buffer overflow caused by out of bounds write in handling of client-output-buffer-limit during CONFIG SET, letting attackers execute arbitrary code, exploit requires sending crafted CONFIG SET command."
  }
]
```

## Report

# ABAC Policy Mining Report

## Scope
Mined from Ansible configuration at `RLM_ANSIBLE_DIR` for slice: **all**.

## Phase 1 — Attribute Catalog
- **Subjects**: 5 users (admin, developer, postgres, redis, www-data), 5 groups (developers, postgres, redis, sudo, www-data), clearance levels (confidential, secret), departments (engineering, operations).
- **Resources**: 3 hosts (web01.lab.local, db01.lab.local, cache01.lab.local), services (nginx, postgresql, redis, ssh, sudo), ports (443, 5432, 6379), paths (/var/lib/postgresql/data, /var/www/html).
- **Environment**: org=privsep-corp, environment=production, compliance_tier=soc2.

## Phase 1.5 — Vulnerability Assessment
Evaluated 20 CVEs across 4 pinned packages:
- **nginx 1.20.0**: 5 CVEs (1 confirmed affects pinned version: CVE-2021-23017).
- **openssh 9.6p1**: 5 CVEs (none confirmed to affect pinned version; mostly legacy entries).
- **postgresql 16.2**: 5 CVEs (CVE-2024-1597 is a JDBC driver issue, not the server itself; marked as not affecting pinned version).
- **redis 7.0.11**: 5 CVEs (2 KEV entries: CVE-2022-0543, CVE-2025-49844).

## Phase 2 — Rule Extraction
Extracted 12 ABAC rules from 3 role task files:
1. `ssh:login` permit for members of `sudo` group.
2. `sudo:execute` deny for user `www-data`.
3. `network:connect` permit to PostgreSQL (5432) from `10.0.1.0/24`.
4. `network:connect` permit to Redis (6379) from `10.0.1.0/24`.
5. `network:connect` permit to nginx HTTPS (443) from `0.0.0.0/0`.
6-8. `filesystem:read/write/execute` permit for `postgres` group on `/var/lib/postgresql/data`.
9-11. `filesystem:read/write/execute` permit for `www-data` group on `/var/www/html`.
12. Default-deny catch-all.

## Ambiguities & Gaps
- No explicit sudoers rules found for `admin` or `developer`; only a negative rule for `www-data`.
- No credential/secrets management (Ansible Vault, password hashes, or key material) observed in the configuration.
- No session logging, audit scripts, or obligations detected.
- Database access rules are network-layer only; no PostgreSQL user-level privilege grants (e.g., SUPERUSER vs SELECT) were defined in the playbooks.
- SELinux, Nagios, HAProxy, MySQL, and iptables configuration files were absent from the repository.

## Recommendations
- Patch nginx to address CVE-2021-23017 (DNS resolver 1-byte overwrite).
- Review Redis KEV CVEs (CVE-2022-0543, CVE-2025-49844) and upgrade urgently.
- Add explicit sudoers definitions for operational users rather than relying on group assumptions.
- Introduce Ansible Vault or an external secrets manager to handle credentials declaratively.
- Expand pg_hba rules to include explicit deny entries for unauthorized networks.
