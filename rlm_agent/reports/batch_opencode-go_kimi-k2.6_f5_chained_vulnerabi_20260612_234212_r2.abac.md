# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 23:49:32_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 18 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "users": {
    "type": "subject",
    "domain": [
      "admin",
      "developer",
      "dba"
    ],
    "source": "group_vars/all.yml"
  },
  "groups": {
    "type": "subject",
    "domain": [
      "dba",
      "developers",
      "sudo"
    ],
    "source": "group_vars/all.yml"
  },
  "clearance": {
    "type": "subject",
    "domain": [
      "confidential",
      "secret"
    ],
    "source": "group_vars/all.yml"
  },
  "department": {
    "type": "subject",
    "domain": [
      "data",
      "engineering",
      "operations"
    ],
    "source": "group_vars/all.yml"
  },
  "source_network": {
    "type": "subject",
    "domain": [
      "10.0.1.0/24",
      "0.0.0.0/0",
      "10.0.2.0/24",
      "10.0.0.0/24"
    ],
    "source": "roles/*/tasks/main.yml"
  },
  "hostname": {
    "type": "resource",
    "domain": [
      "bastion01.lab.local",
      "web01.lab.local",
      "app01.lab.local",
      "db01.lab.local"
    ],
    "source": "inventory.ini"
  },
  "role": {
    "type": "resource",
    "domain": [
      "application",
      "bastion",
      "frontend",
      "primary"
    ],
    "source": "inventory.ini"
  },
  "zone": {
    "type": "resource",
    "domain": [
      "app",
      "data",
      "dmz",
      "mgmt"
    ],
    "source": "inventory.ini"
  },
  "inventory_group": {
    "type": "resource",
    "domain": [
      "bastion",
      "webservers",
      "appservers",
      "dbservers",
      "prod"
    ],
    "source": "inventory.ini"
  },
  "service": {
    "type": "resource",
    "domain": [
      "application",
      "postgresql",
      "http",
      "ssh"
    ],
    "source": "group_vars/all.yml,group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/webservers.yml,roles/bastion/tasks/main.yml"
  },
  "port": {
    "type": "resource",
    "domain": [
      22,
      80,
      5432,
      8080
    ],
    "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/webservers.yml,roles/bastion/tasks/main.yml"
  },
  "path": {
    "type": "resource",
    "domain": [
      "/var/lib/postgresql/data"
    ],
    "source": "group_vars/dbservers.yml"
  },
  "owner": {
    "type": "resource",
    "domain": [
      "postgres"
    ],
    "source": "group_vars/dbservers.yml"
  },
  "group": {
    "type": "resource",
    "domain": [
      "postgres"
    ],
    "source": "group_vars/dbservers.yml"
  },
  "mode": {
    "type": "resource",
    "domain": [
      "0700"
    ],
    "source": "group_vars/dbservers.yml"
  },
  "database_privilege": {
    "type": "resource",
    "domain": [
      "SUPERUSER"
    ],
    "source": "roles/db/tasks/main.yml"
  },
  "org": {
    "type": "environment",
    "domain": [
      "chaincorp"
    ],
    "source": "group_vars/all.yml"
  },
  "environment": {
    "type": "environment",
    "domain": [
      "production"
    ],
    "source": "inventory.ini"
  },
  "compliance_tier": {
    "type": "environment",
    "domain": [
      "pci"
    ],
    "source": "group_vars/all.yml"
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
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "31-35"
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
      "inventory_group": {
        "equals": "bastion"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "8-13"
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
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "29-33"
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
      "inventory_group": {
        "equals": "webservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "21-25"
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
      "inventory_group": {
        "equals": "bastion"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "22-29"
    },
    "obligations": [
      {
        "type": "nopassword",
        "value": false
      }
    ]
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "database_privilege": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "16-22"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "23-28"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "application"
      },
      "port": {
        "equals": 8080
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": "23-30"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": "14-21"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "13-20"
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
    "action": "*",
    "effect": "deny",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "policy",
      "task": "default-deny",
      "lines": "0-0"
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
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
      "service": {
        "equals": "application"
      },
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
        "equals": "http"
      },
      "port": {
        "equals": 80
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": true,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "cvss_score": 9.8,
    "recommendation": "Upgrade openssh from pinned version to latest stable release. CVE CVE-2023-38408 affects this product.",
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding "
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": true,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "cvss_score": 8.1,
    "recommendation": "Upgrade openssh from pinned version to latest stable release. CVE CVE-2024-6387 affects this product.",
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "cvss_score": 7.5,
    "recommendation": "Review if openssh is affected; CVE CVE-2007-4752 likely does not apply to the pinned version.",
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipula"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "cvss_score": 6.8,
    "recommendation": "Review if openssh is affected; CVE CVE-2019-6110 likely does not apply to the pinned version.",
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "cvss_score": 6.8,
    "recommendation": "Review if openssh is affected; CVE CVE-2019-6109 likely does not apply to the pinned version.",
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani"
  },
  {
    "cve_id": "CVE-2003-0789",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "cvss_score": 10,
    "recommendation": "Review if apache is affected; CVE CVE-2003-0789 likely does not apply to the pinned version.",
    "description": "Apache before 2.0.48 with threaded MPM contains a CGI redirect path handling issue caused by improper handling in mod_cgid, letting Apache send CGI output to the wrong client, exploit requires specifi"
  },
  {
    "cve_id": "CVE-1999-1237",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "cvss_score": 10,
    "recommendation": "Review if apache is affected; CVE CVE-1999-1237 likely does not apply to the pinned version.",
    "description": "Multiple buffer overflows in smbvalid/smbval SMB authentication library used in Apache::AuthenSmb allow remote attackers to execute arbitrary commands via long username, long password, and other metho"
  },
  {
    "cve_id": "CVE-1999-1293",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "cvss_score": 10,
    "recommendation": "Review if apache is affected; CVE CVE-1999-1293 likely does not apply to the pinned version.",
    "description": "Apache 1.2.5 and earlier contains a denial of service caused by malformed FTP commands in mod_proxy, letting remote attackers cause Apache to dump core, exploit requires sending malformed FTP commands"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": true,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "cvss_score": 10,
    "recommendation": "Upgrade log4j from pinned version to latest stable release. CVE CVE-2021-44228 affects this product.",
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to e"
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": true,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "cvss_score": 9,
    "recommendation": "Upgrade log4j from pinned version to latest stable release. CVE CVE-2021-45046 affects this product.",
    "description": "Apache Log4j2 contains a remote code execution caused by vulnerable thread context lookup pattern in certain non-default configurations, letting remote attackers execute arbitrary code, exploit requir"
  },
  {
    "cve_id": "CVE-2021-4104",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": false,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "cvss_score": 7.5,
    "recommendation": "Review if log4j is affected; CVE CVE-2021-4104 likely does not apply to the pinned version.",
    "description": "Log4j 1.2 with JMSAppender configured contains a deserialization of untrusted data caused by write access to the configuration, letting attackers perform JNDI requests that may lead to remote code exe"
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": true,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "cvss_score": 7.5,
    "recommendation": "Upgrade log4j from pinned version to latest stable release. CVE CVE-2023-26464 affects this product.",
    "description": "Log4j 1.x on JRE less than 1.7 contains a denial of service caused by deserialization of specially-crafted nested hashmaps or hashtables, letting attackers exhaust memory, exploit requires attacker to"
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": true,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "cvss_score": 6.6,
    "recommendation": "Upgrade log4j from pinned version to latest stable release. CVE CVE-2021-44832 affects this product.",
    "description": "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding 2.3.2 and 2.12.4) contain a remote code execution caused by unsafe JNDI LDAP data source URI usage in JDBC Appender, letting attackers with c"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "cvss_score": 10,
    "recommendation": "Review if postgresql is affected; CVE CVE-2002-1399 likely does not apply to the pinned version.",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "cvss_score": 10,
    "recommendation": "Review if postgresql is affected; CVE CVE-2007-3279 likely does not apply to the pinned version.",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "cvss_score": 10,
    "recommendation": "Review if postgresql is affected; CVE CVE-2024-1597 likely does not apply to the pinned version.",
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": true,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "cvss_score": 10,
    "recommendation": "Upgrade postgresql from pinned version to latest stable release. CVE CVE-2013-1903 affects this product.",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": true,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "cvss_score": 10,
    "recommendation": "Upgrade postgresql from pinned version to latest stable release. CVE CVE-2013-1902 affects this product.",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit "
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": true,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "cvss_score": 7.2,
    "recommendation": "Upgrade postgresql from pinned version to latest stable release. CVE CVE-2019-9193 affects this product.",
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": false,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "cvss_score": 7.1,
    "recommendation": "Review if postgresql is affected; CVE CVE-2022-31197 likely does not apply to the pinned version.",
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a"
  }
]
```

## Report

# ABAC Policy Mining Report — ChainCorp Ansible Configuration

## 1. Scope & Methodology
Mined an Attribute-Based Access Control (ABAC) policy from the ChainCorp Ansible repository (`all` slice). The catalog was built from `inventory.ini` and `group_vars/*.yml`. Rules were extracted from the four role task files (`roles/{app,bastion,db,web}/tasks/main.yml`). Vulnerability assessment was performed against the four pinned software versions declared in `group_vars/all.yml`.

## 2. Attribute Catalog
- **Subjects**: 3 users (`admin`, `developer`, `dba`), 3 groups (`dba`, `developers`, `sudo`), 2 clearance levels (`confidential`, `secret`), 3 departments (`data`, `engineering`, `operations`).
- **Resources**: 4 hosts, 4 services (`application`, `postgresql`, `http`, `ssh`), 4 networks, 1 filesystem path (`/var/lib/postgresql/data`).
- **Environment**: `org=chaincorp`, `environment=production`, `compliance_tier=pci`.

## 3. Rule Summary (11 rules)
| ID | Action | Effect | Scope |
|---|---|---|---|
| rule-001 | ssh:login | permit | `appservers` — groups `sudo` or `developers` |
| rule-002 | ssh:login | permit | `bastion` — groups `sudo` or `dba` |
| rule-003 | ssh:login | permit | `dbservers` — groups `sudo` or `dba` |
| rule-004 | ssh:login | permit | `webservers` — group `sudo` |
| rule-005 | sudo:execute | permit | `bastion` — group `sudo` + clearance `secret` (nopassword=false) |
| rule-006 | db:login | permit | `dbservers` — group `dba` + `SUPERUSER` |
| rule-007 | network:connect | permit | `dbservers:5432` from `10.0.2.0/24` |
| rule-008 | network:connect | permit | `appservers:8080` from `10.0.1.0/24` |
| rule-009 | network:connect | permit | `bastion:22` from `0.0.0.0/0` |
| rule-010 | network:connect | permit | `webservers:80` from `10.0.0.0/24` |
| rule-011 | * | deny | Default deny |

## 4. Vulnerability Assessment
Pinned vulnerable packages:
- **OpenSSH** 9.1p1 (bastion) and 9.9p1 (others): CVE-2024-6387 (regreSSHion) and CVE-2023-38408 affect the bastion version (9.1p1). The other hosts run 9.9p1 which is not affected by these CVEs.
- **Apache** 2.4.49-1: The vulnx search returned only historical CVEs for `http_server` that do not impact Apache 2.4.49. Notably, the well-known path-traversal CVEs (CVE-2021-41773/42013) for 2.4.49 were absent from the search results.
- **Log4j** 2.14.1: Multiple confirmed CVEs (CVE-2021-44228, CVE-2021-45046, CVE-2021-44832, CVE-2023-26464) affect this pinned version.
- **PostgreSQL** 9.2.3-1: CVE-2019-9193, CVE-2013-1902, CVE-2013-1903 affect this pinned version.

## 5. Ambiguities
- **Credentials**: No Ansible Vault or explicit credential rotation logic was found. PostgreSQL authentication uses `scram-sha-256`, but passwords are not managed in the configuration.
- **Apache Versioning**: The variable is named `httpd_version` but the package installed is `apache2`. The pinned version `2.4.49-1` is a known vulnerable release.
- **Session Logging**: The bastion role restricts SSH and sudo but does not configure session recording or centralized logging.
- **Missing Security Templates**: No separate `iptables`, `selinux`, `nagios`, or `haproxy` files exist; network controls are embedded in role tasks only.
- **Filesystem ACLs**: Only the PostgreSQL data directory has explicit mode/owner; other paths lack ACL declarations.
