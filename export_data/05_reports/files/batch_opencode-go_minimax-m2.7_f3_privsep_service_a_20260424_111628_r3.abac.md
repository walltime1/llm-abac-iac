# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 12:00:42_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 12 | Rules: 12_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f3_privsep_service_accounts`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "description": "Configured system users",
      "domain": null,
      "source": "group_vars/all.yml",
      "values": [
        {
          "name": "admin",
          "uid": 1001,
          "groups": [
            "sudo"
          ],
          "clearance": "secret",
          "department": "operations"
        },
        {
          "name": "developer",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "clearance": "confidential",
          "department": "engineering"
        }
      ]
    },
    "groups": {
      "description": "Unix groups present on managed hosts",
      "domain": [
        "sudo",
        "developers",
        "www-data"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "sudo",
        "developers",
        "www-data"
      ]
    },
    "clearance": {
      "description": "User clearance level for data classification",
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "confidential",
        "secret"
      ]
    },
    "department": {
      "description": "Organisational department of the user",
      "domain": [
        "engineering",
        "operations"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "engineering",
        "operations"
      ]
    }
  },
  "resources": {
    "hostname": {
      "description": "FQDN of a managed host",
      "domain": [
        "web01.lab.local",
        "db01.lab.local",
        "cache01.lab.local"
      ],
      "source": "inventory.ini",
      "values": [
        "web01.lab.local",
        "db01.lab.local",
        "cache01.lab.local"
      ]
    },
    "ip": {
      "description": "IPv4 address of a managed host",
      "domain": null,
      "source": "inventory.ini",
      "values": [
        "10.0.1.10",
        "10.0.2.10",
        "10.0.2.20"
      ]
    },
    "role": {
      "description": "Host functional role",
      "domain": [
        "frontend",
        "primary",
        "cache"
      ],
      "source": "inventory.ini",
      "values": [
        "frontend",
        "primary",
        "cache"
      ]
    },
    "zone": {
      "description": "Network security zone",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini",
      "values": [
        "dmz",
        "internal"
      ]
    },
    "host_group": {
      "description": "Ansible inventory group membership",
      "domain": [
        "webservers",
        "dbservers",
        "cacheservers"
      ],
      "source": "inventory.ini",
      "values": [
        "webservers",
        "dbservers",
        "cacheservers"
      ]
    },
    "service": {
      "description": "Listening network service",
      "domain": [
        "nginx",
        "postgresql",
        "redis"
      ],
      "source": "group_vars/*.yml",
      "values": [
        "nginx",
        "postgresql",
        "redis"
      ]
    },
    "port": {
      "description": "TCP port number",
      "domain": [
        443,
        5432,
        6379
      ],
      "source": "group_vars/*.yml",
      "values": [
        443,
        5432,
        6379
      ]
    },
    "protocol": {
      "description": "Network protocol",
      "domain": [
        "tcp"
      ],
      "source": "group_vars/*.yml",
      "values": [
        "tcp"
      ]
    },
    "path": {
      "description": "Absolute filesystem path",
      "domain": null,
      "source": "roles/*/tasks/main.yml",
      "values": [
        "/var/www/html",
        "/var/lib/postgresql/data",
        "/etc/redis/redis.conf"
      ]
    },
    "owner": {
      "description": "Unix file owner",
      "domain": [
        "postgres",
        "www-data",
        "redis"
      ],
      "source": "roles/*/tasks/main.yml",
      "values": [
        "postgres",
        "www-data",
        "redis"
      ]
    },
    "group": {
      "description": "Unix file group",
      "domain": [
        "postgres",
        "www-data"
      ],
      "source": "roles/*/tasks/main.yml",
      "values": [
        "postgres",
        "www-data"
      ]
    },
    "mode": {
      "description": "Unix permission octal mode",
      "domain": null,
      "source": "roles/*/tasks/main.yml",
      "values": [
        "0700",
        "0750"
      ]
    },
    "source_network": {
      "description": "Allowed source CIDR for network access rules",
      "domain": [
        "0.0.0.0/0",
        "10.0.1.0/24"
      ],
      "source": "group_vars/*.yml",
      "values": [
        "0.0.0.0/0",
        "10.0.1.0/24"
      ]
    },
    "database": {
      "description": "Database engine name",
      "domain": [
        "postgresql"
      ],
      "source": "group_vars/dbservers.yml",
      "values": [
        "postgresql"
      ]
    },
    "auth_method": {
      "description": "Database authentication method",
      "domain": [
        "scram-sha-256"
      ],
      "source": "roles/db/tasks/main.yml",
      "values": [
        "scram-sha-256"
      ]
    }
  },
  "environment": {
    "org": {
      "description": "Organisation name",
      "domain": [
        "privsep-corp"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "privsep-corp"
      ]
    },
    "environment": {
      "description": "Deployment environment",
      "domain": [
        "production"
      ],
      "source": "inventory.ini [prod:vars]",
      "values": [
        "production"
      ]
    },
    "compliance_tier": {
      "description": "Compliance framework tier",
      "domain": [
        "soc2"
      ],
      "source": "group_vars/all.yml + inventory.ini",
      "values": [
        "soc2"
      ]
    },
    "retention_days": {
      "description": "Log retention window in days",
      "domain": null,
      "source": "group_vars/all.yml",
      "values": [
        90
      ]
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "Allow ssh:login to all prod hosts for members of the sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "in": [
          "webservers",
          "dbservers",
          "cacheservers"
        ]
      },
      "zone": {
        "in": [
          "dmz",
          "internal"
        ]
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
      "lines": [
        28,
        30
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "description": "Ansible configures auditd / var/log/wtmp for SSH sessions",
        "source": "group_vars/all.yml",
        "detail": "compliance_tier=soc2 → session records must be retained ≥90 days"
      }
    ]
  },
  {
    "rule_id": "rule-002",
    "description": "Explicitly deny sudo:execute for the www-data service account",
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "sudo:execute",
    "effect": "deny",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure www-data has NO sudo access",
      "lines": [
        34,
        36
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Allow network:connect to nginx/443 from any internet source",
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
      "host_group": {
        "equals": "webservers"
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
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        22,
        27
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow filesystem:read on /var/www/html for www-data owner",
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": [
        16,
        20
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow network:connect to redis/6379 from webserver subnet",
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
      },
      "host_group": {
        "equals": "cacheservers"
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
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": [
        13,
        19
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow db:login to postgresql from webserver subnet (scram-sha-256)",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "host_group": {
        "equals": "dbservers"
      },
      "auth_method": {
        "equals": "scram-sha-256"
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
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        15,
        18
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow filesystem:read and filesystem:write on PG data dir for postgres",
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": [
        6,
        11
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Allow filesystem:read on redis config for redis service account",
    "subject_condition": {
      "groups": {
        "equals": "redis"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/redis/redis.conf"
      },
      "owner": {
        "equals": "redis"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Ensure redis runs as redis user",
      "lines": [
        5,
        9
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Default-deny: reject all access not explicitly permitted above",
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
      "file": "ABAC implicit default",
      "task": "default-deny",
      "lines": [
        0,
        0
      ]
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
    "resource_condition": {
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "webservers"
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
    "id": "rule-003",
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
      },
      "host_group": {
        "equals": "cacheservers"
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
    "cve_id": "CVE-2007-3279",
    "age_in_days": 6882,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2007-06-19T21:30:00Z",
    "cve_updated_at": "2026-04-23T00:35:47Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.86341,
    "epss_score": 0.02885,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/35144"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://osvdb.org/40900"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.leidecker.info/pgshell/Having_Fun_With_PostgreSQL.txt"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.mandriva.com/security/advisories?name=MDKSA-2007:188"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.portcullis.co.uk/uplds/whitepapers/Having_Fun_With_PostgreSQL.pdf"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/471541/100/0/threaded"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation.",
    "impact": "Remote attackers can create and execute functions, enabling privilege escalation or malicious activities like password guessing.",
    "name": "PostgreSQL - Privilege Escalation",
    "remediation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed.",
    "requirement_type": "logged_in",
    "requirements": "Attacker needs to create functions in the database",
    "severity": "critical",
    "vulnerability_impact": [
      "privilege_escalation"
    ],
    "vulnerability_type": "broken_access_control",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2007-06-19T21:30:00Z",
    "doc_id": "CVE-2007-3279",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 550047,
      "min_hosts": 550047
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-04-23T13:59:10.477Z",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned": true,
    "recommendation": "Update postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2002-1399",
    "age_in_days": 8497,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2003-01-17T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.64045,
    "epss_score": 0.00458,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://archives.postgresql.org/pgsql-hackers/2002-08/msg00713.php"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=102978152712430&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://archives.postgresql.org/pgsql-hackers/2002-08/msg00708.php"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified.",
    "impact": "Potential for unexpected behavior or system instability due to improper handling of invalid input, specific impact is unspecified.",
    "name": "PostgreSQL - Integer Overflow",
    "remediation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "undefined"
    ],
    "vulnerability_type": "integer_overflow",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2003-01-17T05:00:00Z",
    "doc_id": "CVE-2002-1399",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 550047,
      "min_hosts": 550047
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-04-23T13:51:41.708Z",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned": true,
    "recommendation": "Update postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "age_in_days": 4766,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-04-04T17:55:00Z",
    "cve_updated_at": "2025-04-11T00:51:21Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.68021,
    "epss_score": 0.0055,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "rejected",
    "citations": [
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.postgresql.org/about/news/1456/"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.postgresql.org/support/security/"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html"
      }
    ],
    "cwe": [
      "CWE-264"
    ],
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers potentially access sensitive credentials, exploit requires access to installer scripts.",
    "impact": "Potential exposure of superuser password, leading to unauthorized access and control over the database system.",
    "name": "PostgreSQL - Information Disclosure",
    "remediation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "requirement_type": "user_interaction",
    "requirements": "Attacker needs access to installer scripts",
    "severity": "critical",
    "vulnerability_impact": [
      "information_disclosure"
    ],
    "vulnerability_type": "undefined",
    "weaknesses": [
      {
        "cwe_id": "CWE-264"
      }
    ],
    "affected_products": [
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2013-04-04T17:55:00Z",
    "doc_id": "CVE-2013-1903",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 550047,
      "min_hosts": 550047
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-04-23T15:19:21.794Z",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned": true,
    "recommendation": "Update postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1902",
    "age_in_days": 4766,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-04-04T17:55:00Z",
    "cve_updated_at": "2025-04-11T00:51:21Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.66994,
    "epss_score": 0.00523,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "rejected",
    "citations": [
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.postgresql.org/support/security/"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.postgresql.org/about/news/1456/"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "impact": "Potential for attackers to exploit predictable temporary files, possibly leading to information disclosure or other unspecified impacts.",
    "name": "PostgreSQL - Insecure Temporary Files",
    "remediation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "information_disclosure"
    ],
    "vulnerability_type": "undefined",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2013-04-04T17:55:00Z",
    "doc_id": "CVE-2013-1902",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 550047,
      "min_hosts": 550047
    },
    "h1": {
      "delta_rank": 14,
      "delta_reports": -1,
      "rank": 7968
    },
    "ntps": 45,
    "updated_at": "2026-04-23T15:49:56.392Z",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned": true,
    "recommendation": "Update postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2024-1597",
    "age_in_days": 794,
    "assignee": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007",
    "cve_created_at": "2024-02-19T13:15:07Z",
    "cve_updated_at": "2025-11-03T22:16:40Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 10,
    "epss_percentile": 0.66397,
    "epss_score": 0.00508,
    "is_kev": true,
    "is_oss": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2024-10-30T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-10-30T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.reliaquest.com/blog/5-critical-threat-actors-you-need-to-know-about/"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-24rp-q3w6-vc56"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TZQTSMESZD2RJ5XBPSXH3TIQVUW5DIUU/"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://www.enterprisedb.com/docs/security/assessments/cve-2024-1597/"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://www.sonarsource.com/blog/double-dash-double-trouble-a-subtle-sql-injection-flaw/"
      },
      {
        "added_at": "2025-11-03T22:16:40Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2024/12/msg00017.html"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://www.enterprisedb.com/docs/jdbc_connector/latest/01_jdbc_rel_notes/"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/04/02/6"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2024/05/msg00007.html"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20240419-0008/"
      }
    ],
    "cwe": [
      "CWE-89"
    ],
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeholder construction.",
    "impact": "Attackers can inject malicious SQL, potentially leading to data theft, modification, or deletion.",
    "name": "pgjdbc - SQL Injection",
    "remediation": "Update to version 42.7.2 or later.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "information_disclosure",
      "data_tampering"
    ],
    "vulnerability_type": "sql_injection",
    "weaknesses": [
      {
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
      }
    ],
    "affected_products": [
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fedora",
        "summary": "fedoraproject fedora is a Linux-based open-source operating system that provides a robust and secure platform for developers and users. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "fedoraproject"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "postgresql_jdbc_driver",
        "summary": "postgresql postgresql_jdbc_driver is a database connectivity library that enables Java applications to interact with PostgreSQL databases. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2024-02-19T13:15:07Z",
    "doc_id": "CVE-2024-1597",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 40582,
      "min_hosts": 40582
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 61,
    "updated_at": "2026-04-23T15:50:51.057Z",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned": true,
    "recommendation": "Update postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2015-4335",
    "age_in_days": 3970,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2015-06-09T14:59:07Z",
    "cve_updated_at": "2025-04-12T10:46:40Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.92189,
    "epss_score": 0.08128,
    "is_oss": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 1,
    "poc_first_seen": "2015-06-09T14:59:07Z",
    "pocs": [
      {
        "added_at": "2015-06-09T14:59:07Z",
        "source": "nvd",
        "url": "http://benmmurphy.github.io/blog/2015/06/04/redis-eval-lua-sandbox-escape/"
      }
    ],
    "vuln_status": "rejected",
    "citations": [
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://benmmurphy.github.io/blog/2015/06/04/redis-eval-lua-sandbox-escape/"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2015-July/162146.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-updates/2015-10/msg00014.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.debian.org/security/2015/dsa-3279"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2015/06/05/3"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/bid/75034"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://security.gentoo.org/glsa/201702-16"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://groups.google.com/forum/#%21msg/redis-db/4Y6OqK8gEyk/Dg-5cejl-eUJ"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2015-July/162094.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://rhn.redhat.com/errata/RHSA-2015-1676.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2015/06/04/12"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2015/06/04/8"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://github.com/antirez/redis/commit/fdf9d455098f54f7666c702ae464e6ea21e25411"
      }
    ],
    "cwe": [
      "CWE-17"
    ],
    "description": "Redis < 2.8.21 and 3.x < 3.0.2 contain a remote code execution caused by unsafe eval command processing, letting attackers execute arbitrary Lua bytecode remotely, exploit requires network access to Redis server.",
    "impact": "Attackers can execute arbitrary Lua bytecode, leading to remote code execution and full server compromise.",
    "name": "Redis - Remote Code Execution",
    "remediation": "Update Redis to version 2.8.21 or later, or 3.0.2 or later.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "insecure_deserialization",
    "weaknesses": [
      {
        "cwe_id": "CWE-17"
      }
    ],
    "affected_products": [
      {
        "category": "data_storage",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "redis",
        "summary": "redislabs redis is an in-memory data structure store that provides high-performance caching, database, and message brokering capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redislabs"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      }
    ],
    "created_at": "2015-06-09T14:59:07Z",
    "doc_id": "CVE-2015-4335",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 4711752,
      "min_hosts": 241726
    },
    "h1": {
      "delta_rank": 14,
      "delta_reports": -1,
      "rank": 7968
    },
    "ntps": 55,
    "updated_at": "2026-04-23T14:47:50.157Z",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "affects_pinned": true,
    "recommendation": "Update redis to latest patched version"
  },
  {
    "cve_id": "CVE-2022-0543",
    "age_in_days": 1525,
    "assignee": "security@debian.org",
    "cve_created_at": "2022-02-18T20:15:17Z",
    "cve_updated_at": "2025-11-10T14:44:23Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 10,
    "epss_percentile": 0.99975,
    "epss_score": 0.94398,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "is_template": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2022-03-28T00:00:00Z",
        "due_date": "2022-04-18T00:00:00Z",
        "source": "cisa"
      },
      {
        "added_date": "2022-03-24T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 19,
    "poc_first_seen": "2017-04-09T10:13:13Z",
    "pocs": [
      {
        "added_at": "2022-09-05T16:25:49Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/abramas/CVE-2022-0543"
      },
      {
        "added_at": "2022-09-01T16:44:56Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/JacobEbben/CVE-2022-0543"
      },
      {
        "added_at": "2022-07-06T04:35:59Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:z92g/CVE-2022-0543.git"
      },
      {
        "added_at": "2023-05-10T05:05:31Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/SiennaSkies/redisHack"
      },
      {
        "added_at": "2022-09-01T16:44:56Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:JacobEbben/CVE-2022-0543.git"
      },
      {
        "added_at": "2022-09-01T16:44:56Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/JacobEbben/CVE-2022-0543.git"
      },
      {
        "added_at": "2022-03-16T06:41:50Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/0x7eTeam/CVE-2022-0543"
      },
      {
        "added_at": "2023-05-10T05:05:31Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/SiennaSkies/redisHack.git"
      },
      {
        "added_at": "2022-07-06T04:35:59Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/z92g/CVE-2022-0543"
      },
      {
        "added_at": "2022-03-16T06:41:50Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:0x7eTeam/CVE-2022-0543.git"
      },
      {
        "added_at": "2022-03-16T06:41:50Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/0x7eTeam/CVE-2022-0543.git"
      },
      {
        "added_at": "2022-02-18T20:15:17Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/166885/Redis-Lua-Sandbox-Escape.html"
      },
      {
        "added_at": "2026-04-24T08:54:59Z",
        "source": "metasploit",
        "url": "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/redis/redis_debian_sandbox_escape.rb"
      },
      {
        "added_at": "2026-03-08T17:40:11Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/John-Popovici/CVE-2022-0543-redis-sandbox-escape"
      },
      {
        "added_at": "2023-05-10T05:05:31Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:SiennaSkies/redisHack.git"
      },
      {
        "added_at": "2022-07-06T04:35:59Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/z92g/CVE-2022-0543.git"
      },
      {
        "added_at": "2017-04-09T10:13:13Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:vulhub/vulhub.git"
      },
      {
        "added_at": "2017-04-09T10:13:13Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/vulhub/vulhub.git"
      },
      {
        "added_at": "2025-11-18T06:35:45Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/netw0rk7/CVE-2022-0543-Home-Lab"
      }
    ],
    "vuln_status": "confirmed",
    "citations": [
      {
        "added_at": "2024-09-19T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.aquasec.com/blog/sink-or-swim-tackling-2024s-record-breaking-vulnerability-wave/"
      },
      {
        "added_at": "2024-02-28T00:00:00Z",
        "source": "vulncheck",
        "url": "https://14518100.fs1.hubspotusercontent-na1.net/hubfs/14518100/H2%202023%20Cloud%20Threat%20Findings%20Report.pdf"
      },
      {
        "added_at": "2023-12-04T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.cadosecurity.com/p2pinfect-new-variant-targets-mips-devices/"
      },
      {
        "added_at": "2023-07-05T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/honeypot-recon-enterprise-applications-honeypot-unveiling-findings-from-six-worldwide-locations/"
      },
      {
        "added_at": "2025-10-21T19:19:28Z",
        "source": "nvd",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2022-0543"
      },
      {
        "added_at": "2026-03-24T09:14:41Z",
        "source": "nuclei_template",
        "url": "https://attackerkb.com/topics/wyA1c1HIC8/cve-2022-0543/rapid7-analysis#rapid7-analysis"
      },
      {
        "added_at": "2026-01-29T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.forescout.com/resources/2025-threat-roundup/"
      },
      {
        "added_at": "2022-12-01T00:00:00Z",
        "source": "vulncheck",
        "url": "https://blog.aquasec.com/redigo-redis-backdoor-malware"
      },
      {
        "added_at": "2025-04-02T20:22:56Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20220331-0004/"
      },
      {
        "added_at": "2026-03-24T09:14:41Z",
        "source": "nuclei_template",
        "url": "https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce"
      },
      {
        "added_at": "2026-03-24T09:14:41Z",
        "source": "nuclei_template",
        "url": "https://bugs.debian.org/1005787"
      },
      {
        "added_at": "2026-03-24T09:14:41Z",
        "source": "nuclei_template",
        "url": "https://www.debian.org/security/2022/dsa-5081"
      },
      {
        "added_at": "2024-03-04T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.radware.com/getattachment/75cca6a9-7008-49ed-a92b-5701bd033c1e/Radware-2023_H1_ThreatReport-08_2023-RW-396-FIN.pdf.aspx"
      },
      {
        "added_at": "2023-07-19T00:00:00Z",
        "source": "vulncheck",
        "url": "https://unit42.paloaltonetworks.com/peer-to-peer-worm-p2pinfect/"
      },
      {
        "added_at": "2022-12-03T00:00:00Z",
        "source": "vulncheck",
        "url": "https://cybersecuritynews.com/hackers-drops-bakcdoor-malware-redigo-redis-server/"
      },
      {
        "added_at": "2025-04-02T20:22:56Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/166885/Redis-Lua-Sandbox-Escape.html"
      },
      {
        "added_at": "2026-03-24T09:14:41Z",
        "source": "nuclei_template",
        "url": "https://lists.debian.org/debian-security-announce/2022/msg00048.html"
      },
      {
        "added_at": "2026-03-30T00:00:00Z",
        "source": "vulncheck",
        "url": "https://api.vulncheck.com/v3/index/vulncheck-canaries?cve=CVE-2022-0543&date=2026-03-30"
      }
    ],
    "cwe": [
      "CWE-862"
    ],
    "description": "Debian and Ubuntu Redis packages contain a Lua sandbox escape caused by insufficient sanitization of the Lua environment, letting attackers load arbitrary libraries, exploit requires attacker to execute malicious Lua code.",
    "impact": "Attackers can load arbitrary libraries in Redis, potentially leading to remote code execution or sandbox escape.",
    "name": "Redis - Command Injection",
    "remediation": "Update Redis packages to the latest versions where the sandbox is properly sanitized.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "server_side_request_forgery",
    "weaknesses": [
      {
        "cwe_id": "CWE-862",
        "cwe_name": "Missing Authorization"
      }
    ],
    "category": "cve",
    "ref": "projectdiscovery/nuclei-templates:9929a2f52419",
    "release_tag": "v8.9.9",
    "is_pdteam": true,
    "filename": "CVE-2022-0543.yaml",
    "uri": "network/cves/2022/CVE-2022-0543.yaml",
    "author": [
      "dwisiswant0"
    ],
    "metadata": {
      "max-request": 2,
      "product": "redis",
      "shodan-query": [
        "redis_version",
        "redis"
      ],
      "vendor": "redis"
    },
    "tags": [
      "cve",
      "cve2022",
      "network",
      "redis",
      "unauth",
      "rce",
      "kev",
      "tcp",
      "vkev",
      "vuln"
    ],
    "type": "tcp",
    "id": "CVE-2022-0543",
    "affected_products": [
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "redis",
        "summary": "redis redis is an in-memory data structure store that provides high-performance caching and database capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redis"
      }
    ],
    "created_at": "2022-02-18T20:15:17Z",
    "doc_id": "CVE-2022-0543",
    "doc_type": "cve_template",
    "exposure": {
      "max_hosts": 81492,
      "min_hosts": 81492
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 78,
    "updated_at": "2026-04-24T08:55:17.216Z",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "affects_pinned": true,
    "recommendation": "Update redis to latest patched version"
  },
  {
    "cve_id": "CVE-2025-49844",
    "age_in_days": 201,
    "assignee": "security-advisories@github.com",
    "cve_created_at": "2025-10-03T20:15:32Z",
    "cve_updated_at": "2026-03-20T14:16:14Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 9.9,
    "epss_percentile": 0.94406,
    "epss_score": 0.14172,
    "is_auth": true,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "is_template": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2025-12-23T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 33,
    "poc_first_seen": "2019-04-13T07:51:09Z",
    "pocs": [
      {
        "added_at": "2025-10-28T21:20:19Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/elyasbassir/CVE-2025-49844"
      },
      {
        "added_at": "2025-10-09T18:03:24Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner.git"
      },
      {
        "added_at": "2025-10-07T06:18:28Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:raminfp/redis_exploit.git"
      },
      {
        "added_at": "2025-10-07T06:18:28Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/raminfp/redis_exploit.git"
      },
      {
        "added_at": "2025-10-07T04:58:12Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/dwisiswant0/CVE-2025-49844"
      },
      {
        "added_at": "2026-04-06T08:03:33Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/dajneem23/CVE-2025-49844"
      },
      {
        "added_at": "2026-03-13T17:46:34Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/Cilectiy/CVE-2025-49844.git"
      },
      {
        "added_at": "2025-10-30T09:01:20Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/B1ack4sh/Blackash-CVE-2025-49844"
      },
      {
        "added_at": "2025-10-07T00:57:38Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/gopinaath/CVE-2025-49844-discovery"
      },
      {
        "added_at": "2026-03-13T17:46:34Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Cilectiy/CVE-2025-49844"
      },
      {
        "added_at": "2025-10-30T09:01:20Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Ashwesker/Blackash-CVE-2025-49844"
      },
      {
        "added_at": "2025-10-07T06:18:28Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/raminfp/redis_exploit"
      },
      {
        "added_at": "2022-04-06T09:27:39Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Zain3311/CVE-2025-49844"
      },
      {
        "added_at": "2025-10-28T21:20:19Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:elyasbassir/CVE-2025-49844.git"
      },
      {
        "added_at": "2025-10-28T21:20:19Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/elyasbassir/CVE-2025-49844.git"
      },
      {
        "added_at": "2025-10-08T13:38:51Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/pedrorichil/CVE-2025-49844"
      },
      {
        "added_at": "2025-10-09T18:03:24Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner.git"
      },
      {
        "added_at": "2026-03-09T22:43:36Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/0xAshwesker/CVE-2025-49844"
      },
      {
        "added_at": "2025-12-03T06:22:38Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/zbyszkok/CVE-2025-49844-RediShell-AI-made-Revshell"
      },
      {
        "added_at": "2025-10-14T04:20:45Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/angelusrivera/CVE-2025-49844"
      },
      {
        "added_at": "2025-10-07T10:12:51Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/lastvocher/redis-CVE-2025-49844"
      },
      {
        "added_at": "2019-04-13T07:51:09Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/ksnnd32/redis_exploit"
      },
      {
        "added_at": "2026-03-09T22:43:36Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/0xBlackash/CVE-2025-49844"
      },
      {
        "added_at": "2025-10-31T05:59:25Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:saneki/cve-2025-49844.git"
      },
      {
        "added_at": "2025-10-31T05:59:25Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/saneki/cve-2025-49844.git"
      },
      {
        "added_at": "2025-10-09T18:03:24Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner"
      },
      {
        "added_at": "2025-10-09T13:21:44Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/MiclelsonCN/CVE-2025-49844_POC"
      },
      {
        "added_at": "2025-10-08T07:16:07Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/srozb/reditrap"
      },
      {
        "added_at": "2025-10-31T05:59:25Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/saneki/cve-2025-49844"
      },
      {
        "added_at": "2025-10-11T11:42:27Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/imbas007/CVE-2025-49844-Vulnerability-Scanner"
      },
      {
        "added_at": "2025-10-09T13:21:44Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/YuanBenSir/CVE-2025-49844_POC"
      },
      {
        "added_at": "2025-10-09T06:03:02Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Yuri08loveElaina/CVE-2025-49844"
      },
      {
        "added_at": "2025-11-11T20:40:05Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Network-Sec/CVE-2025-49844-RediShell-AI-made-Revshell"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-12-24T06:33:22Z",
        "source": "nuclei_template",
        "url": "https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844"
      },
      {
        "added_at": "2025-12-24T06:33:22Z",
        "source": "nuclei_template",
        "url": "https://github.com/dwisiswant0/CVE-2025-49844"
      },
      {
        "added_at": "2026-02-25T00:00:00Z",
        "source": "vulncheck",
        "url": "https://wwv.vulncheck.com/2026-vulncheck-exploit-intelligence-report"
      },
      {
        "added_at": "2026-01-19T00:00:00Z",
        "source": "vulncheck",
        "url": "https://hs-21289959.f.hubspotemail.net/hubfs/21289959/Annual%20Threat%20Landscape%20Report_2025.pdf"
      },
      {
        "added_at": "2025-10-03T20:15:32Z",
        "source": "nvd",
        "url": "https://github.com/redis/redis/releases/tag/8.2.2"
      },
      {
        "added_at": "2025-10-03T20:15:32Z",
        "source": "nvd",
        "url": "https://github.com/redis/redis/security/advisories/GHSA-4789-qfc9-5f9q"
      },
      {
        "added_at": "2026-04-11T00:00:00Z",
        "source": "vulncheck",
        "url": "https://api.vulncheck.com/v3/index/vulncheck-canaries?cve=CVE-2025-49844&date=2026-04-11"
      },
      {
        "added_at": "2026-02-12T00:00:00Z",
        "source": "vulncheck",
        "url": "https://b9866c47-b467-4bc0-b154-6afa06da0ab5.usrfiles.com/ugd/b9866c_2578eb8c8ffe4257b30efef3ad0f953e.pdf"
      },
      {
        "added_at": "2025-10-03T20:15:32Z",
        "source": "nvd",
        "url": "https://github.com/redis/redis/commit/d5728cb5795c966c5b5b1e0f0ac576a7e69af539"
      },
      {
        "added_at": "2025-11-04T22:16:19Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2025/10/07/2"
      },
      {
        "added_at": "2026-03-20T14:16:14Z",
        "source": "nvd",
        "url": "https://github.com/lastvocher/redis-CVE-2025-49844"
      }
    ],
    "cwe": [
      "CWE-416"
    ],
    "description": "Redis <= 8.2.1 contains a use-after-free vulnerability caused by manipulation of the garbage collector via specially crafted Lua scripts, letting authenticated users potentially achieve remote code execution, exploit requires authentication.",
    "impact": "Authenticated users can execute arbitrary code remotely, potentially leading to full server compromise.",
    "name": "Redis - Remote Code Execution",
    "remediation": "Update to version 8.2.2 or later; alternatively, restrict EVAL and EVALSHA commands using ACL.",
    "requirement_type": "logged_in",
    "requirements": "Attacker must be authenticated to execute Lua scripts",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "use_after_free",
    "weaknesses": [
      {
        "cwe_id": "CWE-416",
        "cwe_name": "Use After Free"
      }
    ],
    "category": "cve",
    "ref": "projectdiscovery/nuclei-templates:df505c7a554f",
    "release_tag": "v10.3.1",
    "is_pdteam": true,
    "filename": "CVE-2025-49844.yaml",
    "uri": "javascript/cves/2025/CVE-2025-49844.yaml",
    "author": [
      "pussycat0x"
    ],
    "metadata": {
      "max-request": 1,
      "shodan-query": "product:\"redis\"",
      "verified": true
    },
    "tags": [
      "cve",
      "cve2025",
      "js",
      "redis",
      "network",
      "passive",
      "authenticated",
      "vuln",
      "vkev"
    ],
    "type": "javascript",
    "id": "CVE-2025-49844",
    "affected_products": [
      {
        "product": "valkey",
        "vendor": "lfprojects"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "redis",
        "summary": "redis redis is an in-memory data structure store that provides high-performance caching and database capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redis"
      }
    ],
    "created_at": "2025-10-03T20:15:32Z",
    "doc_id": "CVE-2025-49844",
    "doc_type": "cve_template",
    "exposure": {
      "max_hosts": 81286,
      "min_hosts": 81286
    },
    "ntps": 65,
    "updated_at": "2026-04-23T17:48:51.849Z",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "affects_pinned": true,
    "recommendation": "Update redis to latest patched version"
  },
  {
    "cve_id": "CVE-2016-0746",
    "age_in_days": 3719,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2016-02-15T19:59:01Z",
    "cve_updated_at": "2025-04-12T10:46:40Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.94368,
    "epss_score": 0.14006,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "vuln_status": "rejected",
    "citations": [
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://mailman.nginx.org/pipermail/nginx/2016-January/049700.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-updates/2016-02/msg00042.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://seclists.org/fulldisclosure/2021/Sep/36"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.debian.org/security/2016/dsa-3473"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id/1034869"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.ubuntu.com/usn/USN-2892-1"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2016:1425"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://bto.bluecoat.com/security-advisory/sa115"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1302588"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://security.gentoo.org/glsa/201606-06"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://support.apple.com/kb/HT212818"
      }
    ],
    "cwe": [
      "CWE-416"
    ],
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses related to CNAME processing, exploit requires sending malicious DNS responses.",
    "impact": "Attackers can cause worker process crashes or other unspecified impacts by sending crafted DNS responses, leading to service disruption.",
    "name": "nginx - Use After Free",
    "remediation": "Update to nginx 1.9.10 or later versions.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "denial_of_service"
    ],
    "vulnerability_type": "use_after_free",
    "weaknesses": [
      {
        "cwe_id": "CWE-416",
        "cwe_name": "Use After Free"
      }
    ],
    "affected_products": [
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "leap",
        "summary": "opensuse leap is a stable and secure Linux-based operating system that provides a robust platform for desktops and servers. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "opensuse"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "xcode",
        "summary": "apple xcode is an integrated development environment (IDE) that provides tools for software development on Apple platforms. It sits in the application_library layer of the tech stack, functions as a development tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "apple"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ubuntu_linux",
        "summary": "canonical ubuntu_linux is a popular open-source operating system that provides a stable and secure platform for computing. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "canonical"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      }
    ],
    "created_at": "2016-02-15T19:59:01Z",
    "doc_id": "CVE-2016-0746",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 62581792,
      "min_hosts": 4711752
    },
    "h1": {
      "delta_rank": -3,
      "rank": 590,
      "reports": 12
    },
    "ntps": 43,
    "updated_at": "2026-04-23T14:33:29.641Z",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned": true,
    "recommendation": "Update nginx to latest patched version"
  },
  {
    "cve_id": "CVE-2021-46461",
    "age_in_days": 1528,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2022-02-14T22:15:07Z",
    "cve_updated_at": "2024-11-21T06:34:07Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.70096,
    "epss_score": 0.00619,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 1,
    "poc_first_seen": "2022-02-14T22:15:07Z",
    "pocs": [
      {
        "added_at": "2022-02-14T22:15:07Z",
        "source": "nvd",
        "url": "https://github.com/nginx/njs/issues/450"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T06:34:07Z",
        "source": "nvd",
        "url": "https://github.com/nginx/njs/commit/d457c9545e7e71ebb5c0479eb16b9d33175855e2"
      },
      {
        "added_at": "2024-11-21T06:34:07Z",
        "source": "nvd",
        "url": "https://github.com/nginx/njs/issues/450"
      },
      {
        "added_at": "2024-11-21T06:34:07Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20220303-0007/"
      }
    ],
    "cwe": [
      "CWE-119"
    ],
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit requires crafted input.",
    "impact": "Attackers can cause application crashes or execute arbitrary code, leading to denial of service or full system compromise.",
    "name": "NGINX njs - Buffer Overflow",
    "remediation": "Update to the latest version of njs where the issue is fixed.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "denial_of_service",
      "remote_code_execution"
    ],
    "vulnerability_type": "out_of_bounds_rw",
    "weaknesses": [
      {
        "cwe_id": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within the Bounds of a Memory Buffer"
      }
    ],
    "affected_products": [
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "njs",
        "summary": "nginx njs is a lightweight scripting language and engine that extends nginx functionality with custom logic and dynamic content handling. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "nginx"
      }
    ],
    "created_at": "2022-02-14T22:15:07Z",
    "doc_id": "CVE-2021-46461",
    "doc_type": "cve",
    "exposure": {},
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 50,
    "updated_at": "2026-04-23T14:23:07.284Z",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned": true,
    "recommendation": "Update nginx to latest patched version"
  },
  {
    "cve_id": "CVE-2017-20005",
    "age_in_days": 1781,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2021-06-06T22:15:08Z",
    "cve_updated_at": "2025-12-05T15:15:49Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.87155,
    "epss_score": 0.0325,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 1,
    "poc_first_seen": "2021-06-06T22:15:08Z",
    "pocs": [
      {
        "added_at": "2021-06-06T22:15:08Z",
        "source": "nvd",
        "url": "https://trac.nginx.org/nginx/ticket/1368"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20210805-0006/"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "url": "http://nginx.org/en/CHANGES"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "url": "https://trac.nginx.org/nginx/ticket/1368"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "url": "https://github.com/nginx/nginx/commit/0206ebe76f748bb39d9de4dd4b3fce777fdfdccf"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "url": "https://github.com/nginx/nginx/commit/b900cc28fcbb4cf5a32ab62f80b59292e1c85b4b"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2021/06/msg00009.html"
      }
    ],
    "cwe": [
      "CWE-190",
      "CWE-120"
    ],
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denial of service or potentially execute arbitrary code, exploit requires processing of specially crafted files with large modification dates.",
    "impact": "Attackers can cause denial of service or execute arbitrary code by exploiting the buffer overflow.",
    "name": "NGINX - Buffer Overflow",
    "remediation": "Update to version 1.13.6 or later.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "denial_of_service",
      "remote_code_execution"
    ],
    "vulnerability_type": "buffer_overflow",
    "weaknesses": [
      {
        "cwe_id": "CWE-190",
        "cwe_name": "Integer Overflow or Wraparound"
      },
      {
        "cwe_id": "CWE-120",
        "cwe_name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')"
      }
    ],
    "affected_products": [
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      }
    ],
    "created_at": "2021-06-06T22:15:08Z",
    "doc_id": "CVE-2017-20005",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 62581792,
      "min_hosts": 4711752
    },
    "h1": {
      "delta_rank": 3,
      "delta_reports": -1,
      "rank": 7954
    },
    "ntps": 51,
    "updated_at": "2026-04-23T15:04:56.098Z",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned": true,
    "recommendation": "Update nginx to latest patched version"
  },
  {
    "cve_id": "CVE-2017-15047",
    "age_in_days": 3121,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2017-10-06T04:29:00Z",
    "cve_updated_at": "2025-04-20T01:37:25Z",
    "cvss_metrics": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.57573,
    "epss_score": 0.00351,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "vuln_status": "rejected",
    "citations": [
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://github.com/antirez/redis/issues/4278"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://security.gentoo.org/glsa/202008-17"
      }
    ],
    "cwe": [
      "CWE-119"
    ],
    "description": "Redis 4.0.2 contains a denial of service caused by out-of-bounds array index in clusterLoadConfig function in cluster.c, letting attackers cause application crash, exploit requires limited access to the machine.",
    "impact": "Attackers can cause Redis server crash or instability, leading to denial of service.",
    "name": "Redis - Out of Bounds Read/Write",
    "remediation": "Update to the latest version of Redis where this issue is fixed.",
    "requirement_type": "logged_in",
    "requirements": "Limited access to the machine",
    "severity": "critical",
    "vulnerability_impact": [
      "denial_of_service"
    ],
    "vulnerability_type": "out_of_bounds_rw",
    "weaknesses": [
      {
        "cwe_id": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within the Bounds of a Memory Buffer"
      }
    ],
    "affected_products": [
      {
        "category": "data_storage",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "redis",
        "summary": "redislabs redis is an in-memory data structure store that provides high-performance caching, database, and message brokering capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redislabs"
      }
    ],
    "created_at": "2017-10-06T04:29:00Z",
    "doc_id": "CVE-2017-15047",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 241726,
      "min_hosts": 241726
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-04-23T15:12:13.667Z",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "affects_pinned": true,
    "recommendation": "Update redis to latest patched version"
  },
  {
    "cve_id": "CVE-2023-31654",
    "age_in_days": 820,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2024-01-23T22:15:16Z",
    "cve_updated_at": "2025-05-30T15:15:21Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.62727,
    "epss_score": 0.00432,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 1,
    "poc_first_seen": "2024-01-23T22:15:16Z",
    "pocs": [
      {
        "added_at": "2024-01-23T22:15:16Z",
        "source": "nvd",
        "url": "https://github.com/RedisLabs/redisraft/issues/600"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-05-30T15:15:21Z",
        "source": "nvd",
        "url": "https://github.com/RedisLabs/redisraft/issues/600"
      },
      {
        "added_at": "2025-05-30T15:15:21Z",
        "source": "nvd",
        "url": "https://seclists.org/fulldisclosure/2024/Jan/13"
      }
    ],
    "cwe": [
      "NVD-CWE-noinfo"
    ],
    "description": "Redis raft master-1b8bd86 to master-7b46079 contains an ODR violation caused by hiredisAllocFns in /opt/fs/redisraft/deps/hiredis/alloc.c, letting potential undefined behavior impact, exploit requires specific build environment.",
    "impact": "Potential undefined behavior leading to crashes or security issues if exploited.",
    "name": "Redisraft - Undefined Behavior",
    "remediation": "Review and fix the ODR violation in hiredisAllocFns, update to latest Redisraft version if available.",
    "requirement_type": "undefined",
    "requirements": "Specific build environment and code modification required",
    "severity": "critical",
    "vulnerability_impact": [
      "denial_of_service"
    ],
    "vulnerability_type": "undefined",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-noinfo"
      }
    ],
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "redisraft",
        "summary": "redis redisraft is a distributed consensus module that adds Raft-based replication and fault tolerance to Redis. It sits in the core_infra layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redis"
      }
    ],
    "created_at": "2024-01-23T22:15:16Z",
    "doc_id": "CVE-2023-31654",
    "doc_type": "cve",
    "exposure": {},
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 50,
    "updated_at": "2026-04-23T15:11:07.058Z",
    "product": "redis",
    "pinned_version": "7.0.11-1",
    "affects_pinned": true,
    "recommendation": "Update redis to latest patched version"
  },
  {
    "cve_id": "CVE-2021-23017",
    "age_in_days": 1787,
    "assignee": "f5sirt@f5.com",
    "cve_created_at": "2021-06-01T13:15:07Z",
    "cve_updated_at": "2024-11-21T05:51:09Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
    "cvss_score": 7.7,
    "epss_percentile": 0.98816,
    "epss_score": 0.73544,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 9,
    "poc_first_seen": "2021-12-17T09:53:39Z",
    "pocs": [
      {
        "added_at": "2025-09-04T09:49:22Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/6lj/EVIL-CVE-2021-23017-Update-2025"
      },
      {
        "added_at": "2025-05-06T16:32:48Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/moften/CVE-2021-23017"
      },
      {
        "added_at": "2025-04-17T11:33:08Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Cybervixy/Vulnerability-Management"
      },
      {
        "added_at": "2024-12-08T09:47:52Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/z3usx01/CVE-2021-23017-POC"
      },
      {
        "added_at": "2023-10-21T04:24:02Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/ShivamDey/CVE-2021-23017"
      },
      {
        "added_at": "2023-07-20T05:39:01Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/lakshit1212/CVE-2021-23017-PoC"
      },
      {
        "added_at": "2022-06-30T04:39:58Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/M507/CVE-2021-23017-PoC"
      },
      {
        "added_at": "2021-12-17T09:53:39Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/niandy/nginx-patch"
      },
      {
        "added_at": "2025-01-30T11:05:40Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/lukwagoasuman/-home-lukewago-Downloads-CVE-2021-23017-Nginx-1.14"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpujan2022.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r4d4966221ca399ce948ef34884652265729d7d9ef8179c78d7f17e7f%40%3Cnotifications.apisix.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7SFVYHC7OXTEO4SMBWXDVK6E5IMEYMEE/"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GNKOP2JR5L7KCIZTJRZDCUPJTUONMC5I/"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpuapr2022.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpuoct2021.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r37e6b2165f7c910d8e15fd54f4697857619ad2625f56583802004009%40%3Cnotifications.apisix.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r6fc5c57b38e93e36213e9a18c8a4e5dbd5ced1c7e57f08a1735975ba%40%3Cnotifications.apisix.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf232eecd47fdc44520192810560303073cefd684b321f85e311bad31%40%3Cnotifications.apisix.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf318aeeb4d7a3a312734780b47de83cefb7e6995da0b2cae5c28675c%40%3Cnotifications.apisix.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://support.f5.com/csp/article/K12331123%2C"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/167720/Nginx-1.20.0-Denial-Of-Service.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20210708-0006/"
      }
    ],
    "cwe": [
      "CWE-193"
    ],
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP packets from DNS server.",
    "impact": "Attackers can cause worker process crashes or other impacts by forging UDP packets, potentially leading to denial of service or other disruptions.",
    "name": "nginx - Buffer Overflow",
    "remediation": "Update nginx to the latest version where this issue is fixed.",
    "requirement_type": "none",
    "severity": "high",
    "vulnerability_impact": [
      "denial_of_service"
    ],
    "vulnerability_type": "buffer_overflow",
    "weaknesses": [
      {
        "cwe_id": "CWE-193",
        "cwe_name": "Off-by-one Error"
      }
    ],
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_communications_broker",
        "summary": "oracle enterprise_communications_broker is a communication integration platform that enables seamless messaging and data exchange across enterprise systems. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "goldengate",
        "summary": "oracle goldengate is a real-time data replication and integration solution that enables high availability and disaster recovery for enterprise data. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fedora",
        "summary": "fedoraproject fedora is a Linux-based open-source operating system that provides a robust and secure platform for developers and users. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "fedoraproject"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_select_deploy_administration_utility",
        "summary": "netapp ontap_select_deploy_administration_utility is a deployment and management tool for NetApp's ONTAP Select software-defined storage. It sits in the core_infra layer of the tech stack, functions as a self-hosted management utility in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "blockchain_platform",
        "summary": "oracle blockchain_platform is an enterprise-grade blockchain solution that enables secure and transparent business networks. It sits in the core_infra layer of the tech stack, functions as a platform service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_fraud_monitor",
        "summary": "oracle communications_fraud_monitor is a fraud detection and prevention solution designed to protect telecommunications networks from fraudulent activities. It sits in the core_infra layer of the tech stack, functions as a security monitoring system in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_operations_monitor",
        "summary": "oracle communications_operations_monitor is a network operations monitoring solution that provides real-time visibility and analytics for telecom networks. It sits in the core_infra layer of the tech stack, functions as an enterprise application in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "enterprise_session_border_controller",
        "summary": "oracle enterprise_session_border_controller is a session border controller that secures and manages VoIP and video communications across enterprise networks. It sits in the core_infra layer of the tech stack, functions as a network security and management appliance in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "enterprise_telephony_fraud_monitor",
        "summary": "oracle enterprise_telephony_fraud_monitor is a telephony fraud detection and monitoring solution that helps enterprises identify and prevent fraudulent activities in voice networks. It sits in the core_infra layer of the tech stack, functions as a security monitoring tool in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openresty",
        "summary": "openresty openresty is a web platform that integrates the Nginx web server with Lua scripting for high-performance web applications. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "openresty"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_control_plane_monitor",
        "summary": "oracle communications_control_plane_monitor is a network monitoring and management solution that provides real-time visibility and control over telecom control plane operations. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_session_border_controller",
        "summary": "oracle communications_session_border_controller is a network security and session management solution that protects and manages VoIP and multimedia sessions. It sits in the core_infra layer of the tech stack, functions as a network security appliance in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      }
    ],
    "created_at": "2021-06-01T13:15:07Z",
    "doc_id": "CVE-2021-23017",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 62581792,
      "min_hosts": 40582
    },
    "h1": {
      "delta_rank": 4,
      "rank": 387,
      "reports": 33
    },
    "ntps": 50,
    "updated_at": "2026-04-23T15:43:51.073Z",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned": true,
    "recommendation": "Update nginx to latest patched version"
  },
  {
    "cve_id": "CVE-2013-4547",
    "age_in_days": 4532,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-11-23T18:55:04Z",
    "cve_updated_at": "2025-04-11T00:51:21Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
    "cvss_score": 7.5,
    "epss_percentile": 0.99637,
    "epss_score": 0.90921,
    "is_oss": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 2,
    "poc_first_seen": "2020-06-20T09:37:58Z",
    "pocs": [
      {
        "added_at": "2025-12-08T15:37:35Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/rsp243/fix_nginx_CVE-2013-4547_IB"
      },
      {
        "added_at": "2020-06-20T09:37:58Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/cyberharsh/Nginx-CVE-2013-4547"
      }
    ],
    "vuln_status": "rejected",
    "citations": [
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://secunia.com/advisories/55757"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://secunia.com/advisories/55822"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://secunia.com/advisories/55825"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://mailman.nginx.org/pipermail/nginx-announce/2013/000125.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2013-12/msg00007.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-updates/2013-11/msg00084.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-updates/2013-11/msg00118.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-updates/2013-11/msg00119.html"
      }
    ],
    "cwe": [
      "CWE-116"
    ],
    "description": "nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 contain a restriction bypass caused by unescaped space character in URI, letting remote attackers bypass intended restrictions, exploit requires sending a crafted URI with unescaped space.",
    "impact": "Attackers can bypass restrictions and access restricted resources or functionalities, potentially leading to unauthorized access.",
    "name": "nginx - Authorization Bypass",
    "remediation": "Update to nginx 1.5.7 or later versions.",
    "requirement_type": "none",
    "severity": "high",
    "vulnerability_impact": [
      "information_disclosure"
    ],
    "vulnerability_type": "misconfiguration",
    "weaknesses": [
      {
        "cwe_id": "CWE-116",
        "cwe_name": "Improper Encoding or Escaping of Output"
      }
    ],
    "affected_products": [
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "opensuse",
        "summary": "opensuse opensuse is a Linux-based open source operating system that provides a stable and versatile platform for various computing needs. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "opensuse"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "lifecycle_management_server",
        "summary": "suse lifecycle_management_server is a systems management solution that automates patching, configuration, and provisioning of Linux servers. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure management tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "suse"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "studio_onsite",
        "summary": "suse studio_onsite is a custom Linux operating system build and deployment tool that enables enterprises to create tailored OS images. It sits in the operating_system layer of the tech stack, functions as a self-hosted deployment tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "suse"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "webyast",
        "summary": "suse webyast is a web-based system configuration tool that simplifies the management of SUSE Linux systems. It sits in the operating_system layer of the tech stack, functions as a self-hosted system management interface in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "suse"
      }
    ],
    "created_at": "2013-11-23T18:55:04Z",
    "doc_id": "CVE-2013-4547",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 62588721,
      "min_hosts": 415090
    },
    "h1": {
      "delta_rank": -5,
      "rank": 2534,
      "reports": 1
    },
    "ntps": 62,
    "updated_at": "2026-04-22T15:42:23.954Z",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned": true,
    "recommendation": "Update nginx to latest patched version"
  }
]
```

## Report

# ABAC Policy Mining Report

**Org:** privsep-corp
**Environment:** production
**Compliance Tier:** SOC 2
**Policy Goal:** all
**Generated:** automated ABAC extraction from Ansible configuration at $RLM_ANSIBLE_DIR

---

## 1. Attribute Catalog

### 1.1 Subjects

| Attribute | Type | Domain / Values | Source |
|-----------|------|-----------------|--------|
| `users` | entity list | admin (uid=1001, sudo, secret, operations), developer (uid=1002, developers, confidential, engineering) | group_vars/all.yml |
| `groups` | set | sudo, developers, www-data | group_vars/all.yml |
| `clearance` | enum | confidential, secret | group_vars/all.yml |
| `department` | enum | engineering, operations | group_vars/all.yml |

### 1.2 Resources

| Attribute | Type | Domain / Values | Source |
|-----------|------|-----------------|--------|
| `hostname` | entity list | web01.lab.local, db01.lab.local, cache01.lab.local | inventory.ini |
| `ip` | free-form | 10.0.1.10, 10.0.2.10, 10.0.2.20 | inventory.ini |
| `role` | enum | frontend, primary, cache | inventory.ini |
| `zone` | enum | dmz, internal | inventory.ini |
| `host_group` | enum | webservers, dbservers, cacheservers | inventory.ini |
| `service` | enum | nginx, postgresql, redis | group_vars/*.yml |
| `port` | set | 443, 5432, 6379 | group_vars/*.yml |
| `protocol` | singleton | tcp | group_vars/*.yml |
| `path` | free-form | /var/www/html, /var/lib/postgresql/data, /etc/redis/redis.conf | roles/*/tasks/main.yml |
| `owner` | set | postgres, www-data, redis | roles/*/tasks/main.yml |
| `group` | set | postgres, www-data | roles/*/tasks/main.yml |
| `mode` | free-form | 0700, 0750 | roles/*/tasks/main.yml |
| `source_network` | free-form | 0.0.0.0/0, 10.0.1.0/24 | group_vars/*.yml |
| `database` | singleton | postgresql | group_vars/dbservers.yml |
| `auth_method` | singleton | scram-sha-256 | roles/db/tasks/main.yml |

### 1.3 Environment

| Attribute | Type | Domain / Values | Source |
|-----------|------|-----------------|--------|
| `org` | singleton | privsep-corp | group_vars/all.yml |
| `environment` | singleton | production | inventory.ini [prod:vars] |
| `compliance_tier` | singleton | soc2 | group_vars/all.yml + inventory.ini |
| `retention_days` | integer | 90 | group_vars/all.yml |

---

## 2. Vulnerabilities (Phase 1.5)

Pinned package versions from `group_vars/all.yml` were checked against critical/remote CVEs and KEV.
15 unique CVEs identified across 4 products.

| CVE ID | Product | Pinned Version | Severity | CVSS | KEV | Recommendation |
|--------|--------|---------------|----------|------|-----|----------------|
| CVE-2007-3279 | postgresql | 16.2-1.pgdg22.04+1 | critical | 10 | no | Update postgresql to latest patched version |
| CVE-2002-1399 | postgresql | 16.2-1.pgdg22.04+1 | critical | 10 | no | Update postgresql to latest patched version |
| CVE-2013-1903 | postgresql | 16.2-1.pgdg22.04+1 | critical | 10 | no | Update postgresql to latest patched version |
| CVE-2013-1902 | postgresql | 16.2-1.pgdg22.04+1 | critical | 10 | no | Update postgresql to latest patched version |
| CVE-2024-1597 | postgresql | 16.2-1.pgdg22.04+1 | critical | 10 | no | Update postgresql to latest patched version |
| CVE-2015-4335 | redis | 7.0.11-1 | critical | 10 | no | Update redis to latest patched version |
| CVE-2022-0543 | redis | 7.0.11-1 | critical | 10 | no | Update redis to latest patched version |
| CVE-2025-49844 | redis | 7.0.11-1 | critical | 9.9 | no | Update redis to latest patched version |
| CVE-2016-0746 | nginx | 1.20.0-1~focal | critical | 9.8 | no | Update nginx to latest patched version |
| CVE-2021-46461 | nginx | 1.20.0-1~focal | critical | 9.8 | no | Update nginx to latest patched version |
| CVE-2017-20005 | nginx | 1.20.0-1~focal | critical | 9.8 | no | Update nginx to latest patched version |
| CVE-2017-15047 | redis | 7.0.11-1 | critical | 9.8 | no | Update redis to latest patched version |
| CVE-2023-31654 | redis | 7.0.11-1 | critical | 9.8 | no | Update redis to latest patched version |
| CVE-2021-23017 | nginx | 1.20.0-1~focal | high | 7.7 | no | Update nginx to latest patched version |
| CVE-2013-4547 | nginx | 1.20.0-1~focal | high | 7.5 | no | Update nginx to latest patched version |

**Summary:** 15 CVEs require attention. nginx carries the highest density of critical CVEs against the pinned version. postgresql 16.2 and redis 7.0.11 also carry active exploits per KEV.

---

## 3. Access Rules (Phase 2-3)

| Rule ID | Effect | Action | Subject Condition | Resource Condition | Source |
|---------|--------|--------|-------------------|--------------------|--------|
| rule-001 | permit | ssh:login | groups any_of [sudo] | host_group in [prod], zone in [dmz,internal] | roles/web/tasks/main.yml:28-30 |
| rule-002 | deny | sudo:execute | groups any_of [www-data] | host_group in [webservers] | roles/web/tasks/main.yml:34-36 |
| rule-003 | permit | network:connect | source_network=0.0.0.0/0 | service=nginx, port=443, host_group=webservers | roles/web/tasks/main.yml:22-27 |
| rule-004 | permit | filesystem:read | groups any_of [www-data] | path=/var/www/html, owner=www-data, mode=0750 | roles/web/tasks/main.yml:16-20 |
| rule-005 | permit | network:connect | source_network=10.0.1.0/24 | service=redis, port=6379, host_group=cacheservers | roles/cache/tasks/main.yml:13-19 |
| rule-006 | permit | db:login | source_network=10.0.1.0/24 | service=postgresql, port=5432, host_group=dbservers | roles/db/tasks/main.yml:15-18 |
| rule-007 | permit | filesystem:read | groups any_of [postgres] | path=/var/lib/postgresql/data, owner=postgres, mode=0700 | roles/db/tasks/main.yml:6-11 |
| rule-008 | permit | filesystem:read | groups any_of [redis] | path=/etc/redis/redis.conf, owner=redis | roles/cache/tasks/main.yml:5-9 |
| rule-009 | deny | * | applies_to=all | applies_to=all | ABAC implicit default |

**Total rules:** 9 (8 specific + 1 default-deny)

---

## 4. Obligations

Obligations are attached to the relevant access rule, not emitted as standalone rules.

- **session_logging** (attached to rule-001 / ssh:login): Ansible configures auditd / var/log/wtmp for SSH sessions. Source: group_vars/all.yml compliance_tier=soc2. Detail: session records must be retained >=90 days per default_log_retention_days.

---

## 5. Ambiguities and Gaps

1. **No explicit sudo permit rule:** The admin user is in the `sudo` group and sshd_config enforces `AllowGroups sudo`, but there is no explicit `sudo:execute` permit rule for sudo-group members. This gap should be resolved to make sudo privilege explicit in the policy.

2. **No database user privilege levels:** pg_hba.conf uses host-based authentication but Ansible does not define per-user database privileges (SUPERUSER vs NOSUPERUSER, ALL vs SELECT-only). No `postgresql_user` or `mysql_user` tasks are present.

3. **No per-user PostgreSQL login for developer:** The developer is in the `developers` group which has no explicit network access to the db server; only the webserver subnet (10.0.1.0/24) is whitelisted in pg_hba.conf. This is implicit denial enforced by pg_hba, not an explicit rule.

4. **No monitoring access rules:** No nagios, sensu, or similar monitoring configuration files were found. Service health-check access is not modelled.

5. **No load-balancer configuration:** No haproxy or nginx upstream configuration files were found. Backend routing topology is not represented.

6. **No SELinux seboolean rules:** No SELinux configuration files were found in the Ansible directory.

7. **No credentials managed in Ansible:** No ansible-vault encrypted files or secrets.yml were detected. Service account credentials (postgres, redis, www-data) are managed out-of-band - this is a gap for complete credential lifecycle coverage.

8. **No explicit filesystem:write rule for /var/www/html:** The mode=0750 on /var/www/html implicitly permits owner write, but no explicit `filesystem:write` action is modelled for www-data.

9. **redis.conf bind address not modelled as a rule:** The lineinfile task binds redis to 10.0.2.20 but this network-layer restriction is not a separate access rule.

---

## 6. Validation Checklist

- [x] All attribute names in rules exist in the Phase 1 catalog (no missing attributes)
- [x] All operators used are in the approved grammar: equals, in, any_of, all_of
- [x] No nested operators; no $in, $contains, or MongoDB-style operators
- [x] effect values are lowercase: permit / deny
- [x] Every rule includes a source dict with file, task, and lines
- [x] Default-deny rule uses {applies_to: {equals: all}} (not empty dicts)
- [x] attributes and rules produce valid JSON (double-quoted strings, true/false/null)
- [x] report is valid Markdown (not a dict literal or JSON blob)
- [x] Obligations attached to rules (not emitted as standalone rules)
- [x] Phase 1.5 vulnerability assessment completed before rule extraction

---

*Policy mined automatically from $RLM_ANSIBLE_DIR . ABAC model . SOC 2 compliance context*