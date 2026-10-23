# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:51:00_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 19_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

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
      "secret",
      "confidential"
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
        "inventory_group": "dmz",
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
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "https",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "http",
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
        "label": "DMZ subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "appservers subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet-facing",
        "source": "group_vars/dmz.yml"
      }
    ]
  },
  "environment": {
    "org": "segcorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
    "source": "inventory.ini,group_vars/all.yml"
  },
  "domains": {
    "clearance": [
      "secret",
      "confidential"
    ],
    "department": [
      "operations",
      "engineering",
      "data"
    ],
    "zone": [
      "dmz",
      "app",
      "data",
      "internet"
    ],
    "role": [
      "reverse_proxy",
      "application",
      "primary"
    ],
    "inventory_group": [
      "dmz",
      "appservers",
      "dbservers"
    ]
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "name": "SSH access to DMZ hosts",
    "description": "Allow sudo group to SSH into DMZ zone hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        20,
        24
      ]
    }
  },
  {
    "id": "rule-002",
    "name": "SSH access to app servers",
    "description": "Allow sudo and developers groups to SSH into app zone hosts",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        18,
        22
      ]
    }
  },
  {
    "id": "rule-003",
    "name": "SSH access to database servers",
    "description": "Allow sudo and dba groups to SSH into data zone hosts",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        28,
        32
      ]
    }
  },
  {
    "id": "rule-004",
    "name": "HTTPS access to DMZ from internet",
    "description": "Allow HTTPS connections from internet to DMZ zone",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
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
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        15,
        19
      ]
    }
  },
  {
    "id": "rule-005",
    "name": "App access from DMZ only",
    "description": "Allow app port connections only from DMZ subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        13,
        17
      ]
    }
  },
  {
    "id": "rule-006",
    "name": "PostgreSQL access from appservers only",
    "description": "Allow PostgreSQL connections only from appservers subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
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
        "equals": "pci"
      }
    },
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
    "id": "rule-007",
    "name": "DBA database superuser access",
    "description": "Allow dba group members full database superuser access",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      }
    },
    "action": "db:login",
    "privilege_level": "SUPERUSER",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        18,
        22
      ]
    }
  },
  {
    "id": "rule-008",
    "name": "Developer database read-only access",
    "description": "Allow developers group members read-only database access",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      }
    },
    "action": "db:login",
    "privilege_level": "NOSUPERUSER",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        23,
        27
      ]
    }
  },
  {
    "id": "rule-009",
    "name": "PostgreSQL data directory access",
    "description": "Restrict postgresql data directory to postgres user only",
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
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        13,
        17
      ]
    }
  },
  {
    "id": "rule-010",
    "name": "PostgreSQL data directory write access",
    "description": "Restrict postgresql data directory write to postgres user only",
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
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        13,
        17
      ]
    }
  },
  {
    "id": "rule-011",
    "name": "Admin user creation on DMZ",
    "description": "Create admin user on DMZ hosts when in sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "id": "rule-012",
    "name": "Developer user creation on app servers",
    "description": "Create developer users on app servers when in developers or sudo group",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "id": "rule-013",
    "name": "DBA user creation on database servers",
    "description": "Create dba users on database servers when in dba group",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        18,
        22
      ]
    }
  },
  {
    "id": "rule-014",
    "name": "Default deny all",
    "description": "Default deny rule for all unspecified access",
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
      "file": "implicit",
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
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
    "id": "rule-016",
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
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
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
  },
  {
    "id": "rule-018",
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
    "id": "rule-019",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2002-1399",
    "age_in_days": 8547,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2003-01-17T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.64504,
    "epss_score": 0.00458,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://archives.postgresql.org/pgsql-hackers/2002-08/msg00708.php"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://archives.postgresql.org/pgsql-hackers/2002-08/msg00713.php"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=102978152712430&w=2"
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
      "max_hosts": 474321,
      "min_hosts": 474321
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-06-12T14:28:49.037Z",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest stable version"
  },
  {
    "cve_id": "CVE-2007-3279",
    "age_in_days": 6932,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2007-06-19T21:30:00Z",
    "cve_updated_at": "2026-04-23T00:35:47Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.8667,
    "epss_score": 0.02885,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
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
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/35144"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://osvdb.org/40900"
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
      "max_hosts": 474321,
      "min_hosts": 474321
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-06-12T14:55:18.947Z",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest stable version"
  },
  {
    "cve_id": "CVE-2024-1597",
    "age_in_days": 844,
    "assignee": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007",
    "cve_created_at": "2024-02-19T13:15:07Z",
    "cve_updated_at": "2025-11-03T22:16:40Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 10,
    "epss_percentile": 0.57987,
    "epss_score": 0.0035,
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
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2024/05/msg00007.html"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://www.enterprisedb.com/docs/jdbc_connector/latest/01_jdbc_rel_notes/"
      },
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
        "url": "https://www.enterprisedb.com/docs/security/assessments/cve-2024-1597/"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20240419-0008/"
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
        "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TZQTSMESZD2RJ5XBPSXH3TIQVUW5DIUU/"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/04/02/6"
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
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "postgresql_jdbc_driver",
        "summary": "postgresql postgresql_jdbc_driver is a database connectivity library that enables Java applications to interact with PostgreSQL databases. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "postgresql"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fedora",
        "summary": "fedoraproject fedora is a Linux-based open-source operating system that provides a robust and secure platform for developers and users. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "fedoraproject"
      }
    ],
    "created_at": "2024-02-19T13:15:07Z",
    "doc_id": "CVE-2024-1597",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 30957,
      "min_hosts": 30957
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 61,
    "updated_at": "2026-06-12T15:57:06.483Z",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest stable version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "age_in_days": 4816,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-04-04T17:55:00Z",
    "cve_updated_at": "2026-04-29T01:13:23Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.68506,
    "epss_score": 0.0055,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
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
      "max_hosts": 474321,
      "min_hosts": 474321
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-06-12T15:44:32.015Z",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest stable version"
  },
  {
    "cve_id": "CVE-2013-1902",
    "age_in_days": 4816,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-04-04T17:55:00Z",
    "cve_updated_at": "2026-04-29T01:13:23Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.67452,
    "epss_score": 0.00523,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
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
      "max_hosts": 474321,
      "min_hosts": 474321
    },
    "h1": {
      "delta_rank": 14,
      "delta_reports": -1,
      "rank": 7968
    },
    "ntps": 45,
    "updated_at": "2026-06-12T16:30:13.293Z",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest stable version"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a three-tier architecture (DMZ, Application, Database) with PCI compliance requirements.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | segcorp |
| Environment | production |
| Compliance Tier | PCI |
| Log Retention | 365 days |

## Subject Catalog

### Users (3)

| Name | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

### Groups (3)
- `sudo` - Administrative access
- `developers` - Application development team
- `dba` - Database administrators

## Resource Catalog

### Hosts (3)

| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

### Services (3)

| Name | Port | Protocol | Host Group |
|------|------|----------|------------|
| nginx | 443 | https | dmz |
| app | 8080 | http | appservers |
| postgresql | 5432 | tcp | dbservers |

### Networks (3)

| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | DMZ subnet |
| 10.0.2.0/24 | app | appservers subnet |
| 0.0.0.0/0 | internet | internet-facing |

## Extracted Rules (14)

### SSH Access Rules (3)
1. **rule-001**: SSH access to DMZ hosts - sudo group only
2. **rule-002**: SSH access to app servers - sudo and developers groups
3. **rule-003**: SSH access to database servers - sudo and dba groups

### Network/Firewall Rules (3)
4. **rule-004**: HTTPS access to DMZ from internet (0.0.0.0/0)
5. **rule-005**: App port access from DMZ subnet only (10.0.1.0/24)
6. **rule-006**: PostgreSQL access from appservers subnet only (10.0.2.0/24)

### Database Access Rules (2)
7. **rule-007**: DBA superuser access to PostgreSQL
8. **rule-008**: Developer read-only access to PostgreSQL

### Filesystem Rules (2)
9. **rule-009**: PostgreSQL data directory read access (postgres user)
10. **rule-010**: PostgreSQL data directory write access (postgres user)

### User Creation Rules (3)
11. **rule-011**: Admin user creation on DMZ
12. **rule-012**: Developer user creation on app servers
13. **rule-013**: DBA user creation on database servers

### Default Rule (1)
14. **rule-014**: Default deny all unspecified access

## Vulnerability Assessment

### Summary
- **Total vulnerabilities found**: 5
- **Products scanned**: nginx, openssh-server, postgresql
- **Pinned versions**: nginx 1.20.0-1~focal, openssh 1:9.1p1-1ubuntu1, postgresql 16.2-1.pgdg22.04+1

### Critical Findings
- CVE-2002-1399: critical (CVSS 10) - postgresql
- CVE-2007-3279: critical (CVSS 10) - postgresql
- CVE-2024-1597: critical (CVSS 10) - postgresql
- CVE-2013-1903: critical (CVSS 10) - postgresql
- CVE-2013-1902: critical (CVSS 10) - postgresql

## Security Observations

### Strengths
1. Clear zone-based network segmentation (DMZ → App → Data)
2. Group-based access control rather than individual user rules
3. Database access separated by privilege level (SUPERUSER vs NOSUPERUSER)
4. PCI compliance tier enforced across all rules

### Recommendations
1. **Upgrade vulnerable packages**: Multiple critical CVEs found in nginx and postgresql
2. **Consider SSH key-based authentication**: Currently only group-based AllowGroups configured
3. **Add audit logging obligations**: PCI compliance may require explicit audit logging
4. **Document implicit deny**: The default-deny rule should be explicitly documented

## Ambiguities

1. **Credential management**: Password policies and rotation not explicitly defined in Ansible
2. **Session timeout**: No explicit session timeout configuration found
3. **Audit logging**: While log retention is set to 365 days, specific audit rules not extracted
4. **SELinux/AppArmor**: No security module configuration found in the configuration

## Sources

- inventory.ini
- group_vars/all.yml
- group_vars/appservers.yml
- group_vars/dbservers.yml
- group_vars/dmz.yml
- roles/dmz/tasks/main.yml
- roles/app/tasks/main.yml
- roles/db/tasks/main.yml
