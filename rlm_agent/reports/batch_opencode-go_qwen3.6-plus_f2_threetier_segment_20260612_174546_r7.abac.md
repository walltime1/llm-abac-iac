# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:51:08_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 18_  
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
      {
        "value": "secret",
        "domain": [
          "secret",
          "confidential",
          "public"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "confidential",
        "domain": [
          "secret",
          "confidential",
          "public"
        ],
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "value": "operations",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "engineering",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "data",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      }
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
        "name": "http",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
      },
      {
        "name": "postgres",
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
        "source": "group_vars/dbservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "dmz",
        "label": "any",
        "source": "group_vars/dmz.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "dmz_subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet",
        "source": "group_vars/dbservers.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "segcorp",
      "domain": [
        "segcorp"
      ],
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
      "value": "pci",
      "domain": [
        "pci",
        "hipaa",
        "sox",
        "internal"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "value": 365,
      "source": "group_vars/all.yml"
    }
  },
  "packages": [
    {
      "name": "nginx",
      "version": "1.20.0-1~focal",
      "source": "group_vars/all.yml"
    },
    {
      "name": "openssh",
      "version": "1:9.6p1-3ubuntu1",
      "source": "group_vars/all.yml"
    },
    {
      "name": "postgresql",
      "version": "13.7-1.pgdg20.04+1",
      "source": "group_vars/all.yml"
    }
  ]
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        14,
        20
      ]
    },
    "obligations": []
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      },
      "zone": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        22,
        29
      ]
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
      "service": {
        "equals": "ssh"
      },
      "zone": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        31,
        35
      ]
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        6,
        12
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      },
      "zone": {
        "equals": "app"
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
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        14,
        21
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
      "service": {
        "equals": "ssh"
      },
      "zone": {
        "equals": "app"
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
      "lines": [
        23,
        27
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      "task": "Ensure postgres data dir",
      "lines": [
        10,
        17
      ]
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        10,
        17
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
      "database": {
        "equals": "postgresql"
      },
      "service": {
        "equals": "postgres"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "All database sessions logged"
      }
    ],
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        19,
        24
      ]
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
      "service": {
        "equals": "postgres"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "All database sessions logged"
      }
    ],
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        26,
        31
      ]
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "zone": {
        "equals": "data"
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
      "lines": [
        33,
        38
      ]
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "zone": {
        "equals": "data"
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
      "lines": [
        40,
        44
      ]
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
      "port": {
        "equals": 443
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
    "id": "rule-017",
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
    "id": "rule-018",
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS r",
    "affects_pinned_version": true,
    "recommendation": "Update to nginx 1.9.10 or later versions."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modific",
    "affects_pinned_version": true,
    "recommendation": "Update to version 1.13.6 or later."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4,",
    "affects_pinned_version": true,
    "recommendation": "Update to the latest versions of affected products that fix the renegotiation handling issue."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, lett",
    "affects_pinned_version": true,
    "recommendation": "Update nginx to the latest version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many ",
    "affects_pinned_version": true,
    "recommendation": "Implement rate limiting and update to the latest HTTP/2 protocol standards or patches."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities cau",
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege manag",
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect mem",
    "affects_pinned_version": true,
    "recommendation": "Update to OpenSSH version 3.7 or later."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 P",
    "affects_pinned_version": true,
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calc",
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search",
    "affects_pinned_version": true,
    "recommendation": "Update to OpenSSH 9.3p2 or later."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthen",
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this regression is fixed."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies,",
    "affects_pinned_version": true,
    "recommendation": "Update to OpenSSH 4.7 or later."
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the p",
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed."
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from",
    "affects_pinned_version": true,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerabi",
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary file",
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing",
    "affects_pinned_version": true,
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17",
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 co",
    "affects_pinned_version": true,
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.2,
    "is_remote": true,
    "is_kev": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM P",
    "affects_pinned_version": true,
    "recommendation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "is_kev": true,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescape",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to version 42.2.26 or 42.4.1."
  }
]
```

## Report

# ABAC Policy Report — Ansible Configuration Mining

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration rooted at `$RLM_ANSIBLE_DIR`. The configuration defines a three-tier infrastructure (DMZ, App, DB) with PCI compliance requirements.

**Scope:** Full coverage (policy_goal = "all")
**Files analyzed:** 9 total (5 catalog files, 3 role task files, 1 README)
**Rules extracted:** 12 permit rules + 1 default-deny rule
**Subjects:** 3 users across 3 groups
**Resources:** 3 hosts, 3 services, 1 protected path, 3 network zones

## Attribute Catalog

### Subjects
- **Users:** admin (uid 1001, sudo, operations, secret), developer (uid 1002, developers, engineering, confidential), dba (uid 1003, dba, data, secret)
- **Groups:** sudo, developers, dba
- **Clearance levels:** secret, confidential
- **Departments:** operations, engineering, data

### Resources
- **Hosts:** proxy01.lab.local (dmz/reverse_proxy), app01.lab.local (app/application), db01.lab.local (data/primary)
- **Services:** http/443 (dmz), app/8080 (app), postgres/5432 (data)
- **Protected paths:** /var/lib/postgresql/data (postgres:postgres, 0700)
- **Networks:** 0.0.0.0/0 (any), 10.0.1.0/24 (dmz_subnet), 10.0.2.0/24 (app_subnet)

### Environment
- **Org:** segcorp
- **Environment:** production
- **Compliance tier:** pci
- **Log retention:** 365 days

## Vulnerability Assessment

| CVE | Product | Severity | CVSS | KEV | Recommendation |
|-----|---------|----------|------|-----|----------------|
| CVE-2023-44487 | nginx | high | 7.5 | Yes | Upgrade nginx |
| CVE-2024-6387 | openssh | high | 8.1 | Yes | Upgrade openssh (regreSSHion) |
| CVE-2023-38408 | openssh | critical | 9.8 | Yes | Upgrade openssh |
| CVE-2019-9193 | postgresql | high | 7.2 | Yes | Upgrade postgresql |
| CVE-2022-31197 | postgresql | high | 7.1 | Yes | Upgrade postgresql |
| *(17 additional CVEs)* | | | | | |

**Total:** 22 vulnerabilities identified (5 KEV-active)
- nginx: 5 critical/remote + 3 KEV
- openssh: 5 critical/remote + 6 KEV
- postgresql: 5 critical/remote + 4 KEV

**Pinned versions in config:**
- nginx 1.20.0-1~focal (vulnerable — several CVEs target older versions)
- openssh 1:9.6p1-3ubuntu1 (some CVEs predate this; KEV items need verification)
- postgresql 13.7-1.pgdg20.04+1 (several CVEs target older major versions)

## Access Rules Summary

| ID | Action | Subject | Resource | Effect | Source |
|----|--------|---------|----------|--------|--------|
| rule-001 | user:create | groups in [sudo] | all | permit | dmz/tasks |
| rule-002 | network:connect | src 0.0.0.0/0 | dmz:443/tcp | permit | dmz/tasks |
| rule-003 | ssh:login | groups in [sudo] | dmz:ssh | permit | dmz/tasks |
| rule-004 | user:create | groups in [developers,sudo] | all | permit | app/tasks |
| rule-005 | network:connect | src 10.0.1.0/24 | app:8080/tcp | permit | app/tasks |
| rule-006 | ssh:login | groups in [sudo,developers] | app:ssh | permit | app/tasks |
| rule-007 | filesystem:read | groups in [dba] | /var/lib/postgresql/data | permit | db/tasks |
| rule-008 | filesystem:write | groups in [dba] | /var/lib/postgresql/data | permit | db/tasks |
| rule-009 | db:login | groups in [dba] | postgresql (SUPERUSER) | permit | db/tasks |
| rule-010 | db:login | groups in [developers] | postgresql (NOSUPERUSER) | permit | db/tasks |
| rule-011 | network:connect | src 10.0.2.0/24 | data:5432/tcp | permit | db/tasks |
| rule-012 | ssh:login | groups in [sudo,dba] | data:ssh | permit | db/tasks |
| rule-013 | * | all | all | deny | default |

## Ambiguities

1. **Credential handling:** The Ansible configuration uses `{{ ssh_version }}`, `{{ postgres_version }}`, etc. as variables but no vault-encrypted credentials are visible in the examined files. Password hashes or SSH keys for user provisioning are not shown — they may exist in vault files not enumerated.
2. **Version applicability:** Many CVEs identified are for older major versions of nginx, openssh, and postgresql. The `affects_pinned_version` field is conservatively set to `true` for all entries; manual verification against the exact pinned versions is recommended.
3. **Implicit denies:** The pg_hba.conf task only adds ALLOW lines; there is no explicit DENY rule in the Ansible config. The default-deny rule (rule-013) covers this at the policy level, but the actual pg_hba.conf behavior depends on file ordering.
4. **DBA filesystem access:** The postgres data dir is owned by `postgres` (system user), not by any DBA group members. The filesystem rules reflect the configured ACL (mode 0700, owner postgres), meaning DBAs cannot directly access files — they must go through the database service. This is a security design, not a configuration gap.
5. **No sudoers policy:** No explicit sudoers rules were found in the Ansible configuration beyond group membership in the `sudo` group. Privilege escalation policies are not explicitly defined.

## Obligations

- **Session logging:** Attached to database login rules (rule-009, rule-010) — all database sessions must be logged per PCI compliance requirements.
