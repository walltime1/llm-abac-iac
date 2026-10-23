# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:20:33_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 12 | Rules: 14_  
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
    "clearance_levels": {
      "values": [
        "confidential",
        "secret"
      ],
      "domain": [
        "confidential",
        "secret",
        "top_secret"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "values": [
        "operations",
        "engineering",
        "data"
      ],
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    }
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
        "source": "group_vars/dbservers.yml"
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
        "label": "AppServers subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "Internet",
        "source": "group_vars/dmz.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "segcorp",
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
    "log_retention_days": {
      "value": 365,
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
    "description": "Allow SSH login on application servers for sudo and developers groups",
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
      },
      "role": {
        "equals": "application"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        24,
        28
      ]
    }
  },
  {
    "id": "rule-002",
    "description": "Allow SSH login on database servers for sudo and dba groups",
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
      },
      "role": {
        "equals": "primary"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        41,
        45
      ]
    }
  },
  {
    "id": "rule-003",
    "description": "Allow SSH login on DMZ servers for sudo group only",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "role": {
        "equals": "reverse_proxy"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        30,
        34
      ]
    }
  },
  {
    "id": "rule-004",
    "description": "Allow network connection to application port 8080 from DMZ subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 8080
      },
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        16,
        22
      ]
    }
  },
  {
    "id": "rule-005",
    "description": "Allow network connection to PostgreSQL from appservers subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        35,
        39
      ]
    }
  },
  {
    "id": "rule-006",
    "description": "Allow network connection to nginx HTTPS from internet",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        22,
        28
      ]
    }
  },
  {
    "id": "rule-007",
    "description": "Allow database SUPERUSER login for DBA group",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "role": {
        "equals": "primary"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        21,
        26
      ]
    }
  },
  {
    "id": "rule-008",
    "description": "Allow database read-only (NOSUPERUSER) login for developers group",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "role": {
        "equals": "primary"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        28,
        33
      ]
    }
  },
  {
    "id": "rule-009",
    "description": "Allow user provisioning on application servers for developers and sudo groups",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        7,
        14
      ]
    }
  },
  {
    "id": "rule-010",
    "description": "Allow admin user provisioning on DMZ servers for sudo group only",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        13,
        20
      ]
    }
  },
  {
    "id": "rule-011",
    "description": "Default deny all access not explicitly permitted",
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
      "file": "implicit",
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
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
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
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
    "source_product": "nginx",
    "pinned_version": "1.20.0",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.20.0 is not affected by CVE-2016-0746. Monitor for updates.",
    "cvss_score": 9.8,
    "title": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS r"
  },
  {
    "cve_id": "CVE-2021-46461",
    "source_product": "nginx",
    "pinned_version": "1.20.0",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.20.0 is not affected by CVE-2021-46461. Monitor for updates.",
    "cvss_score": 9.8,
    "title": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof i"
  },
  {
    "cve_id": "CVE-2017-20005",
    "source_product": "nginx",
    "pinned_version": "1.20.0",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.20.0 is not affected by CVE-2017-20005. Monitor for updates.",
    "cvss_score": 9.8,
    "title": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modific"
  },
  {
    "cve_id": "CVE-2021-23017",
    "source_product": "nginx",
    "pinned_version": "1.20.0",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from 1.20.0 to latest patched version. CVE CVE-2021-23017 affects this version.",
    "cvss_score": 7.7,
    "title": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, lett"
  },
  {
    "cve_id": "CVE-2013-4547",
    "source_product": "nginx",
    "pinned_version": "1.20.0",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.20.0 is not affected by CVE-2013-4547. Monitor for updates.",
    "cvss_score": 7.5,
    "title": "nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 contain a restriction bypass caused by unescaped s"
  },
  {
    "cve_id": "CVE-2023-44487",
    "source_product": "nginx",
    "pinned_version": "1.20.0",
    "vuln_type": "kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from 1.20.0 to latest patched version. CVE CVE-2023-44487 affects this version.",
    "cvss_score": 7.5,
    "title": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many "
  },
  {
    "cve_id": "CVE-2009-3555",
    "source_product": "nginx",
    "pinned_version": "1.20.0",
    "vuln_type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 1.20.0 is not affected by CVE-2009-3555. Monitor for updates.",
    "cvss_score": 5.8,
    "title": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4,"
  },
  {
    "cve_id": "CVE-2003-0786",
    "source_product": "openssh",
    "pinned_version": "9.1p1",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.1p1 is not affected by CVE-2003-0786. Monitor for updates.",
    "cvss_score": 10,
    "title": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 P"
  },
  {
    "cve_id": "CVE-2000-0999",
    "source_product": "openssh",
    "pinned_version": "9.1p1",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.1p1 is not affected by CVE-2000-0999. Monitor for updates.",
    "cvss_score": 10,
    "title": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities cau"
  },
  {
    "cve_id": "CVE-2000-0525",
    "source_product": "openssh",
    "pinned_version": "9.1p1",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.1p1 is not affected by CVE-2000-0525. Monitor for updates.",
    "cvss_score": 10,
    "title": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege manag"
  },
  {
    "cve_id": "CVE-2001-0144",
    "source_product": "openssh",
    "pinned_version": "9.1p1",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.1p1 is not affected by CVE-2001-0144. Monitor for updates.",
    "cvss_score": 10,
    "title": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calc"
  },
  {
    "cve_id": "CVE-2003-0693",
    "source_product": "openssh",
    "pinned_version": "9.1p1",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.1p1 is not affected by CVE-2003-0693. Monitor for updates.",
    "cvss_score": 10,
    "title": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect mem"
  },
  {
    "cve_id": "CVE-2023-38408",
    "source_product": "openssh",
    "pinned_version": "9.1p1",
    "vuln_type": "kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 9.1p1 to latest patched version. CVE CVE-2023-38408 affects this version.",
    "cvss_score": 9.8,
    "title": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search"
  },
  {
    "cve_id": "CVE-2024-6387",
    "source_product": "openssh",
    "pinned_version": "9.1p1",
    "vuln_type": "kev",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 9.1p1 to latest patched version. CVE CVE-2024-6387 affects this version.",
    "cvss_score": 8.1,
    "title": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthen"
  },
  {
    "cve_id": "CVE-2007-4752",
    "source_product": "openssh",
    "pinned_version": "9.1p1",
    "vuln_type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.1p1 is not affected by CVE-2007-4752. Monitor for updates.",
    "cvss_score": 7.5,
    "title": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies,"
  },
  {
    "cve_id": "CVE-2019-6110",
    "source_product": "openssh",
    "pinned_version": "9.1p1",
    "vuln_type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.1p1 is not affected by CVE-2019-6110. Monitor for updates.",
    "cvss_score": 6.8,
    "title": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from"
  },
  {
    "cve_id": "CVE-2019-6109",
    "source_product": "openssh",
    "pinned_version": "9.1p1",
    "vuln_type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 9.1p1 is not affected by CVE-2019-6109. Monitor for updates.",
    "cvss_score": 6.8,
    "title": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the p"
  },
  {
    "cve_id": "CVE-2007-3279",
    "source_product": "postgresql",
    "pinned_version": "16.2",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.2 is not affected by CVE-2007-3279. Monitor for updates.",
    "cvss_score": 10,
    "title": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing"
  },
  {
    "cve_id": "CVE-2002-1399",
    "source_product": "postgresql",
    "pinned_version": "16.2",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.2 is not affected by CVE-2002-1399. Monitor for updates.",
    "cvss_score": 10,
    "title": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerabi"
  },
  {
    "cve_id": "CVE-2013-1903",
    "source_product": "postgresql",
    "pinned_version": "16.2",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.2 is not affected by CVE-2013-1903. Monitor for updates.",
    "cvss_score": 10,
    "title": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17"
  },
  {
    "cve_id": "CVE-2013-1902",
    "source_product": "postgresql",
    "pinned_version": "16.2",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.2 is not affected by CVE-2013-1902. Monitor for updates.",
    "cvss_score": 10,
    "title": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary file"
  },
  {
    "cve_id": "CVE-2024-1597",
    "source_product": "postgresql",
    "pinned_version": "16.2",
    "vuln_type": "critical_remote",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.2 is not affected by CVE-2024-1597. Monitor for updates.",
    "cvss_score": 10,
    "title": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 co"
  },
  {
    "cve_id": "CVE-2019-9193",
    "source_product": "postgresql",
    "pinned_version": "16.2",
    "vuln_type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.2 is not affected by CVE-2019-9193. Monitor for updates.",
    "cvss_score": 7.2,
    "title": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM P"
  },
  {
    "cve_id": "CVE-2022-31197",
    "source_product": "postgresql",
    "pinned_version": "16.2",
    "vuln_type": "kev",
    "affects_pinned_version": false,
    "recommendation": "Pinned version 16.2 is not affected by CVE-2022-31197. Monitor for updates.",
    "cvss_score": 7.1,
    "title": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescape"
  }
]
```

## Report

# ABAC Policy Report — SegCorp PCI Production Environment

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the
Ansible configuration rooted at `$RLM_ANSIBLE_DIR`. The configuration manages a
three-tier architecture (DMZ → AppServers → DBServers) in a **PCI-compliant
production** environment under the **segcorp** organization.

**Scope**: `policy_goal = all` (full coverage: ssh, sudo, db-access, firewall, filesystem)

**Statistics**:
- Subjects: 3 users, 3 groups
- Resources: 3 hosts, 3 services, 1 managed path, 3 network zones
- Rules: 10 permit rules + 1 default-deny rule
- Vulnerabilities: 24 CVEs scanned, 4 affecting pinned versions

## Attribute Catalog

### Subjects
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

**Groups**: `sudo`, `developers`, `dba`
**Clearance levels**: confidential, secret
**Departments**: operations, engineering, data

### Resources
| Host | IP | Role | Zone | Group |
|------|----|------|------|-------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

**Services**: nginx (443/tcp, dmz), app (8080/tcp, appservers), postgresql (5432/tcp, dbservers)
**Managed paths**: `/var/lib/postgresql/data` (owner=postgres, group=postgres, mode=0700)

### Environment
- **Organization**: segcorp
- **Environment**: production
- **Compliance tier**: pci
- **Log retention**: 365 days

## Rule Summary

| ID | Action | Subject | Resource | Effect |
|----|--------|---------|----------|--------|
| rule-001 | ssh:login | groups ∈ {sudo, developers} | zone=app | permit |
| rule-002 | ssh:login | groups ∈ {sudo, dba} | zone=data | permit |
| rule-003 | ssh:login | groups ∈ {sudo} | zone=dmz | permit |
| rule-004 | network:connect | source=10.0.1.0/24 | port=8080, zone=app | permit |
| rule-005 | network:connect | source=10.0.2.0/24 | port=5432, zone=data | permit |
| rule-006 | network:connect | source=0.0.0.0/0 | port=443, zone=dmz | permit |
| rule-007 | db:login (SUPERUSER) | groups ∈ {dba} | port=5432 | permit |
| rule-008 | db:login (NOSUPERUSER) | groups ∈ {developers} | port=5432 | permit |
| rule-009 | user:create | groups ∈ {sudo, developers} | zone=app | permit |
| rule-010 | user:create | groups ∈ {sudo} | zone=dmz | permit |
| rule-011 | * (all) | all | all | deny |

## Vulnerability Assessment

### Pinned Versions
| Package | Pinned Version | Affected CVEs |
|---------|---------------|---------------|
| nginx | 1.20.0 | CVE-2021-23017, CVE-2023-44487 |
| openssh | 9.1p1 | CVE-2023-38408, CVE-2024-6387 |
| postgresql | 16.2 | None (all found CVEs target older versions or JDBC driver) |

### Critical Findings
1. **CVE-2024-6387 (regreSSHion)** — OpenSSH < 9.8p1. RCE via signal handler race condition. 
   **Recommendation**: Upgrade openssh-server from 9.1p1 to ≥ 9.8p1 immediately.
2. **CVE-2023-38408** — OpenSSH < 9.3p2. Remote code execution via pkcs11.
   **Recommendation**: Upgrade openssh-server to ≥ 9.3p2.
3. **CVE-2021-23017** — nginx < 1.21.0. Resolver 1-byte memory overwrite.
   **Recommendation**: Upgrade nginx from 1.20.0 to ≥ 1.21.0.
4. **CVE-2023-44487** — HTTP/2 rapid reset DoS.
   **Recommendation**: Upgrade nginx to ≥ 1.25.3 or apply mitigation.

## Ambiguities and Notes

- **No sudoers configuration found**: The Ansible playbooks do not deploy explicit sudoers rules.
  The `sudo` group membership implies sudo access via the default `/etc/sudoers` on Ubuntu,
  but no explicit `sudo:execute` ABAC rule could be extracted from the configuration files.
- **PostgreSQL pg_hba.conf uses lineinfile**: The `pg_hba.conf` rule is templated via
  `ansible.builtin.lineinfile` looping over `db_allow_from`. The implicit deny-default
  of pg_hba.conf (reject if no match) is noted but not emitted as a separate DENY rule
  since it is a PostgreSQL internal default, not an explicit Ansible-managed deny entry.
- **Filesystem permissions**: The PostgreSQL data directory (`/var/lib/postgresql/data`)
  is set to mode `0700` (owner-only). The owner is the system user `postgres`, which is
  not in the Ansible user catalog. No cataloged subject has explicit filesystem access;
  this is enforced by the POSIX permission model and covered by the default-deny rule.
- **No SELinux or iptables explicit rules**: The configuration uses `firewalld` modules
  rather than raw iptables or SELinux booleans.
- **Credentials**: Database authentication uses `scram-sha-256` (pg_hba.conf). No
  plaintext passwords are visible in the Ansible configuration.
- **SSH key management**: Not observed in the current configuration.
