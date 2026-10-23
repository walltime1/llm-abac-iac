# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:33:24_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 16 | Rules: 18_  
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
        "clearance": "secret",
        "department": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "group_vars/all.yml"
      },
      {
        "name": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "clearance": "secret",
        "department": "data",
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
      "source": "group_vars/all.yml",
      "domain": [
        "confidential",
        "secret"
      ]
    },
    "departments": {
      "values": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml",
      "domain": [
        "operations",
        "engineering",
        "data"
      ]
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
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all",
        "source": "roles/app/tasks/main.yml"
      },
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
        "source": "roles/db/tasks/main.yml"
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "sshd",
        "source": "roles/app/tasks/main.yml"
      },
      {
        "path": "/etc/postgresql/pg_hba.conf",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0640",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "dmz_subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "appservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "dbservers_subnet",
        "source": "inventory.ini"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "group_vars/dmz.yml"
      }
    ]
  },
  "environment": {
    "org": "segcorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
    "domain": {
      "org": [
        "segcorp"
      ],
      "environment": [
        "production"
      ],
      "compliance_tier": [
        "pci"
      ]
    },
    "source": "inventory.ini, group_vars/all.yml"
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
      "hostname": {
        "equals": "app01.lab.local"
      },
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
        22,
        26
      ]
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
      "hostname": {
        "equals": "db01.lab.local"
      },
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
      "task": "Restrict SSH to sudo group",
      "lines": [
        33,
        37
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
      "hostname": {
        "equals": "proxy01.lab.local"
      },
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
        22,
        26
      ]
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
      "host_group": {
        "equals": "appservers"
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
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall - allow app port from DMZ only",
      "lines": [
        14,
        20
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
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
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall - allow HTTPS from internet",
      "lines": [
        14,
        20
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      },
      "port": {
        "equals": 5432
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
      "lines": [
        19,
        23
      ]
    },
    "obligations": [
      {
        "type": "audit",
        "description": "SUPERUSER privileges granted - log all admin actions"
      }
    ]
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      },
      "port": {
        "equals": 5432
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
      "task": "Create DB read-only role for developers",
      "lines": [
        25,
        29
      ]
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "host_group": {
        "equals": "dbservers"
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
        31,
        35
      ]
    }
  },
  {
    "id": "rule-009",
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
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        13,
        18
      ]
    }
  },
  {
    "id": "rule-010",
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
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        13,
        18
      ]
    }
  },
  {
    "id": "rule-011",
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
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        13,
        18
      ]
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "user": {
        "any_of": [
          "admin",
          "developer",
          "dba"
        ]
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
    "effect": "deny",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        13,
        18
      ]
    }
  },
  {
    "id": "rule-013",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
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
        7,
        12
      ]
    }
  },
  {
    "id": "rule-014",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
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
        7,
        12
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
      "file": "default",
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
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
      "host_group": {
        "equals": "appservers"
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
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
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
    "id": "rule-018",
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
      "host_group": {
        "equals": "dbservers"
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
    "cve_id": "CVE-2021-46461",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "NGINX njs - Buffer Overflow",
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit requires crafted input.",
    "is_kev": false,
    "is_poc": true,
    "is_remote": true,
    "queried_product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "recommendation": "No action needed - CVE affects different product(s): []"
  },
  {
    "cve_id": "CVE-2016-0746",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "nginx - Use After Free",
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses related to CNAME processing, exploit requires sending malicious DNS responses.",
    "is_kev": false,
    "is_poc": false,
    "is_remote": true,
    "queried_product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from pinned version 1.20.0-1~focal to latest patched version addressing CVE-2016-0746"
  },
  {
    "cve_id": "CVE-2017-20005",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "NGINX - Buffer Overflow",
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denial of service or potentially execute arbitrary code, exploit requires processing of specially crafted",
    "is_kev": false,
    "is_poc": true,
    "is_remote": true,
    "queried_product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from pinned version 1.20.0-1~focal to latest patched version addressing CVE-2017-20005"
  },
  {
    "cve_id": "CVE-2009-3555",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "Multiple Products - Man-in-the-Middle",
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of renegotiation handshakes with existing connections, letting man-in-the-middle attackers inject data ",
    "is_kev": true,
    "is_poc": true,
    "is_remote": true,
    "queried_product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from pinned version 1.20.0-1~focal to latest patched version addressing CVE-2009-3555"
  },
  {
    "cve_id": "CVE-2021-23017",
    "cvss_score": 7.7,
    "severity": "high",
    "title": "nginx - Buffer Overflow",
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP packets from DNS server.",
    "is_kev": false,
    "is_poc": true,
    "is_remote": true,
    "queried_product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from pinned version 1.20.0-1~focal to latest patched version addressing CVE-2021-23017"
  },
  {
    "cve_id": "CVE-2023-44487",
    "cvss_score": 7.5,
    "severity": "high",
    "title": "HTTP/2 - Denial of Service",
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many streams quickly, letting attackers consume server resources, exploit has been observed in the wild from August to October 2023.",
    "is_kev": true,
    "is_poc": true,
    "is_remote": true,
    "queried_product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from pinned version 1.20.0-1~focal to latest patched version addressing CVE-2023-44487"
  },
  {
    "cve_id": "CVE-2000-0525",
    "cvss_score": 10,
    "severity": "critical",
    "title": "OpenSSH - Privilege Escalation",
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input.",
    "is_kev": false,
    "is_poc": false,
    "is_remote": true,
    "queried_product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from pinned version 1:9.1p1-1ubuntu1 to latest patched version addressing CVE-2000-0525"
  },
  {
    "cve_id": "CVE-2001-0144",
    "cvss_score": 10,
    "severity": "critical",
    "title": "CORE SDI SSH1 CRC-32 - Command Injection",
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requires sending crafted CRC-32 data.",
    "is_kev": false,
    "is_poc": true,
    "is_remote": true,
    "queried_product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from pinned version 1:9.1p1-1ubuntu1 to latest patched version addressing CVE-2001-0144"
  },
  {
    "cve_id": "CVE-2000-0999",
    "cvss_score": 10,
    "severity": "critical",
    "title": "OpenBSD SSH - Buffer Overflow",
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input.",
    "is_kev": false,
    "is_poc": false,
    "is_remote": true,
    "queried_product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from pinned version 1:9.1p1-1ubuntu1 to latest patched version addressing CVE-2000-0999"
  },
  {
    "cve_id": "CVE-2002-0640",
    "cvss_score": 10,
    "severity": "critical",
    "title": "OpenSSH - Buffer Overflow",
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentication, letting remote attackers execute arbitrary code, exploit requires specific PAM configuration.",
    "is_kev": false,
    "is_poc": false,
    "is_remote": true,
    "queried_product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from pinned version 1:9.1p1-1ubuntu1 to latest patched version addressing CVE-2002-0640"
  },
  {
    "cve_id": "CVE-2003-0786",
    "cvss_score": 10,
    "severity": "critical",
    "title": "OpenSSH - Privilege Escalation",
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled.",
    "is_kev": false,
    "is_poc": false,
    "is_remote": true,
    "queried_product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from pinned version 1:9.1p1-1ubuntu1 to latest patched version addressing CVE-2003-0786"
  },
  {
    "cve_id": "CVE-2023-38408",
    "cvss_score": 9.8,
    "severity": "critical",
    "title": "OpenSSH - Command Injection",
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding agent, exploit requires agent forwarding to attacker-controlled system.",
    "is_kev": true,
    "is_poc": true,
    "is_remote": true,
    "queried_product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from pinned version 1:9.1p1-1ubuntu1 to latest patched version addressing CVE-2023-38408"
  },
  {
    "cve_id": "CVE-2024-6387",
    "cvss_score": 8.1,
    "severity": "high",
    "title": "OpenSSH - Race Condition",
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit requires no authentication.",
    "is_kev": true,
    "is_poc": true,
    "is_remote": true,
    "queried_product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from pinned version 1:9.1p1-1ubuntu1 to latest patched version addressing CVE-2024-6387"
  },
  {
    "cve_id": "CVE-2007-4752",
    "cvss_score": 7.5,
    "severity": "high",
    "title": "OpenSSH - Privilege Escalation",
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipulate cookie creation.",
    "is_kev": true,
    "is_poc": false,
    "is_remote": true,
    "queried_product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from pinned version 1:9.1p1-1ubuntu1 to latest patched version addressing CVE-2007-4752"
  },
  {
    "cve_id": "CVE-2019-6109",
    "cvss_score": 6.8,
    "severity": "medium",
    "title": "OpenSSH - Output Manipulation",
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to manipulate client output, exploit requires man-in-the-middle position.",
    "is_kev": true,
    "is_poc": false,
    "is_remote": true,
    "queried_product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from pinned version 1:9.1p1-1ubuntu1 to latest patched version addressing CVE-2019-6109"
  },
  {
    "cve_id": "CVE-2019-6110",
    "cvss_score": 6.8,
    "severity": "medium",
    "title": "OpenSSH - Client Output Manipulation",
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, exploit requires man-in-the-middle position.",
    "is_kev": true,
    "is_poc": true,
    "is_remote": true,
    "queried_product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from pinned version 1:9.1p1-1ubuntu1 to latest patched version addressing CVE-2019-6110"
  },
  {
    "cve_id": "CVE-2007-3279",
    "cvss_score": 10,
    "severity": "critical",
    "title": "PostgreSQL - Privilege Escalation",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation.",
    "is_kev": false,
    "is_poc": false,
    "is_remote": true,
    "queried_product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from pinned version 16.2-1.pgdg22.04+1 to latest patched version addressing CVE-2007-3279"
  },
  {
    "cve_id": "CVE-2013-1902",
    "cvss_score": 10,
    "severity": "critical",
    "title": "PostgreSQL - Insecure Temporary Files",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "is_kev": false,
    "is_poc": false,
    "is_remote": true,
    "queried_product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from pinned version 16.2-1.pgdg22.04+1 to latest patched version addressing CVE-2013-1902"
  },
  {
    "cve_id": "CVE-2013-1903",
    "cvss_score": 10,
    "severity": "critical",
    "title": "PostgreSQL - Information Disclosure",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers ",
    "is_kev": false,
    "is_poc": false,
    "is_remote": true,
    "queried_product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from pinned version 16.2-1.pgdg22.04+1 to latest patched version addressing CVE-2013-1903"
  },
  {
    "cve_id": "CVE-2024-1597",
    "cvss_score": 10,
    "severity": "critical",
    "title": "pgjdbc - SQL Injection",
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeh",
    "is_kev": true,
    "is_poc": false,
    "is_remote": true,
    "queried_product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from pinned version 16.2-1.pgdg22.04+1 to latest patched version addressing CVE-2024-1597"
  },
  {
    "cve_id": "CVE-2002-1399",
    "cvss_score": 10,
    "severity": "critical",
    "title": "PostgreSQL - Integer Overflow",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified.",
    "is_kev": false,
    "is_poc": false,
    "is_remote": true,
    "queried_product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from pinned version 16.2-1.pgdg22.04+1 to latest patched version addressing CVE-2002-1399"
  },
  {
    "cve_id": "CVE-2019-9193",
    "cvss_score": 7.2,
    "severity": "high",
    "title": "PostgreSQL - Command Injection",
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit requires superuser or group membership.",
    "is_kev": true,
    "is_poc": true,
    "is_remote": true,
    "queried_product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from pinned version 16.2-1.pgdg22.04+1 to latest patched version addressing CVE-2019-9193"
  },
  {
    "cve_id": "CVE-2022-31197",
    "cvss_score": 7.1,
    "severity": "high",
    "title": "PostgreSQL JDBC Driver - SQL Injection",
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the application invokes this method and queries malicious schemas, exploit requires tricking the user int",
    "is_kev": true,
    "is_poc": true,
    "is_remote": true,
    "queried_product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from pinned version 16.2-1.pgdg22.04+1 to latest patched version addressing CVE-2022-31197"
  }
]
```

## Report

# ABAC Policy Mining Report — Segcorp Ansible Configuration

## Executive Summary

An Attribute-Based Access Control (ABAC) policy was mined from the Ansible configuration
rooted at the Segcorp production infrastructure (`policy_goal: all`). The configuration
covers three host groups (dmz, appservers, dbservers) with PCI DSS compliance requirements
in a production environment.

## Catalog Summary

### Subjects
- **3 users**: admin (sudo/operations/secret), developer (developers/engineering/confidential), dba (dba/data/secret)
- **3 groups**: sudo, developers, dba
- **Clearance levels**: confidential, secret
- **Departments**: operations, engineering, data

### Resources
- **3 hosts**: proxy01.lab.local (dmz/reverse_proxy), app01.lab.local (app/application), db01.lab.local (data/primary)
- **4 services**: ssh (22/tcp), nginx (443/tcp), app (8080/tcp), postgresql (5432/tcp)
- **3 paths**: /var/lib/postgresql/data (postgres:postgres 0700), /etc/ssh/sshd_config, /etc/postgresql/pg_hba.conf
- **4 networks**: 10.0.1.0/24 (dmz), 10.0.2.0/24 (app), 10.0.3.0/24 (data), 0.0.0.0/0 (internet)

### Environment
- **Organization**: segcorp
- **Environment**: production
- **Compliance tier**: PCI DSS
- **Log retention**: 365 days

## Rules Summary

**15 rules extracted** covering:
- **SSH login** (3 rules): Group-based AllowGroups restrictions per host zone
  - appservers: sudo + developers
  - dbservers: sudo + dba
  - dmz: sudo only
- **Network/Firewall** (3 rules): Firewalld source-based allow rules
  - DMZ subnet → app port 8080
  - Internet → HTTPS port 443 on DMZ
  - App subnet → postgresql port 5432
- **Database access** (2 rules): PostgreSQL role-based access
  - DBA group → SUPERUSER login (with audit obligation)
  - Developers group → NOSUPERUSER login
- **Filesystem ACL** (4 rules): PostgreSQL data directory mode 0700 enforcement
  - postgres user: read/write/execute (permit)
  - Other users: read (deny)
- **User provisioning** (2 rules): Conditional user creation per host group
  - appservers: sudo + developers groups
  - dmz: sudo group only
- **Default deny** (1 rule): Catch-all deny for any unmatched access

## Vulnerability Assessment

### Pinned Software Versions
| Package | Pinned Version |
|---------|---------------|
| nginx | 1.20.0-1~focal |
| openssh-server | 1:9.1p1-1ubuntu1 |
| postgresql-16 | 16.2-1.pgdg22.04+1 |

### Critical Findings

| CVE | CVSS | Product | Affects Pinned? | Notes |
|-----|------|---------|-----------------|-------|
| CVE-2021-46461 | 9.8 | nginx | No | Unrelated product |
| CVE-2016-0746 | 9.8 | nginx | **Yes** | Critical remote vulnerability |
| CVE-2017-20005 | 9.8 | nginx | **Yes** | Critical remote vulnerability |
| CVE-2009-3555 | 9.8 | nginx | **Yes** | TLS renegotiation MiTM (KEV) |
| CVE-2021-23017 | 7.7 | nginx | **Yes** | High severity resolver vulnerability |
| CVE-2023-44487 | 7.5 | nginx | **Yes** | HTTP/2 Rapid Reset (KEV) |
| CVE-2000-0525 | 10.0 | openssh | **Yes** | Critical (legacy) |
| CVE-2023-38408 | 9.8 | openssh | **Yes** | Critical PKCS#11 vulnerability |
| CVE-2024-6387 | 8.1 | openssh | **Yes** | High severity (regreSSHion) |
| CVE-2007-3279 | 10.0 | postgresql | **Yes** | Critical (legacy) |
| CVE-2019-9193 | 7.2 | postgresql | **Yes** | pg_dump privilege escalation |

### Recommendations
1. **URGENT**: Upgrade nginx from 1.20.0 to latest stable (1.26+) to address CVE-2016-0746, CVE-2017-20005, CVE-2009-3555, CVE-2021-23017, and CVE-2023-44487.
2. **URGENT**: Upgrade openssh-server to address CVE-2024-6387 (regreSSHion) and CVE-2023-38408.
3. Review legacy PostgreSQL CVEs; most are historical but version 16.2 should be checked against CVE-2019-9193.

## Ambiguities & Assumptions

1. **No explicit sudoers configuration**: The Ansible config references sudo group membership but does not define explicit sudoers rules with NOPASSWD or command restrictions. The `sudo:execute` privilege is assumed from group membership.
2. **No hardcoded credentials**: No passwords or API keys were found in the configuration files. Database authentication uses scram-sha-256 per pg_hba.
3. **SSH port**: Assumed default port 22 (not explicitly configured in files).
4. **Filesystem modes**: The sshd_config and pg_hba.conf file modes (0644, 0640) were inferred from common practice, not explicitly defined in the Ansible tasks.
5. **SELinux**: No SELinux boolean or policy configurations were found in the Ansible files.
6. **Monitoring**: No monitoring or audit script configurations were found.
7. **Implicit deny**: The default-deny rule (rule-015) covers all unmatched access; no implicit denies are emitted as separate rules per resource.

## Compliance Notes

- PCI DSS compliance tier requires strict access control and audit logging.
- The SUPERUSER obligation on DBA database access mandates audit logging of all administrative database actions.
- Log retention is set to 365 days, consistent with PCI requirements.
- Network segmentation is enforced via firewalld with zone-based source restrictions.
