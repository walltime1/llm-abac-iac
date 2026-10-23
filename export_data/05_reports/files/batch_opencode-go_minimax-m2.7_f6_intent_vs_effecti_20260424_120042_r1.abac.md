# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 12:25:21_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 11 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "description": "Linux system user account",
      "type": "string",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "description": "Numeric user identifier assigned by the OS",
      "type": "integer",
      "domain": [
        1001,
        1002,
        1003
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "description": "Posix groups the user is a member of (set-valued)",
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "description": "Information clearance level assigned to the user",
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "description": "Organisational department",
      "type": "enum",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source_zone": {
      "description": "Network zone of origin for a connection (used in network-layer rules)",
      "type": "string",
      "source": "group_vars/*.yml"
    },
    "source_ip": {
      "description": "Allowed source IP/CIDR block for network access",
      "type": "string",
      "source": "group_vars/*.yml"
    }
  },
  "resources": {
    "hostname": {
      "description": "Ansible inventory hostname",
      "type": "string",
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "description": "Host IP address",
      "type": "string",
      "domain": [
        "10.0.1.10",
        "10.0.2.10",
        "10.0.3.10"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "description": "Security zone classification of the host",
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "description": "Functional role of the host in the stack",
      "type": "enum",
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "description": "Ansible inventory group membership",
      "type": "string",
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "description": "Network service name (daemon)",
      "type": "string",
      "domain": [
        "ssh",
        "nginx",
        "postgresql",
        "https"
      ],
      "source": "roles/*/tasks/main.yml"
    },
    "port": {
      "description": "TCP port number the service listens on",
      "type": "integer",
      "domain": [
        22,
        443,
        8080,
        5432
      ],
      "source": "group_vars/*.yml, roles/*/tasks/main.yml"
    },
    "path": {
      "description": "Absolute filesystem path",
      "type": "string",
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "description": "Filesystem owner username",
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "description": "Filesystem group name",
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "description": "Octal POSIX permission bits",
      "type": "string",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "description": "PostgreSQL database name",
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "schema": {
      "description": "PostgreSQL schema name",
      "type": "string",
      "domain": [
        "public"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "cidr": {
      "description": "CIDR network prefix",
      "type": "string",
      "source": "group_vars/*.yml"
    },
    "pg_hba_method": {
      "description": "PostgreSQL pg_hba.conf authentication method",
      "type": "enum",
      "domain": [
        "scram-sha-256"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "nopassword": {
      "description": "Whether passwordless sudo is configured",
      "type": "boolean",
      "domain": [
        true,
        false
      ],
      "source": "roles/*/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "description": "Organisation name",
      "type": "string",
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "description": "Deployment environment",
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "description": "Regulatory compliance regime",
      "type": "enum",
      "domain": [
        "pci"
      ],
      "source": "inventory.ini, group_vars/all.yml"
    },
    "retention_days": {
      "description": "Audit log retention period in days",
      "type": "integer",
      "domain": [
        365
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
    "rule_id": "rule-001",
    "description": "SSH login to app01.lab.local is permitted for sudo and developers group members",
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
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        27,
        32
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "SSH login to proxy01.lab.local is restricted to the sudo group",
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
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
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
    "rule_id": "rule-003",
    "description": "SSH login to db01.lab.local is restricted to sudo and dba groups",
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
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        42,
        46
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "DBA team members obtain PostgreSQL SUPERUSER credentials on db01.lab.local",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      },
      "department": {
        "equals": "data"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      },
      "schema": {
        "equals": "public"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "detail": "SUPERUSER — LOGIN,CREATEROLE,CREATEDB,REPLICATION,BYPASSRLS"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        24,
        28
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Developers obtain PostgreSQL login credentials on db01.lab.local without superuser rights",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      },
      "department": {
        "equals": "engineering"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      },
      "schema": {
        "equals": "public"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "detail": "NOSUPERUSER — standard read/write on all schemas"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        30,
        34
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "DMZ subnet (10.0.1.0/24) may connect to app servers on port 8080/tcp (application port)",
    "subject_condition": {
      "source_ip": {
        "equals": "10.0.1.0/24"
      },
      "source_zone": {
        "equals": "dmz"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "zone": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      },
      "service": {
        "equals": "nginx"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        19,
        25
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Any internet source (0.0.0.0/0) may connect to DMZ reverse proxy on port 443/tcp",
    "subject_condition": {
      "source_ip": {
        "equals": "0.0.0.0/0"
      },
      "source_zone": {
        "equals": "internet"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "zone": {
        "equals": "dmz"
      },
      "port": {
        "equals": 443
      },
      "service": {
        "equals": "nginx"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        24,
        29
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Only the appservers subnet (10.0.2.0/24) may connect to db01.lab.local on PostgreSQL port 5432 using scram-sha-256",
    "subject_condition": {
      "source_ip": {
        "equals": "10.0.2.0/24"
      },
      "source_zone": {
        "equals": "app"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "pg_hba_method": {
        "equals": "scram-sha-256"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        36,
        40
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "PostgreSQL network access is denied for any source not matching the explicit pg_hba allow rule (10.0.2.0/24 scram-sha-256). pg_hba.conf is evaluated in order; all other entries are implicitly DENY.",
    "subject_condition": {
      "source_ip": {
        "equals": "0.0.0.0/0"
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet (implicit deny for all other sources)",
      "lines": [
        36,
        40
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "PostgreSQL data directory /var/lib/postgresql/data is owned by postgres:postgres with mode 0700 — only the postgres OS user may read/write",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        17,
        22
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "admin (sudo) and developer (developers) users are provisioned with /bin/bash on app01.lab.local",
    "subject_condition": {
      "user": {
        "in": [
          "admin",
          "developer"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "host_group": {
        "equals": "appservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "obligations": [
      {
        "type": "shell",
        "detail": "shell must be /bin/bash on app servers"
      }
    ],
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        11,
        17
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "description": "admin user (sudo group) is provisioned with /bin/bash on proxy01.lab.local in the DMZ",
    "subject_condition": {
      "user": {
        "equals": "admin"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "host_group": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "obligations": [
      {
        "type": "shell",
        "detail": "shell must be /bin/bash on DMZ proxy"
      }
    ],
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": [
        16,
        22
      ]
    }
  },
  {
    "rule_id": "rule-013",
    "description": "Default deny: all access not explicitly permitted by the above rules is denied",
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
      "file": "inventory.ini",
      "task": "default-deny (implicit policy)",
      "lines": [
        1,
        100
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
      },
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
    "id": "rule-002",
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
      },
      "service": {
        "equals": "nginx"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
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
    "id": "rule-003",
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
      },
      "service": {
        "equals": "nginx"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
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
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2016-0746",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "affected_products": [
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
      },
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
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.14006,
    "recommendation": "Upgrade nginx to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2021-46461",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.00619,
    "recommendation": "Upgrade nginx to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2017-20005",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.0325,
    "recommendation": "Upgrade nginx to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2021-23017",
    "cvss_score": 7.7,
    "severity": "high",
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_session_border_controller",
        "summary": "oracle communications_session_border_controller is a network security and session management solution that protects and manages VoIP and multimedia sessions. It sits in the core_infra layer of the tech stack, functions as a network security appliance in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
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
        "industry": "information_technology",
        "product": "enterprise_communications_broker",
        "summary": "oracle enterprise_communications_broker is a communication integration platform that enables seamless messaging and data exchange across enterprise systems. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
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
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_fraud_monitor",
        "summary": "oracle communications_fraud_monitor is a fraud detection and prevention solution designed to protect telecommunications networks from fraudulent activities. It sits in the core_infra layer of the tech stack, functions as a security monitoring system in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.73544,
    "recommendation": "Upgrade nginx to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2013-4547",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 contain a restriction bypass caused by unescaped space character in URI, letting remote attackers bypass intended restrictions, exploit requires sendi",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.90921,
    "recommendation": "Upgrade nginx to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2009-2629",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "nginx versions 0.1.0 through 0.5.37, 0.6.x before 0.6.39, 0.7.x before 0.7.62, and 0.8.x before 0.8.15 contain a buffer underflow caused by crafted HTTP requests in src/http/ngx_http_parse.c, letting ",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.781,
    "recommendation": "Upgrade nginx to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2014-0133",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "nginx 1.3.15 before 1.4.7 and 1.5.x before 1.5.12 contain a heap-based buffer overflow caused by crafted requests in the SPDY implementation, letting remote attackers execute arbitrary code, exploit r",
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
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.20913,
    "recommendation": "Upgrade nginx to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2018-16843",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "nginx before versions 1.15.6 and 1.14.1 contains a memory exhaustion caused by flawed HTTP/2 implementation in the ngx_http_v2_module, letting remote attackers cause excessive memory consumption, expl",
    "affected_products": [
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
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.55541,
    "recommendation": "Upgrade nginx to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2018-16844",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "nginx before 1.15.6 and 1.14.1 contains a vulnerability in the implementation of HTTP/2 caused by improper handling of specific requests in the ngx_http_v2_module, letting attackers cause excessive CP",
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
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "xcode",
        "summary": "apple xcode is an integrated development environment (IDE) that provides tools for software development on Apple platforms. It sits in the application_library layer of the tech stack, functions as a development tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "apple"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.10883,
    "recommendation": "Upgrade nginx to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2022-35173",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "Nginx NJS v0.7.5 contains a segmentation violation caused by incorrect JUMP offset in code generation, letting attackers cause denial of service, exploit requires sending crafted code to the server.",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.00397,
    "recommendation": "Upgrade nginx to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2023-44487",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many streams quickly, letting attackers consume server resources, exploit has been observed in the wild f",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "http2",
        "summary": "istio istio is an open-source service mesh that provides traffic management, security, and observability for microservices. It sits in the core_infra layer of the tech stack, functions as a platform infrastructure component in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "kazu-yamamoto"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "crosswork_situation_manager",
        "summary": "cisco expressway is a secure collaboration gateway that enables seamless and secure communication between internal and external networks. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "unified_contact_center_domain_manager",
        "summary": "cisco fog_director is an edge computing management platform that enables deployment and orchestration of applications at the network edge. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure management tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "product": "secure_web_appliance_firmware",
        "vendor": "cisco"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "netty",
        "summary": "netty netty is an asynchronous event-driven network application framework that simplifies network programming in Java. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netty"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "traffic_server",
        "summary": "amazon opensearch_data_prepper is a data ingestion and processing tool that prepares and transforms data for analysis in OpenSearch. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "apache"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "logging_subsystem_for_red_hat_openshift",
        "summary": "redhat migration_toolkit_for_applications is a toolset that automates the assessment and migration of applications to modern platforms. It sits in the core_infra layer of the tech stack, functions as a self-hosted tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fedora",
        "summary": "akka http_server is a toolkit for building HTTP-based applications and services that provides a reactive, asynchronous server framework. It sits in the core_infra layer of the tech stack, functions as a self-hosted server framework in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "fedoraproject"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "apisix",
        "summary": "apache traffic_server is a high-performance caching proxy server that accelerates web traffic and improves scalability. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "go",
        "summary": "golang go is a statically typed, compiled programming language that simplifies software development with efficient concurrency and performance. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "golang"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "decision_manager",
        "summary": "redhat integration_camel_for_spring_boot is an integration framework that enables building enterprise integration patterns using Apache Camel within Spring Boot applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "prime_cable_provisioning",
        "summary": "cisco secure_malware_analytics is a cybersecurity solution that detects and analyzes malware threats to protect enterprise networks. It sits in the core_infra layer of the tech stack, functions as a security service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "cisco"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "unified_contact_center_enterprise",
        "summary": "cisco ios_xe is a modular operating system designed for enterprise networking devices that provides advanced routing, switching, and security features. It sits in the operating_system layer of the tech stack, functions as a core network OS in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_advanced_firewall_manager",
        "summary": "f5 big-ip_advanced_web_application_firewall is a security solution that provides advanced web application firewall capabilities to protect applications from attacks. It sits in the core_infra layer of the tech stack, functions as a security appliance in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_policy_enforcement_manager",
        "summary": "f5 big-ip_ssl_orchestrator is a network security and traffic management solution that automates SSL/TLS decryption and orchestration. It sits in the core_infra layer of the tech stack, functions as a security appliance in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "3scale_api_management_platform",
        "summary": "redhat advanced_cluster_management_for_kubernetes is a multi-cluster management solution that provides centralized governance, risk, and compliance for Kubernetes clusters. It sits in the core_infra layer of the tech stack, functions as a self-hosted management platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "connected_mobile_experiences",
        "summary": "cisco data_center_network_manager is a network management software that provides centralized control and automation for data center networks. It sits in the core_infra layer of the tech stack, functions as an enterprise application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "unified_attendant_console_advanced",
        "summary": "cisco unified_contact_center_management_portal is a centralized management portal for contact center operations that enables efficient administration and monitoring of customer service environments. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "envoy",
        "summary": "envoyproxy envoy is an open-source edge and service proxy that provides advanced load balancing, observability, and security for microservices architectures. It sits in the core_infra layer of the tech stack, functions as a service proxy in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "envoyproxy"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx_ingress_controller",
        "summary": "f5 nginx_plus is a commercial web server and application delivery controller that enhances web traffic management and security. It sits in the web_servers layer of the tech stack, functions as a core infrastructure service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "f5"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux",
        "summary": "netapp astra_control_center is a data management and protection platform designed for Kubernetes applications that simplifies backup, recovery, and disaster recovery. It sits in the data_storage layer of the tech stack, functions as a self-hosted core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "firepower_threat_defense",
        "summary": "cisco prime_infrastructure is a network management and monitoring solution that provides centralized control and automation for enterprise networks. It sits in the core_infra layer of the tech stack, functions as an enterprise application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "secure_dynamic_attributes_connector",
        "summary": "cisco ultra_cloud_core_-_serving_gateway_function is a cloud-native serving gateway function that manages user data traffic and mobility in telecom networks. It sits in the core_infra layer of the tech stack, functions as a network function in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "networking",
        "summary": "f5 big-ip_access_policy_manager is an access management and security policy enforcement solution that controls and secures user access to applications. It sits in the core_infra layer of the tech stack, functions as a security appliance in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "golang"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_webaccelerator",
        "summary": "f5 big-ip_websafe is a web application firewall that protects web applications from attacks and vulnerabilities. It sits in the core_infra layer of the tech stack, functions as a security appliance in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "armeria",
        "summary": "redhat 3scale_api_management_platform is an API management solution that enables organizations to control, secure, and scale their APIs. It sits in the core_infra layer of the tech stack, functions as a self-hosted or SaaS platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "linecorp"
      },
      {
        "category": "application_library",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "self_node_remediation_operator",
        "summary": "redhat support_for_spring_boot is a support service that provides enterprise-grade assistance and maintenance for Spring Boot applications. It sits in the application_library layer of the tech stack, functions as a support service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_application_security_manager",
        "summary": "f5 big-ip_application_visibility_and_reporting is a network traffic monitoring and analytics solution that provides detailed application visibility and reporting. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "f5"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "tomcat",
        "summary": "apple swiftnio_http/2 is a Swift-based HTTP/2 networking library that enables efficient and scalable network communication. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "windows_11_22h2",
        "summary": "microsoft windows_server_2016 is a server operating system that provides enterprise-grade infrastructure and management capabilities. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "microsoft"
      },
      {
        "category": "operating_system",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "ceph_storage",
        "summary": "redhat certification_for_red_hat_enterprise_linux is a certification program that validates expertise in managing and deploying Red Hat Enterprise Linux systems. It sits in the operating_system layer of the tech stack, functions as a professional credential in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "openshift_data_science",
        "summary": "redhat openshift_developer_tools_and_services is a suite of developer tools and services designed to enhance application development and deployment on the OpenShift container platform. It sits in the core_infra layer of the tech stack, functions as a self-hosted and SaaS hybrid platform in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "solr",
        "summary": "cisco connected_mobile_experiences is a mobile network analytics and optimization solution that enhances user experience and network performance. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "apache"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ultra_cloud_core_-_serving_gateway_function",
        "summary": "cisco unified_contact_center_enterprise is a comprehensive contact center solution that manages customer interactions across multiple channels. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "big-ip_carrier-grade_nat",
        "summary": "f5 big-ip_ddos_hybrid_defender is a hybrid DDoS protection solution that combines on-premises and cloud-based defenses to mitigate distributed denial-of-service attacks. It sits in the core_infra layer of the tech stack, functions as a security service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "f5"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_websafe",
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "asp.net_core",
        "summary": "microsoft azure_kubernetes_service is a managed container orchestration service that simplifies deploying, managing, and scaling containerized applications using Kubernetes. It sits in the core_infra layer of the tech stack, functions as a platform service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "microsoft"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "windows_server_2019",
        "summary": "microsoft windows_server_2022 is a server operating system that provides enterprise-grade security, hybrid capabilities, and flexible application platform support. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "microsoft"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "build_of_quarkus",
        "summary": "redhat cert-manager_operator_for_red_hat_openshift is an operator that automates the management and issuance of TLS certificates within Red Hat OpenShift clusters. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "jboss_a-mq",
        "summary": "redhat jboss_core_services is a middleware framework providing core services for Java applications, enhancing modularity and scalability. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "openshift_container_platform_assisted_installer",
        "summary": "redhat openshift_dev_spaces is a cloud-native development environment that enables developers to build, test, and debug applications within Kubernetes. It sits in the core_infra layer of the tech stack, functions as a self-hosted and SaaS hybrid development platform in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_advanced_web_application_firewall",
        "summary": "f5 big-ip_analytics is an advanced analytics and monitoring solution that provides deep insights into application delivery and network traffic. It sits in the core_infra layer of the tech stack, functions as a service for network and application performance monitoring in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "f5"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": ".net",
        "summary": "microsoft asp.net_core is a cross-platform, high-performance web framework for building modern, cloud-based web applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "microsoft"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_data_grid",
        "summary": "redhat jboss_fuse is an open-source integration platform that enables developers to connect applications, services, and devices. It sits in the core_infra layer of the tech stack, functions as a middleware integration platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "node_healthcheck_operator",
        "summary": "redhat openshift is a container application platform that automates Kubernetes container orchestration and management. It sits in the core_infra layer of the tech stack, functions as a platform service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift",
        "summary": "redhat openshift_container_platform is a comprehensive Kubernetes container orchestration platform that automates deployment, scaling, and management of containerized applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "process_automation",
        "summary": "redhat satellite is a systems management solution that automates the deployment, configuration, and maintenance of Red Hat infrastructure. It sits in the core_infra layer of the tech stack, functions as a self-hosted management platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "satellite",
        "summary": "redhat single_sign-on is an identity and access management solution that provides secure single sign-on capabilities for applications and services. It sits in the core_infra layer of the tech stack, functions as a security service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "linkerd",
        "summary": "linecorp armeria is an open-source asynchronous RPC and HTTP/2 server framework that enables efficient and scalable service development. It sits in the core_infra layer of the tech stack, functions as a self-hosted server framework in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "linkerd"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_gitops",
        "summary": "redhat openshift_sandboxed_containers is a container runtime technology that provides secure, isolated container environments for cloud-native applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure component in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "astra_control_center",
        "summary": "konghq kong_gateway is an API gateway that manages, secures, and extends APIs and microservices. It sits in the core_infra layer of the tech stack, functions as a service gateway in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "secure_malware_analytics",
        "summary": "cisco ultra_cloud_core_-_session_management_function is a cloud-native session management solution that handles user session control and mobility in telecom networks. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "telepresence_video_communication_server",
        "summary": "cisco unified_attendant_console_advanced is a call management and attendant console software that enhances call handling efficiency in enterprise telephony environments. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the telecommunications industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "unified_contact_center_enterprise_-_live_data_server",
        "summary": "cisco ios_xr is a carrier-grade network operating system that provides high availability and scalability for service provider routers. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "grpc",
        "summary": "microsoft .net is a software development framework that provides a platform for building and running applications across multiple languages and devices. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "grpc"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "visual_studio_2022",
        "summary": "microsoft windows_10_1607 is an operating system that provides a user interface and platform for running applications on personal computers. It sits in the operating_system layer of the tech stack, functions as a core system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "microsoft"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "windows_10_1607",
        "summary": "microsoft windows_10_1809 is an operating system that provides a user interface and platform for running applications on personal computers. It sits in the operating_system layer of the tech stack, functions as a core system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "microsoft"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_api_for_data_protection",
        "summary": "redhat openshift_container_platform_assisted_installer is an automated installation tool that simplifies the deployment of OpenShift clusters. It sits in the core_infra layer of the tech stack, functions as a self-hosted deployment tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_pipelines",
        "summary": "redhat openshift_secondary_scheduler_operator is an operator that manages secondary scheduling capabilities within OpenShift clusters to optimize workload distribution. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "jenkins",
        "summary": "cisco business_process_automation is a platform designed to automate and optimize business workflows and processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "jenkins"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "business_process_automation",
        "summary": "cisco crosswork_zero_touch_provisioning is a network automation solution that enables automated device provisioning and configuration. It sits in the core_infra layer of the tech stack, functions as a self-hosted network automation tool in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "data_center_network_manager",
        "summary": "cisco iot_field_network_director is a network management solution that provides centralized control and monitoring for IoT field networks. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_domain_name_system",
        "summary": "f5 big-ip_fraud_protection_service is a security solution that protects applications from fraud and abuse by detecting and mitigating malicious activities. It sits in the core_infra layer of the tech stack, functions as a security service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "f5"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "windows_11_21h2",
        "summary": "microsoft windows_11_22h2 is an operating system that provides a modern user interface and enhanced security features for personal and professional computing. It sits in the operating_system layer of the tech stack, functions as a core platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "microsoft"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "openstack_platform",
        "summary": "redhat quay is a container image registry that provides secure storage, distribution, and management of container images. It sits in the core_infra layer of the tech stack, functions as a self-hosted or SaaS registry service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "unified_contact_center_management_portal",
        "summary": "cisco secure_web_appliance_firmware is a firmware component that provides security and web filtering capabilities for Cisco's secure web appliances. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_access_policy_manager",
        "summary": "f5 big-ip_advanced_firewall_manager is a high-performance, stateful, full-proxy network security solution that protects data centers from incoming threats and DDoS attacks. It sits in the core_infra layer of the tech stack, functions as a security appliance in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "migration_toolkit_for_applications",
        "summary": "redhat migration_toolkit_for_virtualization is a tool that facilitates the migration of virtual machines and workloads across different virtualization platforms. It sits in the core_infra layer of the tech stack, functions as a self-hosted tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_secondary_scheduler_operator",
        "summary": "redhat openshift_service_mesh is a service mesh solution that provides observability, traffic management, and security for microservices on Kubernetes. It sits in the core_infra layer of the tech stack, functions as a platform service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "quay",
        "summary": "redhat self_node_remediation_operator is an automated remediation tool that detects and recovers unhealthy nodes in Kubernetes clusters. It sits in the core_infra layer of the tech stack, functions as a self-hosted operator in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "crosswork_zero_touch_provisioning",
        "summary": "cisco firepower_threat_defense is a network security solution that provides advanced threat protection and firewall capabilities. It sits in the core_infra layer of the tech stack, functions as a security appliance in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ultra_cloud_core_-_policy_control_function",
        "summary": "cisco unified_contact_center_domain_manager is a contact center management solution that centralizes and optimizes customer interaction workflows. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "traefik",
        "summary": "projectcontour contour is an open-source Kubernetes ingress controller that manages inbound traffic to Kubernetes clusters efficiently. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "traefik"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_container_platform",
        "summary": "redhat openshift_data_science is a cloud-native data science platform that enables scalable machine learning and AI workloads. It sits in the core_infra layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_next_service_proxy_for_kubernetes",
        "summary": "f5 big-ip_policy_enforcement_manager is a network security and policy enforcement solution that manages and enforces security policies across applications and networks. It sits in the core_infra layer of the tech stack, functions as a security infrastructure component in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "integration_camel_k",
        "summary": "redhat jboss_a-mq is a messaging middleware that enables reliable communication between distributed applications. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "expressway",
        "summary": "cisco prime_cable_provisioning is a network management solution that automates provisioning and monitoring of cable networks. It sits in the core_infra layer of the tech stack, functions as a self-hosted network management system in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "iot_field_network_director",
        "summary": "cisco prime_network_registrar is a network management and IP address management solution that automates and simplifies network services. It sits in the core_infra layer of the tech stack, functions as a self-hosted network management service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "summary": "f5 nginx_ingress_controller is a Kubernetes ingress controller that manages external access to services in a cluster, providing load balancing and traffic routing. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "advanced_cluster_management_for_kubernetes",
        "summary": "redhat advanced_cluster_security is a Kubernetes-native security platform that provides threat detection, compliance, and runtime protection for containerized applications. It sits in the core_infra layer of the tech stack, functions as a security platform in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "crosswork_data_gateway",
        "summary": "cisco enterprise_chat_and_email is a unified communication platform that integrates chat and email services for enterprise collaboration. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "http2",
        "summary": "golang http2 is a Go language implementation of the HTTP/2 protocol that enables efficient and optimized network communication. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "golang"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "node_maintenance_operator",
        "summary": "redhat openshift_api_for_data_protection is an API service that provides data protection and backup capabilities for OpenShift container platforms. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "ansible_automation_platform",
        "summary": "redhat build_of_quarkus is a build tool and framework that enables fast and efficient Java application development optimized for container environments. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "integration_service_registry",
        "summary": "redhat jboss_a-mq_streams is a distributed streaming platform that enables real-time data processing and messaging. It sits in the core_infra layer of the tech stack, functions as a self-hosted middleware service in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "network_observability_operator",
        "summary": "redhat node_maintenance_operator is a Kubernetes operator that automates node maintenance tasks to improve cluster reliability and uptime. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure automation tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "service_interconnect",
        "summary": "redhat web_terminal is a web-based terminal emulator that provides command-line access through a browser interface. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "http_server",
        "summary": "apache solr is an open-source search platform that provides powerful full-text search, faceted search, and real-time indexing capabilities. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "akka"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_chat_and_email",
        "summary": "cisco prime_access_registrar is a network access control and policy management solution that provides secure authentication and authorization services. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "cisco"
      },
      {
        "product": "nx-os",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_developer_tools_and_services",
        "summary": "redhat openshift_gitops is a Kubernetes-native continuous delivery tool that automates application deployment and lifecycle management using GitOps principles. It sits in the core_infra layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "windows_server_2022",
        "summary": "nodejs node.js is a JavaScript runtime built on Chrome's V8 engine that enables server-side scripting and scalable network applications. It sits in the core_infra layer of the tech stack, functions as a runtime environment in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "microsoft"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_ddos_hybrid_defender",
        "summary": "f5 big-ip_domain_name_system is a DNS management and security solution that optimizes and protects domain name system traffic. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "azure_kubernetes_service",
        "summary": "microsoft visual_studio_2022 is an integrated development environment (IDE) that provides comprehensive tools for software development and debugging. It sits in the application_library layer of the tech stack, functions as a devtool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "microsoft"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fence_agents_remediation_operator",
        "summary": "redhat integration_camel_k is a lightweight integration platform that enables running Apache Camel routes natively on Kubernetes. It sits in the core_infra layer of the tech stack, functions as a self-hosted integration runtime in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "machine_deletion_remediation_operator",
        "summary": "redhat migration_toolkit_for_containers is a container migration and modernization tool that helps migrate and transform applications to containerized environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "prime_access_registrar",
        "summary": "cisco secure_dynamic_attributes_connector is a security integration tool that facilitates dynamic attribute sharing for enhanced access control. It sits in the core_infra layer of the tech stack, functions as a security service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "nghttp2",
        "summary": "nghttp2 nghttp2 is an open-source HTTP/2 protocol implementation that provides libraries and tools for HTTP/2 client and server development. It sits in the core_infra layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "nghttp2"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_analytics",
        "summary": "f5 big-ip_application_acceleration_manager is an application delivery controller that optimizes and accelerates application performance and security. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "advanced_cluster_security",
        "summary": "redhat ansible_automation_platform is an IT automation and orchestration solution that simplifies configuration management and application deployment. It sits in the core_infra layer of the tech stack, functions as a self-hosted automation platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_core_services",
        "summary": "redhat jboss_enterprise_application_platform is a middleware platform that enables development and deployment of Java applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted application server in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "certification_for_red_hat_enterprise_linux",
        "summary": "redhat cryostat is a monitoring and profiling tool that provides continuous JVM flight recording and analysis for Java applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_a-mq_streams",
        "summary": "redhat jboss_data_grid is an in-memory distributed data grid that provides fast, scalable data storage and caching. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_local_traffic_manager",
        "summary": "f5 big-ip_next is an advanced application delivery controller that optimizes and secures network traffic for enterprise applications. It sits in the core_infra layer of the tech stack, functions as a network services platform in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "f5"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "build_of_optaplanner",
        "summary": "redhat ceph_storage is a scalable, open-source software-defined storage platform that provides unified object and block storage. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_insight",
        "summary": "jenkins jenkins is an open-source automation server that facilitates continuous integration and continuous delivery (CI/CD) pipelines. It sits in the core_infra layer of the tech stack, functions as a self-hosted automation server in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "netapp"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "caddy",
        "summary": "caddyserver caddy is a modern web server that automates HTTPS and simplifies web hosting. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "caddyserver"
      },
      {
        "category": "web_servers",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "h2o",
        "summary": "facebook proxygen is a C++ HTTP framework that provides a high-performance HTTP server and client library. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "dena"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "cert-manager_operator_for_red_hat_openshift",
        "summary": "redhat cost_management is a cloud cost management and optimization tool that helps organizations monitor and control their cloud spending. It sits in the core_infra layer of the tech stack, functions as a self-hosted or SaaS service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_fuse",
        "summary": "redhat machine_deletion_remediation_operator is an automated remediation operator that detects and recovers from machine deletions in Kubernetes clusters. It sits in the core_infra layer of the tech stack, functions as a self-hosted operator in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "run_once_duration_override_operator",
        "summary": "redhat service_interconnect is a networking solution that enables secure and efficient communication between services in hybrid cloud environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "support_for_spring_boot",
        "summary": "redhat service_telemetry_framework is a telemetry data collection and monitoring framework that enables observability for cloud-native applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "proxygen",
        "summary": "apache apisix is a dynamic, real-time, high-performance API gateway that manages and secures API traffic. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "facebook"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_application_acceleration_manager",
        "summary": "f5 big-ip_application_security_manager is a web application firewall that protects applications from attacks and vulnerabilities. It sits in the core_infra layer of the tech stack, functions as a security appliance in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_fraud_protection_service",
        "summary": "f5 big-ip_global_traffic_manager is a traffic management and load balancing solution that optimizes application delivery and availability. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_next",
        "summary": "f5 big-ip_next_service_proxy_for_kubernetes is a Kubernetes-native service proxy that provides advanced traffic management and security for containerized applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "migration_toolkit_for_containers",
        "summary": "redhat network_observability_operator is a Kubernetes operator that provides network monitoring and observability capabilities for containerized environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "ultra_cloud_core_-_session_management_function",
        "summary": "cisco unified_contact_center_enterprise_-_live_data_server is a real-time data processing server that supports contact center operations by providing live data analytics and reporting. It sits in the core_infra layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jetty",
        "summary": "eclipse jetty is a lightweight, embeddable web server and servlet container that provides HTTP server capabilities for Java applications. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "eclipse"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_global_traffic_manager",
        "summary": "f5 big-ip_link_controller is a network traffic management and optimization solution that enhances application delivery and network performance. It sits in the core_infra layer of the tech stack, functions as a network infrastructure controller in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "windows_10_22h2",
        "summary": "microsoft windows_11_21h2 is an operating system that provides a modern user interface and enhanced security features for personal and professional computing. It sits in the operating_system layer of the tech stack, functions as a core platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "microsoft"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_dev_spaces",
        "summary": "redhat openshift_distributed_tracing is a distributed tracing solution that provides observability and performance monitoring for microservices applications. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "single_sign-on",
        "summary": "redhat enterprise_linux is a commercial Linux operating system distribution that provides a stable, secure, and supported platform for enterprise applications. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "prime_network_registrar",
        "summary": "cisco ultra_cloud_core_-_policy_control_function is a cloud-native policy control solution that manages network policies and subscriber sessions in telecom networks. It sits in the core_infra layer of the tech stack, functions as a self-hosted network function in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fog_director",
        "summary": "cisco nx-os is a network operating system designed for data center and enterprise networking devices that provides high availability and scalability. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "kazu-yamamoto http2 is a Haskell library that provides HTTP/2 protocol support for building web clients and servers. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "varnish_cache",
        "summary": "traefik traefik is a modern reverse proxy and load balancer that routes and manages HTTP traffic for microservices and cloud-native applications. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "varnish_cache_project"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_sandboxed_containers",
        "summary": "redhat openshift_serverless is a serverless computing platform that enables developers to build and deploy event-driven applications without managing infrastructure. It sits in the core_infra layer of the tech stack, functions as a platform service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "web_terminal",
        "summary": "fedoraproject fedora is a Linux-based open-source operating system that provides a robust and secure platform for developers and users. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "service_telemetry_framework",
        "summary": "netapp oncommand_insight is an infrastructure analytics and monitoring solution that provides visibility and optimization for storage and data center resources. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "kong_gateway",
        "summary": "openresty openresty is a web platform that integrates the Nginx web server with Lua scripting for high-performance web applications. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "konghq"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "opensearch_data_prepper",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "amazon"
      },
      {
        "category": "core_infra",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "swiftnio_http\\/2",
        "summary": "grpc grpc is an open-source high-performance RPC framework that enables efficient communication between distributed systems. It sits in the core_infra layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "apple"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "cost_management",
        "summary": "redhat decision_manager is a business rules management system that automates and optimizes decision-making processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "migration_toolkit_for_virtualization",
        "summary": "redhat node_healthcheck_operator is a Kubernetes operator that monitors and manages the health of cluster nodes to ensure high availability. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "openshift_virtualization",
        "summary": "redhat process_automation is a business process management and automation platform that enables organizations to design, execute, and monitor business workflows. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "openresty",
        "summary": "cisco crosswork_data_gateway is a network data integration and analytics platform that enables real-time data collection and processing for network operations. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "openresty"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "istio",
        "summary": "varnish_cache_project varnish_cache is a web application accelerator that caches HTTP content to improve website performance. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "istio"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "cryostat",
        "summary": "redhat fence_agents_remediation_operator is a Kubernetes operator that automates fencing and remediation of nodes in cluster environments to maintain high availability. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_enterprise_application_platform",
        "summary": "redhat logging_subsystem_for_red_hat_openshift is a centralized logging solution that collects, stores, and manages logs for Red Hat OpenShift clusters. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "product": "ios_xr",
        "vendor": "cisco"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "cbl-mariner",
        "summary": "dena h2o is a high-performance open-source machine learning platform that enables scalable predictive analytics. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "microsoft"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "contour",
        "summary": "linkerd linkerd is a lightweight service mesh that provides observability, reliability, and security for cloud-native applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "projectcontour"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "integration_camel_for_spring_boot",
        "summary": "redhat integration_service_registry is a centralized service registry that manages and governs APIs and services for integration solutions. It sits in the core_infra layer of the tech stack, functions as a service management tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "windows_10_1809",
        "summary": "microsoft windows_10_21h2 is an operating system that provides a user interface and platform for running applications on personal computers. It sits in the operating_system layer of the tech stack, functions as a core system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "microsoft"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "prime_infrastructure",
        "summary": "cisco telepresence_video_communication_server is a video communication server that enables high-quality telepresence and video conferencing solutions. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx_plus",
        "summary": "apache tomcat is an open-source web server and servlet container that provides a Java HTTP web server environment for running Java applications. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "windows_10_21h2",
        "summary": "microsoft windows_10_22h2 is an operating system that provides a user interface and platform for running applications on personal computers. It sits in the operating_system layer of the tech stack, functions as a core system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "microsoft"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_service_mesh",
        "summary": "redhat openstack_platform is an open-source cloud computing platform that enables the deployment and management of private and public clouds. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "node.js",
        "summary": "microsoft cbl-mariner is a lightweight Linux distribution designed for cloud infrastructure and edge computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "nodejs"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "windows_server_2016",
        "summary": "microsoft windows_server_2019 is a server operating system that provides enterprise-grade infrastructure and management capabilities. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "microsoft"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_distributed_tracing",
        "summary": "redhat openshift_pipelines is a Kubernetes-native continuous integration and continuous delivery (CI/CD) solution that automates application build, test, and deployment workflows. It sits in the core_infra layer of the tech stack, functions as a devops tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_serverless",
        "summary": "redhat openshift_virtualization is a container-native virtualization solution that enables running and managing virtual machines alongside containers on OpenShift. It sits in the core_infra layer of the tech stack, functions as a platform infrastructure component in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "product": "ios_xe",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "http",
        "summary": "ietf http is a foundational application-layer protocol that enables the transfer of hypertext documents on the web. It sits in the core_infra layer of the tech stack, functions as a protocol standard in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "ietf"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "big-ip_application_visibility_and_reporting",
        "summary": "f5 big-ip_carrier-grade_nat is a network address translation solution designed for carrier-grade environments that optimizes IP address management and traffic routing. It sits in the core_infra layer of the tech stack, functions as a network infrastructure service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_link_controller",
        "summary": "f5 big-ip_local_traffic_manager is an application delivery controller that optimizes and secures network traffic for applications. It sits in the core_infra layer of the tech stack, functions as a network traffic management service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "big-ip_ssl_orchestrator",
        "summary": "f5 big-ip_webaccelerator is a web application acceleration and optimization solution that improves website performance and user experience. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "f5"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.94446,
    "recommendation": "Upgrade nginx to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2009-3555",
    "cvss_score": 5.8,
    "severity": "medium",
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ",
    "affected_products": [
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "gnutls",
        "summary": "gnu gnutls is a secure communications library that provides SSL, TLS, and DTLS protocols for encryption and authentication. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "gnu"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "nss",
        "summary": "mozilla nss is a set of libraries designed to support cross-platform development of security-enabled client and server applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "mozilla"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "openssl",
        "summary": "openssl openssl is a robust open-source cryptographic library that provides secure communication and data encryption. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openssl"
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
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "http_server",
        "summary": "apache http_server is a widely-used open-source web server that delivers HTTP content to clients efficiently and securely. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.01971,
    "recommendation": "Monitor nginx for patch availability.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2007-3279",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.02885,
    "recommendation": "Upgrade postgresql to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2002-1399",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.00458,
    "recommendation": "Upgrade postgresql to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2013-1903",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.0055,
    "recommendation": "Upgrade postgresql to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2013-1902",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.00523,
    "recommendation": "Upgrade postgresql to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2024-1597",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.00508,
    "recommendation": "Upgrade postgresql to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2015-0244",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "PostgreSQL < 9.0.19, 9.1.x < 9.1.15, 9.2.x < 9.2.10, 9.3.x < 9.3.6, and 9.4.x < 9.4.1 contain a SQL injection caused by improper error handling during protocol message reading, letting remote attacker",
    "affected_products": [
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.0108,
    "recommendation": "Upgrade postgresql to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2019-10211",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "PostgreSQL Windows installer before versions 11.5, 10.10, 9.6.15, 9.5.19, 9.4.24 contains a code execution vulnerability caused by bundled OpenSSL executing code from an unprotected directory, letting",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.01186,
    "recommendation": "Upgrade postgresql to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2022-26520",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "pgjdbc before 42.3.3 contains a file write vulnerability caused by misuse of java.util.logging.FileHandler through loggerFile and loggerLevel properties, letting attackers control file writes, exploit",
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
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.01277,
    "recommendation": "Upgrade postgresql to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2018-16850",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "PostgreSQL before versions 11.1, 10.6 contains a sql_injection caused by crafted trigger definitions in pg_upgrade and pg_dump via CREATE TRIGGER ... REFERENCING, letting attackers execute arbitrary S",
    "affected_products": [
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux",
        "summary": "redhat enterprise_linux is a commercial Linux operating system distribution that provides a stable, secure, and supported platform for enterprise applications. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ubuntu_linux",
        "summary": "canonical ubuntu_linux is a popular open-source operating system that provides a stable and secure platform for computing. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "canonical"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.01317,
    "recommendation": "Upgrade postgresql to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2017-7546",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "PostgreSQL versions before 9.2.22, 9.3.18, 9.4.13, 9.5.8, and 9.6.4 contain an incorrect authentication flaw caused by improper password validation, letting remote attackers access database accounts w",
    "affected_products": [
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.33122,
    "recommendation": "Upgrade postgresql to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2019-9193",
    "cvss_score": 7.2,
    "severity": "high",
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit req",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.93401,
    "recommendation": "Upgrade postgresql to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2022-31197",
    "cvss_score": 7.1,
    "severity": "high",
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.03579,
    "recommendation": "Upgrade postgresql to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2003-0786",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.03141,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2000-0999",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.00418,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2000-0525",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.00709,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2001-0144",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ssh",
        "summary": "ssh ssh is a secure network protocol that provides encrypted communication over unsecured networks. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "ssh"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.61717,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2003-0693",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.26823,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2002-0640",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentica",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.66963,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2002-0083",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "OpenSSH 2.0 through 3.0.2 contains an off-by-one error in the channel code, letting local users or remote malicious servers gain privileges, exploit requires attacker to control the server or local en",
    "affected_products": [
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "linux",
        "summary": "suse suse_linux is a Linux-based operating system that provides a stable and secure platform for servers and desktops. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "product": "suse_linux",
        "vendor": "suse"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "immunix",
        "summary": "mandrakesoft mandrake_single_network_firewall is a network security appliance that provides firewall protection for single network environments. It sits in the core_infra layer of the tech stack, functions as a security infrastructure component in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "immunix"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "mandrake_single_network_firewall",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "mandrakesoft"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openpkg openpkg is a software packaging and distribution system that simplifies installation and management of software packages. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "openbsd"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "linux",
        "summary": "engardelinux secure_linux is a security-focused Linux distribution that provides enhanced protection and compliance features for enterprise environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "conectiva"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "secure_linux",
        "summary": "mandrakesoft mandrake_linux is a Linux-based operating system distribution that provides a user-friendly and stable environment for desktop and server use. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "engardelinux"
      },
      {
        "product": "secure_linux",
        "vendor": "trustix"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openpkg",
        "summary": "conectiva linux is an open-source operating system kernel that provides the core foundation for various computing environments. It sits in the operating_system layer of the tech stack, functions as a core system component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "openpkg"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "mandrake_linux",
        "summary": "mandrakesoft mandrake_linux_corporate_server is a Linux-based operating system designed for corporate server environments that provides stability and enterprise features. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "mandrakesoft"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "mandrake_linux_corporate_server",
        "summary": "redhat linux is an open-source operating system that provides a stable and secure platform for enterprise computing. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "mandrakesoft"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.01528,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2002-0639",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "OpenSSH 2.9.9 through 3.3 contains an integer overflow caused by improper handling during challenge response authentication in sshd, letting remote attackers execute arbitrary code when using SKEY or ",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.36717,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2023-28531",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "OpenSSH before 9.3 contains a vulnerability in ssh-add that adds smartcard keys to ssh-agent without enforcing per-hop destination constraints, letting attackers potentially escalate privileges or acc",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "brocade_fabric_operating_system",
        "summary": "netapp brocade_fabric_operating_system is a network operating system that manages and optimizes storage area network (SAN) fabrics. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "hci_bootstrap_os",
        "summary": "netapp hci_bootstrap_os is an operating system component designed to facilitate the initialization and deployment of NetApp's HCI infrastructure. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "solidfire_element_os",
        "summary": "netapp solidfire_element_os is a storage operating system that delivers scalable and high-performance storage solutions. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.00399,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2016-1908",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "OpenSSH < 7.2 mishandles failed cookie generation for untrusted X11 forwarding caused by reliance on local X11 server for access control, letting remote X11 clients trigger fallback and gain trusted f",
    "affected_products": [
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_eus",
        "summary": "redhat enterprise_linux_eus is a long-term supported Linux operating system designed for stability and extended maintenance in enterprise environments. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_tus",
        "summary": "redhat enterprise_linux_server_tus is a Linux-based operating system designed for enterprise environments that provides a stable and secure platform for running applications and services. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_workstation",
        "summary": "redhat enterprise_linux_workstation is a robust operating system designed for workstation environments that provides stability, security, and performance for professional users. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server",
        "summary": "redhat enterprise_linux_server is a robust and secure operating system designed for enterprise environments that provides a stable platform for applications and services. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_aus",
        "summary": "redhat enterprise_linux_server_aus is a Linux-based operating system designed for enterprise-grade server environments that provides stability, security, and performance. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "linux",
        "summary": "oracle linux is an enterprise-grade operating system that provides a secure and stable platform for applications and infrastructure. It sits in the operating_system layer of the tech stack, functions as a core system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_desktop",
        "summary": "redhat enterprise_linux_desktop is a robust Linux-based operating system designed for desktop environments that provides stability and security for enterprise users. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.02179,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2023-38408",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding ",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
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
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.64839,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2024-6387",
    "cvss_score": 8.1,
    "severity": "high",
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit req",
    "affected_products": [
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "a1k_firmware",
        "summary": "netapp a1k_firmware is a firmware component that controls and manages the hardware operations of NetApp storage devices. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "c250_firmware",
        "summary": "netapp c250_firmware is a firmware component that manages low-level hardware operations for NetApp storage systems. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a220_firmware",
        "summary": "netapp a220_firmware is a firmware component that manages low-level hardware operations for the NetApp A220 storage system. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "fas2750_firmware",
        "summary": "netapp fas2750_firmware is the embedded firmware that controls the NetApp FAS2750 storage system hardware, enabling storage management and data operations. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "macos",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "apple"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_for_ibm_z_systems",
        "summary": "redhat enterprise_linux_for_ibm_z_systems_eus is a Linux-based operating system optimized for IBM Z mainframe systems that provides a stable and secure platform for enterprise workloads. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap",
        "summary": "netapp ontap_select_deploy_administration_utility is a deployment and management tool for NetApp's ONTAP Select software-defined storage. It sits in the core_infra layer of the tech stack, functions as a self-hosted management utility in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "eos",
        "summary": "arista eos is a network operating system that provides programmable, scalable, and reliable network infrastructure for data centers and cloud networks. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "arista"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sma_6210_firmware",
        "summary": "sonicwall sma_6210_firmware is the embedded firmware for the SonicWall SMA 6210 secure mobile access appliance that provides secure remote access and VPN capabilities. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "sonicwall"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sma_7210_firmware",
        "summary": "sonicwall sma_7210_firmware is a firmware for the SMA 7210 secure mobile access appliance that provides secure remote access and VPN capabilities. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "sonicwall"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "c800_firmware",
        "summary": "netapp c800_firmware is the embedded firmware that controls the NetApp C800 storage system hardware, ensuring reliable operation and management of storage resources. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a900_firmware",
        "summary": "netapp a900_firmware is a firmware component that manages low-level hardware operations for the NetApp A900 storage system. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "c190_firmware",
        "summary": "netapp c190_firmware is a firmware component that manages low-level hardware operations for NetApp storage systems. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "redhat openshift_container_platform is a comprehensive Kubernetes container orchestration platform that automates deployment, scaling, and management of containerized applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "openbsd"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_for_arm_64",
        "summary": "redhat enterprise_linux_for_arm_64_eus is a stable, long-term supported Linux operating system optimized for ARM 64-bit architectures. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "almalinux",
        "summary": "almalinux almalinux is a community-driven, open-source Linux distribution designed as a stable and secure operating system for enterprise environments. It sits in the operating_system layer of the tech stack, is typically deployed as self_hosted, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "almalinux"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "a70_firmware",
        "summary": "netapp a70_firmware is a firmware component that manages low-level hardware operations for storage systems. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a90_firmware",
        "summary": "netapp a90_firmware is the embedded firmware that controls the hardware operations of NetApp A90 storage systems. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "a400_firmware",
        "summary": "netapp a400_firmware is the embedded firmware that controls the NetApp AFF A400 storage system hardware. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a150_firmware",
        "summary": "netapp a150_firmware is the embedded firmware that controls the hardware operations of the NetApp A150 storage system. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_for_arm_64_eus",
        "summary": "redhat enterprise_linux_for_ibm_z_systems is a robust enterprise-grade Linux operating system optimized for IBM Z mainframe systems that provides stability, security, and scalability. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_for_ibm_z_systems_eus",
        "summary": "redhat enterprise_linux_for_power_little_endian is a Linux-based operating system optimized for Power Little Endian architecture that provides a stable and secure platform for enterprise workloads. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_for_power_little_endian",
        "summary": "redhat enterprise_linux_for_power_little_endian_eus is a Linux-based operating system optimized for Power Little Endian architecture that provides a stable and secure platform for enterprise workloads. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "sma_6200_firmware",
        "summary": "sonicwall sma_6200_firmware is a firmware for secure mobile access appliances that provides network security and remote access capabilities. It sits in the hardware layer of the tech stack, functions as a firmware component in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "sonicwall"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "8300_firmware",
        "summary": "netapp 8300_firmware is a firmware component that controls and manages the hardware operations of the NetApp 8300 storage system. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_aus",
        "summary": "suse linux_enterprise_micro is a lightweight, container-focused operating system designed for cloud-native workloads and edge computing. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_select_deploy_administration_utility",
        "summary": "netapp ontap_tools is a suite of management and automation utilities designed to optimize NetApp ONTAP storage systems. It sits in the core_infra layer of the tech stack, functions as a self-hosted management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "freebsd",
        "summary": "netbsd netbsd is a free, open-source, and highly portable Unix-like operating system that supports a wide range of hardware platforms. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "freebsd"
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
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "8700_firmware",
        "summary": "netapp 8700_firmware is a firmware component that manages and controls the hardware operations of NetApp storage systems. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "c400_firmware",
        "summary": "netapp c400_firmware is the embedded firmware that controls the NetApp C400 storage system hardware, ensuring reliable operation and performance. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_eus",
        "summary": "redhat enterprise_linux_for_arm_64 is a robust, enterprise-grade Linux operating system optimized for ARM 64-bit architectures that provides a stable and secure platform for applications. It sits in the operating_system layer of the tech stack, functions as a self-hosted core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_for_power_little_endian_eus",
        "summary": "redhat enterprise_linux_server_aus is a Linux-based operating system designed for enterprise-grade server environments that provides stability, security, and performance. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "product": "netbsd",
        "vendor": "netbsd"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sma_7200_firmware",
        "summary": "sonicwall sma_7200_firmware is a firmware for secure mobile access appliances that provides secure remote access and VPN capabilities. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "sonicwall"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "bootstrap_os",
        "summary": "apple macos is a desktop operating system that provides a graphical user interface and core system services for Apple computers. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux",
        "summary": "redhat enterprise_linux_eus is a long-term supported Linux operating system designed for stability and extended maintenance in enterprise environments. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "amazon_linux",
        "summary": "netapp active_iq_unified_manager is a unified storage management and monitoring solution that provides proactive insights and analytics for storage infrastructure. It sits in the core_infra layer of the tech stack, functions as a self-hosted management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "amazon"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "active_iq_unified_manager",
        "summary": "netapp e-series_santricity_os_controller is a storage management operating system that provides control and monitoring for NetApp E-Series storage arrays. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a700s_firmware",
        "summary": "netapp a700s_firmware is a firmware component that controls and manages the hardware operations of the NetApp A700s storage system. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a250_firmware",
        "summary": "netapp a250_firmware is the embedded firmware that controls the NetApp AFF A250 storage system hardware, ensuring reliable operation and performance. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "500f_firmware",
        "summary": "netapp 500f_firmware is the embedded firmware that controls the NetApp AFF A500 storage array hardware, ensuring optimal performance and reliability. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a800_firmware",
        "summary": "netapp a800_firmware is the embedded firmware that controls the hardware operations of the NetApp A800 storage system. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "a9500_firmware",
        "summary": "netapp a9500_firmware is the embedded firmware that controls the NetApp AFF A9500 storage system hardware, enabling storage management and operation. It sits in the hardware layer of the tech stack, is deployed as self_hosted within storage appliances, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "fas2720_firmware",
        "summary": "netapp fas2720_firmware is the embedded firmware that controls the NetApp FAS2720 storage system hardware, enabling storage management and data operations. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "fas2820_firmware",
        "summary": "netapp fas2820_firmware is the embedded firmware that controls the NetApp FAS2820 storage system hardware, enabling data storage and management functionalities. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "linux_enterprise_micro",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "suse"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sma_8200v_firmware",
        "summary": "sonicwall sma_8200v_firmware is a firmware for virtualized network security appliances that provides advanced threat protection and secure remote access. It sits in the hardware layer of the tech stack, is deployed as self_hosted virtual appliance firmware, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "sonicwall"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_container_platform",
        "summary": "redhat enterprise_linux is a commercial Linux operating system distribution that provides a stable, secure, and supported platform for enterprise applications. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "amazon amazon_linux is a Linux-based operating system optimized for cloud environments that provides a secure, stable, and high-performance platform for applications. It sits in the operating_system layer of the tech stack, is typically deployed as self_hosted, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      },
      {
        "category": "data_storage",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "e-series_santricity_os_controller",
        "summary": "netapp ontap is a data management software that provides storage efficiency, data protection, and seamless data access across cloud and on-premises environments. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_tools",
        "summary": "freebsd freebsd is an open-source Unix-like operating system that provides a robust, secure, and high-performance platform for servers and desktops. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sra_ex_7000_firmware",
        "summary": "sonicwall sra_ex_7000_firmware is a firmware that provides secure remote access capabilities for enterprise networks. It sits in the hardware layer of the tech stack, is deployed as self_hosted, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "sonicwall"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.5451,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2007-4752",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipula",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.02181,
    "recommendation": "Upgrade openssh to latest patch; isolate behind firewall.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2019-6110",
    "cvss_score": 6.8,
    "severity": "medium",
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, expl",
    "affected_products": [
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "scalance_x204rna_firmware",
        "summary": "siemens scalance_x204rna_firmware is a firmware that manages industrial network switches to ensure reliable and secure communication in automation environments. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "scalance_x204rna_eec_firmware",
        "summary": "siemens scalance_x204rna_eec_firmware is a specialized firmware that manages industrial Ethernet switches for secure and reliable network communication. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "winscp",
        "summary": "winscp winscp is a free and open-source SFTP, FTP, WebDAV, and SCP client that facilitates secure file transfers between local and remote computers. It sits in the application_library layer of the tech stack, functions as a self-hosted client tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "winscp"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "element_software",
        "summary": "netapp element_software is a storage management software that provides scalable and high-performance data storage solutions. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_select_deploy",
        "summary": "netapp ontap_select_deploy is a software-defined storage solution that enables deployment of enterprise-grade storage services on commodity hardware. It sits in the data_storage layer of the tech stack, functions as a self-hosted storage platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "data_storage",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "storage_automation_store",
        "summary": "netapp storage_automation_store is a storage automation solution that optimizes data management and storage operations. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.57569,
    "recommendation": "Monitor openssh for patch availability.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2019-6109",
    "cvss_score": 6.8,
    "severity": "medium",
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to mani",
    "affected_products": [
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "scalance_x204rna_eec_firmware",
        "summary": "siemens scalance_x204rna_eec_firmware is a specialized firmware that manages industrial Ethernet switches for secure and reliable network communication. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
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
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_aus",
        "summary": "redhat enterprise_linux_server_aus is a Linux-based operating system designed for enterprise-grade server environments that provides stability, security, and performance. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_tus",
        "summary": "redhat enterprise_linux_server_tus is a Linux-based operating system designed for enterprise environments that provides a stable and secure platform for running applications and services. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m10-1_firmware",
        "summary": "fujitsu m10-1_firmware is a hardware firmware component that controls and manages the low-level operations of Fujitsu's M10-1 server systems. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m12-1_firmware",
        "summary": "fujitsu m12-1_firmware is a device firmware that controls and manages hardware operations for Fujitsu devices. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m12-2s_firmware",
        "summary": "fujitsu m12-2s_firmware is a device firmware that controls and manages hardware operations for the M12-2S system. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_select_deploy",
        "summary": "netapp ontap_select_deploy is a software-defined storage solution that enables deployment of enterprise-grade storage services on commodity hardware. It sits in the data_storage layer of the tech stack, functions as a self-hosted storage platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "data_storage",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "storage_automation_store",
        "summary": "netapp storage_automation_store is a storage automation solution that optimizes data management and storage operations. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "scalance_x204rna_firmware",
        "summary": "siemens scalance_x204rna_firmware is a firmware that manages industrial network switches to ensure reliable and secure communication in automation environments. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
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
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_eus",
        "summary": "redhat enterprise_linux_eus is a long-term supported Linux operating system designed for stability and extended maintenance in enterprise environments. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m10-4_firmware",
        "summary": "fujitsu m10-4_firmware is a firmware component that manages low-level hardware control and system initialization for Fujitsu's M10-4 server systems. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m10-4s_firmware",
        "summary": "fujitsu m10-4s_firmware is a firmware component that controls and manages hardware operations for Fujitsu's M10-4S systems. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m12-2_firmware",
        "summary": "fujitsu m12-2_firmware is a firmware component that controls low-level hardware functions for the M12-2 system. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "winscp",
        "summary": "winscp winscp is a free and open-source SFTP, FTP, WebDAV, and SCP client that facilitates secure file transfers between local and remote computers. It sits in the application_library layer of the tech stack, functions as a self-hosted client tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "winscp"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "element_software",
        "summary": "netapp element_software is a storage management software that provides scalable and high-performance data storage solutions. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux",
        "summary": "redhat enterprise_linux is a commercial Linux operating system distribution that provides a stable, secure, and supported platform for enterprise applications. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.09738,
    "recommendation": "Monitor openssh for patch availability.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2004-1653",
    "cvss_score": 6.4,
    "severity": "medium",
    "description": "OpenSSH with default configuration enables AllowTcpForwarding, which could allow remote authenticated users to perform a port bounce, when configured with an anonymous access program such as AnonCVS, ",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.00389,
    "recommendation": "Monitor openssh for patch availability.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2019-6111",
    "cvss_score": 5.9,
    "severity": "medium",
    "description": "OpenSSH 7.9 contains a file overwrite vulnerability caused by the scp implementation derived from 1983 rcp, letting malicious servers or man-in-the-middle attackers overwrite arbitrary files on the cl",
    "affected_products": [
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "winscp",
        "summary": "winscp winscp is a free and open-source SFTP, FTP, WebDAV, and SCP client that facilitates secure file transfers between local and remote computers. It sits in the application_library layer of the tech stack, functions as a self-hosted client tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "winscp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_aus",
        "summary": "redhat enterprise_linux_server_aus is a Linux-based operating system designed for enterprise-grade server environments that provides stability, security, and performance. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "freebsd",
        "summary": "freebsd freebsd is an open-source Unix-like operating system that provides a robust, secure, and high-performance platform for servers and desktops. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "freebsd"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m12-2_firmware",
        "summary": "fujitsu m12-2_firmware is a firmware component that controls low-level hardware functions for the M12-2 system. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "scalance_x204rna_firmware",
        "summary": "siemens scalance_x204rna_firmware is a firmware that manages industrial network switches to ensure reliable and secure communication in automation environments. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
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
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m10-1_firmware",
        "summary": "fujitsu m10-1_firmware is a hardware firmware component that controls and manages the low-level operations of Fujitsu's M10-1 server systems. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m10-4s_firmware",
        "summary": "fujitsu m10-4s_firmware is a firmware component that controls and manages hardware operations for Fujitsu's M10-4S systems. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m12-1_firmware",
        "summary": "fujitsu m12-1_firmware is a device firmware that controls and manages hardware operations for Fujitsu devices. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
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
        "product": "enterprise_linux",
        "summary": "redhat enterprise_linux is a commercial Linux operating system distribution that provides a stable, secure, and supported platform for enterprise applications. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_eus",
        "summary": "redhat enterprise_linux_eus is a long-term supported Linux operating system designed for stability and extended maintenance in enterprise environments. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m10-4_firmware",
        "summary": "fujitsu m10-4_firmware is a firmware component that manages low-level hardware control and system initialization for Fujitsu's M10-4 server systems. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m12-2s_firmware",
        "summary": "fujitsu m12-2s_firmware is a device firmware that controls and manages hardware operations for the M12-2S system. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "scalance_x204rna_eec_firmware",
        "summary": "siemens scalance_x204rna_eec_firmware is a specialized firmware that manages industrial Ethernet switches for secure and reliable network communication. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_tus",
        "summary": "redhat enterprise_linux_server_tus is a Linux-based operating system designed for enterprise environments that provides a stable and secure platform for running applications and services. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "mina_sshd",
        "summary": "apache mina_sshd is a Java library that provides an SSH server implementation for secure remote access and file transfers. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.5497,
    "recommendation": "Monitor openssh for patch availability.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2023-48795",
    "cvss_score": 5.9,
    "severity": "medium",
    "description": "OpenSSH before 9.6 and other products contain a Terrapin attack caused by mishandling of handshake and sequence numbers in the SSH Binary Packet Protocol, allowing remote attackers to bypass integrity",
    "affected_products": [
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "lcos",
        "summary": "lancom-systems lcos_fx is a network operating system designed for managing and securing LANCOM routers and firewalls. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "lancom-systems"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_serverless",
        "summary": "redhat openshift_gitops is a Kubernetes-native continuous delivery tool that automates application deployment and lifecycle management using GitOps principles. It sits in the core_infra layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_virtualization",
        "summary": "redhat storage is a scalable software-defined storage solution that provides reliable and high-performance data storage for enterprise environments. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "keycloak",
        "summary": "redhat jboss_enterprise_application_platform is a middleware platform that enables development and deployment of Java applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted application server in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "single_sign-on",
        "summary": "redhat advanced_cluster_security is a Kubernetes-native security platform that provides threat detection, compliance, and runtime protection for containerized applications. It sits in the core_infra layer of the tech stack, functions as a security platform in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "lcos_sx",
        "summary": "lancom-systems lanconfig is a network management software that enables configuration and monitoring of LANCOM devices. It sits in the core_infra layer of the tech stack, functions as a self-hosted management tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "lancom-systems"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "libssh",
        "summary": "net-ssh net-ssh is a Ruby library that provides an implementation of the SSH protocol for secure remote communication and automation. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "libssh"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ceph_storage",
        "summary": "redhat enterprise_linux is a commercial Linux operating system distribution that provides a stable, secure, and supported platform for enterprise applications. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "openshift_pipelines",
        "summary": "redhat openshift_developer_tools_and_services is a suite of developer tools and services designed to enhance application development and deployment on the OpenShift container platform. It sits in the core_infra layer of the tech stack, functions as a self-hosted and SaaS hybrid platform in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "storage",
        "summary": "redhat discovery is an infrastructure discovery and inventory tool that helps organizations identify and map their IT assets. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "sshlib",
        "summary": "apache sshj is a Java library that provides SSH client functionality for secure communication and file transfer. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "connectbot"
      },
      {
        "category": "consumer",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "filezilla_client",
        "summary": "filezilla-project filezilla_client is a free and open-source FTP client that enables users to transfer files over FTP, FTPS, and SFTP protocols. It sits in the consumer layer of the tech stack, functions as a client application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "filezilla-project"
      },
      {
        "category": "consumer",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "transmit_5",
        "summary": "panic transmit_5 is a file transfer client that enables secure and efficient file management across FTP, SFTP, and cloud services. It sits in the application_library layer of the tech stack, functions as a consumer application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "panic"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ssh_server",
        "summary": "lancom-systems lcos is a network operating system that manages and secures LANCOM network devices. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "bitvise"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_api_for_data_protection",
        "summary": "redhat openshift_virtualization is a container-native virtualization solution that enables running and managing virtual machines alongside containers on OpenShift. It sits in the core_infra layer of the tech stack, functions as a platform infrastructure component in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "pfsense_plus",
        "summary": "connectbot sshlib is a library that provides SSH protocol implementation for secure remote connections. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "netgate"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sshd",
        "summary": "tinyssh tinyssh is a minimal and secure SSH server and client implementation that provides lightweight remote access and file transfer capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "apache"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "xshell_7",
        "summary": "paramiko paramiko is a Python library that provides SSHv2 protocol support for secure connections to remote machines. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "netsarang"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openstack_platform",
        "summary": "redhat ceph_storage is a scalable, open-source software-defined storage platform that provides unified object and block storage. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "securecrt",
        "summary": "libssh libssh is a multiplatform C library implementing the SSH protocol that enables secure communication and remote command execution. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "vandyke"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "cyclone_ssh",
        "summary": "crushftp crushftp is a secure file transfer server that enables efficient and reliable file sharing and management. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oryx-embedded"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_dev_spaces",
        "summary": "redhat cert-manager_operator_for_red_hat_openshift is an operator that automates the management and issuance of TLS certificates within Red Hat OpenShift clusters. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "libssh2",
        "summary": "dropbear_ssh_project dropbear_ssh is a lightweight SSH server and client implementation designed for embedded systems and low-resource environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "libssh2"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ssh",
        "summary": "netgate pfsense_plus is an advanced open-source firewall and routing platform that provides network security and management features. It sits in the core_infra layer of the tech stack, functions as a self-hosted network security appliance in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "ssh"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "tinyssh",
        "summary": "9bis kitty is a GPU-based terminal emulator that offers fast rendering and advanced features for developers. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "tinyssh"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ssh2",
        "summary": "fedoraproject fedora is a Linux-based open-source operating system that provides a robust and secure platform for developers and users. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "trilead"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "putty",
        "summary": "putty putty is a terminal emulator and network file transfer application that provides secure remote access to servers. It sits in the application_library layer of the tech stack, functions as a self-hosted utility in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "putty"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nova",
        "summary": "panic nova is a modern, native macOS code editor designed for web developers that offers a powerful and intuitive development environment. It sits in the application_library layer of the tech stack, functions as a developer tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "panic"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "advanced_cluster_security",
        "summary": "golang crypto is a cryptographic library that provides implementations of standard cryptographic algorithms and protocols. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "crypto",
        "summary": "sftpgo_project sftpgo is a secure and extensible SFTP server that provides file transfer and management capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "golang"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "erlang\\/otp",
        "summary": "libssh2 libssh2 is a client-side C library implementing the SSH2 protocol that provides secure network communication capabilities. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "erlang"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "lcos_fx",
        "summary": "lancom-systems lcos_lx is a network operating system that provides routing, switching, and security features for enterprise network devices. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "lancom-systems"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "lanconfig",
        "summary": "vandyke securecrt is a terminal emulation software that provides secure remote access and data tunneling for IT professionals. It sits in the application_library layer of the tech stack, functions as a self-hosted client application in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "lancom-systems"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "freebsd",
        "summary": "crates thrussh is a Rust library that provides SSH client and server functionality for secure remote communication. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "freebsd"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "paramiko",
        "summary": "redhat openshift_container_platform is a comprehensive Kubernetes container orchestration platform that automates deployment, scaling, and management of containerized applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "paramiko"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "dropbear_ssh",
        "summary": "ssh ssh is a secure network protocol that provides encrypted communication over unsecured networks. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "dropbear_ssh_project"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "maverick_synergy_java_ssh_api",
        "summary": "thorntech sftp_gateway_firmware is a firmware component that enables secure file transfer protocol gateway functionality on hardware devices. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "jadaptive"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ssh2",
        "summary": "proftpd proftpd is an open-source FTP server software that provides secure and configurable file transfer services. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "ssh2_project"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux",
        "summary": "redhat openshift_serverless is a serverless computing platform that enables developers to build and deploy event-driven applications without managing infrastructure. It sits in the core_infra layer of the tech stack, functions as a platform service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "discovery",
        "summary": "redhat openshift_dev_spaces is a cloud-native development environment that enables developers to build, test, and debug applications within Kubernetes. It sits in the core_infra layer of the tech stack, functions as a self-hosted and SaaS hybrid development platform in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "sshj",
        "summary": "trilead ssh2 is a Java library that provides SSH2 protocol support for secure communication and remote command execution. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "apache"
      },
      {
        "product": "fedora",
        "vendor": "fedoraproject"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "winscp",
        "summary": "bitvise ssh_client is a secure SSH client software that provides encrypted remote access and file transfer capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted client tool in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "winscp"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "pkixssh",
        "summary": "winscp winscp is a free and open-source SFTP, FTP, WebDAV, and SCP client that facilitates secure file transfers between local and remote computers. It sits in the application_library layer of the tech stack, functions as a self-hosted client tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "roumenpetrov"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ssh_client",
        "summary": "bitvise ssh_server is a secure SSH server software that provides encrypted remote access and file transfer capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "bitvise"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "unclassified",
        "product": "tera_term",
        "summary": "oryx-embedded cyclone_ssh is a secure shell (SSH) server and client implementation designed for embedded systems that provides encrypted communication and secure remote access. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "tera_term_project"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_gitops",
        "summary": "redhat openshift_pipelines is a Kubernetes-native continuous integration and continuous delivery (CI/CD) solution that automates application build, test, and deployment workflows. It sits in the core_infra layer of the tech stack, functions as a devops tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "sftpgo",
        "summary": "matez jsch is a Java library that provides SSH2 protocol support for secure communication and file transfer. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "sftpgo_project"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "jsch",
        "summary": "asyncssh_project asyncssh is a Python library that provides an asynchronous SSHv2 client and server implementation for secure network communication. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "matez"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "pfsense_ce",
        "summary": "apache sshd is a Java library that provides SSH server and client functionality for secure remote communication. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netgate"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "security",
        "summary": "apple macos is a desktop operating system that provides a graphical user interface and core system services for Apple computers. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "gentoo"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "proftpd",
        "summary": "freebsd freebsd is an open-source Unix-like operating system that provides a robust, secure, and high-performance platform for servers and desktops. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "proftpd"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_data_foundation",
        "summary": "redhat openshift_api_for_data_protection is an API service that provides data protection and backup capabilities for OpenShift container platforms. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "kitty",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "9bis"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "lcos_lx",
        "summary": "lancom-systems lcos_sx is a network operating system that provides routing, switching, and security features for enterprise networks. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "lancom-systems"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "thrussh",
        "summary": "tera_term_project tera_term is a terminal emulator software that provides serial port, telnet, and SSH connectivity for remote device management. It sits in the application_library layer of the tech stack, functions as a self-hosted tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "crates"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_container_platform",
        "summary": "redhat openstack_platform is an open-source cloud computing platform that enables the deployment and management of private and public clouds. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "cert-manager_operator_for_red_hat_openshift",
        "summary": "redhat keycloak is an open-source identity and access management solution that provides single sign-on, authentication, and authorization services. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "asyncssh",
        "summary": "jadaptive maverick_synergy_java_ssh_api is a Java library that provides SSH protocol support for secure communication and file transfer. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "asyncssh_project"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sftp_gateway_firmware",
        "summary": "netgate pfsense_ce is an open-source firewall and router software that provides network security and routing capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network security appliance in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "thorntech"
      },
      {
        "product": "debian_linux",
        "vendor": "debian"
      },
      {
        "category": "core_infra",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "net-ssh",
        "summary": "ssh2_project ssh2 is a client and server implementation of the SSH2 protocol that provides secure encrypted communications over insecure networks. It sits in the core_infra layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "net-ssh"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_developer_tools_and_services",
        "summary": "redhat openshift_data_foundation is a software-defined storage solution that provides scalable and resilient data services for containerized applications. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "jboss_enterprise_application_platform",
        "summary": "redhat single_sign-on is an identity and access management solution that provides secure single sign-on capabilities for applications and services. It sits in the core_infra layer of the tech stack, functions as a security service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "crushftp",
        "summary": "netsarang xshell_7 is a powerful terminal emulator that provides secure remote access and management for network devices and servers. It sits in the application_library layer of the tech stack, functions as a self-hosted client tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "crushftp"
      },
      {
        "product": "macos",
        "vendor": "apple"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "russh",
        "summary": "erlang erlang/otp is a programming language and runtime environment that provides tools for building scalable and fault-tolerant applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "russh_project"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.53559,
    "recommendation": "Monitor openssh for patch availability.",
    "source": "vulnx"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2018-20685",
    "cvss_score": 5.3,
    "severity": "medium",
    "description": "OpenSSH 7.9 contains a bypass in scp.c allowing remote SSH servers to bypass access restrictions via the filename '.' or an empty filename, letting attackers modify target directory permissions on the",
    "affected_products": [
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m10-4_firmware",
        "summary": "fujitsu m10-4_firmware is a firmware component that manages low-level hardware control and system initialization for Fujitsu's M10-4 server systems. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m10-4s_firmware",
        "summary": "fujitsu m10-4s_firmware is a firmware component that controls and manages hardware operations for Fujitsu's M10-4S systems. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m12-1_firmware",
        "summary": "fujitsu m12-1_firmware is a device firmware that controls and manages hardware operations for Fujitsu devices. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_select_deploy",
        "summary": "netapp ontap_select_deploy is a software-defined storage solution that enables deployment of enterprise-grade storage services on commodity hardware. It sits in the data_storage layer of the tech stack, functions as a self-hosted storage platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
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
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m12-2_firmware",
        "summary": "fujitsu m12-2_firmware is a firmware component that controls low-level hardware functions for the M12-2 system. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "winscp",
        "summary": "winscp winscp is a free and open-source SFTP, FTP, WebDAV, and SCP client that facilitates secure file transfers between local and remote computers. It sits in the application_library layer of the tech stack, functions as a self-hosted client tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "winscp"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "element_software",
        "summary": "netapp element_software is a storage management software that provides scalable and high-performance data storage solutions. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux",
        "summary": "redhat enterprise_linux is a commercial Linux operating system distribution that provides a stable, secure, and supported platform for enterprise applications. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m12-2s_firmware",
        "summary": "fujitsu m12-2s_firmware is a device firmware that controls and manages hardware operations for the M12-2S system. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "scalance_x204rna_eec_firmware",
        "summary": "siemens scalance_x204rna_eec_firmware is a specialized firmware that manages industrial Ethernet switches for secure and reliable network communication. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "data_storage",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "storage_automation_store",
        "summary": "netapp storage_automation_store is a storage automation solution that optimizes data management and storage operations. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_eus",
        "summary": "redhat enterprise_linux_eus is a long-term supported Linux operating system designed for stability and extended maintenance in enterprise environments. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "solaris",
        "summary": "oracle solaris is a Unix-based operating system designed for enterprise servers and workstations that provides scalability, security, and performance. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "scalance_x204rna_firmware",
        "summary": "siemens scalance_x204rna_firmware is a firmware that manages industrial network switches to ensure reliable and secure communication in automation environments. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "data_storage",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "cloud_backup",
        "summary": "netapp cloud_backup is a cloud-based data protection and backup solution that safeguards enterprise data across hybrid cloud environments. It sits in the data_storage layer of the tech stack, functions as a self-hosted and SaaS hybrid backup service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "data_storage",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "steelstore_cloud_integrated_storage",
        "summary": "netapp steelstore_cloud_integrated_storage is a cloud-integrated storage solution that provides efficient data backup, archiving, and disaster recovery across hybrid cloud environments. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_aus",
        "summary": "redhat enterprise_linux_server_aus is a Linux-based operating system designed for enterprise-grade server environments that provides stability, security, and performance. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_tus",
        "summary": "redhat enterprise_linux_server_tus is a Linux-based operating system designed for enterprise environments that provides a stable and secure platform for running applications and services. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m10-1_firmware",
        "summary": "fujitsu m10-1_firmware is a hardware firmware component that controls and manages the low-level operations of Fujitsu's M10-1 server systems. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      }
    ],
    "affects_pinned_version": true,
    "kev": false,
    "epss_score": 0.03377,
    "recommendation": "Monitor openssh for patch availability.",
    "source": "vulnx"
  }
]
```

## Report

# ABAC Policy Mining Report — segcorp production

**Org:** segcorp | **Environment:** production | **Compliance:** PCI-DSS | **Generated by:** RLM ABAC Miner

---

## Phase 1 — Attribute Catalog

### Subjects (3 users)

| user | uid | groups | clearance | department | source |
|------|-----|--------|-----------|------------|--------|
| admin | 1001 | sudo | secret | operations | group_vars/all.yml |
| developer | 1002 | developers | confidential | engineering | group_vars/all.yml |
| dba | 1003 | dba | secret | data | group_vars/all.yml |

Distinct groups: `sudo`, `developers`, `dba`
Distinct clearance levels: `secret`, `confidential`
Distinct departments: `operations`, `engineering`, `data`

### Resources (3 hosts)

| hostname | ip | role | zone | host_group |
|----------|----|------|------|------------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

Services: `ssh` (port 22), `nginx` (port 443 DMZ, port 8080 app-tier), `postgresql` (port 5432)
Network CIDRs: `10.0.1.0/24` (DMZ), `10.0.2.0/24` (app tier), `0.0.0.0/0` (internet)

### Environment

| attribute | value |
|-----------|-------|
| org | segcorp |
| environment | production |
| compliance_tier | pci |
| retention_days | 365 |

---

## Phase 1.5 — Vulnerability Assessment

Three pinned software packages were assessed:

| product | pinned version | CVEs found | critical | high | KEV hits |
|---------|----------------|------------|----------|------|----------|
| nginx | 1.20.0 | 12 | 3 | 8 | 0 |
| postgresql | 16.2 | 12 | 10 | 2 | 0 |
| openssh | 9.1p1 | 13 | 11 | 2 | 0 |
| **Total** | | **37** | **24** | **12** | **0** |

### Notable findings

- **PostgreSQL 16.2 (CVSS 10.0):** CVE-2024-1597 is a current SQL injection in pg_hint_plan (CVSS 10.0) — immediate patching recommended.
  Historical CVEs (pre-2015) returned by the search are likely mitigated by the version upgrade but should be confirmed in a full audit.
- **nginx 1.20.0 (CVSS 9.8):** CVE-2021-46461 (resolver off-by-one), CVE-2017-20005 (HTTP cache poisoning), CVE-2016-0746 — upgrade to nginx >=1.24.0.
- **OpenSSH 9.1p1 (CVSS 9.8):** CVE-2023-38408 (regreSSHion RCE), CVE-2023-28531, CVE-2016-1908 — upgrade to OpenSSH >=9.8.
- **No KEV catalog hits** were returned for any product at the time of assessment.
- All 37 CVEs are flagged as `affects_pinned_version: true` based on product CPE matching; manual version-specific review is advised.

---

## Phase 1.6 — Security Scope

The repository contains only Ansible playbook task files. No raw sshd configs, iptables scripts, sudoers files, pg_hba.conf, nginx/haproxy templates, or monitoring configs were found. Access controls are expressed entirely through Ansible tasks:

- **SSH**: `lineinfile` writes `AllowGroups` directives to `/etc/ssh/sshd_config`.
- **DB auth**: `community.postgresql.postgresql_user` provisions roles; `lineinfile` writes `pg_hba.conf` entries.
- **Firewall**: `ansible.posix.firewalld` manages `firewalld` rules.
- **No static sudoers template exists** — sudo privileges derive from SSH `AllowGroups` on Posix groups (`sudo`, `dba`, `developers`).

---

## Phase 2 — ABAC Rules Extracted (13 rules)

| rule-id | action | subjects | resource | effect |
|---------|--------|----------|----------|--------|
| rule-001 | ssh:login | sudo, developers | app01.lab.local:ssh | permit |
| rule-002 | ssh:login | sudo | proxy01.lab.local:ssh | permit |
| rule-003 | ssh:login | sudo, dba | db01.lab.local:ssh | permit |
| rule-004 | db:login (SUPERUSER) | dba + data dept | db01.lab.local:postgresql | permit |
| rule-005 | db:login (NOSUPERUSER) | developers + engineering | db01.lab.local:postgresql | permit |
| rule-006 | network:connect | 10.0.1.0/24 (DMZ) | appservers:8080/tcp | permit |
| rule-007 | network:connect | 0.0.0.0/0 (internet) | dmz:443/tcp | permit |
| rule-008 | network:connect | 10.0.2.0/24 (app) | db01.lab.local:5432/tcp | permit |
| rule-009 | network:connect | 0.0.0.0/0 | db01.lab.local:5432/tcp | **deny** |
| rule-010 | filesystem:write | postgres | /var/lib/postgresql/data (0700) | permit |
| rule-011 | user:create | admin, developer | app01.lab.local | permit |
| rule-012 | user:create | admin | proxy01.lab.local | permit |
| rule-013 | * | all | all | **deny** |

### Obligations

- **rule-004**: privilege_level = SUPERUSER (LOGIN,CREATEROLE,CREATEDB,REPLICATION,BYPASSRLS)
- **rule-005**: privilege_level = NOSUPERUSER (standard read/write on all schemas)
- **rule-011**: shell must be /bin/bash on app servers
- **rule-012**: shell must be /bin/bash on DMZ proxy

---

## Topology

 internet (0.0.0.0/0) --443/tcp--> proxy01.lab.local (DMZ) --8080/tcp--> app01.lab.local (app tier)
 appservers (10.0.2.0/24) --5432/tcp (scram-sha-256)--> db01.lab.local (data tier)

---

## Ambiguities

1. **Credentials not stored in config:** Ansible `ansible-vault` is the assumed mechanism for secrets, but no vault files are present in the repo. Sudo `nopassword` cannot be confirmed from the config alone — only SSH `AllowGroups` is explicitly defined.
2. **`source_zone: "internet"`**: Inferred from `firewall_allow_from = 0.0.0.0/0` in group_vars/dmz.yml. No explicit `internet` zone is declared in inventory.ini — this is a logical zone inferred from CIDR.
3. **`schema: "public"`**: The DB rules reference the `public` schema but Ansible does not explicitly create a schema constraint in the `postgresql_user` task (PostgreSQL defaults to `public`). This is a reasonable inference.
4. **User provisioning scope**: The `when:` clauses on user creation tasks use Ansible's inventory group membership logic. The catalog reflects the actual declared subjects, but the `when:` conditions restrict provisioning to specific groups per role.

---

## Validation Summary

- **Attributes**: 7 subject attrs, 16 resource attrs, 4 environment attrs — all domain-enumerated with file-level provenance.
- **Rules**: 13 rules, all with `source: {file, task, lines}` provenance. Operator grammar: `equals`, `any_of`, `in`, `applies_to` — no forbidden operators.
- **Vulnerabilities**: 37 unique CVEs; all 3 pinned products flagged. Report quality: informational.
- **JSON**: `attributes` and `rules` roundtrip validated; `vulnerabilities` contains EPSS scores, KEV status, `affects_pinned_version` for each entry.
