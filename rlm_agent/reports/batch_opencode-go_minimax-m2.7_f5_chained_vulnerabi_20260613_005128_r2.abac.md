# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:00:57_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "type": "string",
      "description": "Username of the subject",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "description": "Unix user ID",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "description": "Unix groups the user belongs to",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "string",
      "description": "Security clearance level",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "string",
      "description": "Department",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source": {
      "type": "string",
      "description": "Origin of user account",
      "domain": [
        "ansible"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hostname": {
      "type": "string",
      "description": "Hostname of the target host",
      "domain": [
        "bastion01.lab.local",
        "web01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "description": "IP address of the host",
      "source": "inventory.ini"
    },
    "role": {
      "type": "string",
      "description": "Functional role of the host",
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "string",
      "description": "Network zone",
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "inventory_group": {
      "type": "string",
      "description": "Ansible inventory group membership",
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
      "type": "string",
      "description": "Network service name",
      "domain": [
        "ssh",
        "http",
        "postgresql",
        "app"
      ],
      "source": "group_vars/*.yml"
    },
    "port": {
      "type": "integer",
      "description": "TCP port number",
      "source": "group_vars/*.yml"
    },
    "protocol": {
      "type": "string",
      "description": "Network protocol",
      "domain": [
        "tcp"
      ],
      "source": "roles/*/tasks/main.yml"
    },
    "host_group": {
      "type": "string",
      "description": "Ansible inventory group for host membership",
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "database": {
      "type": "string",
      "description": "PostgreSQL database name",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "db_privilege": {
      "type": "string",
      "description": "PostgreSQL privilege level assigned to user",
      "domain": [
        "SUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "source_ip": {
      "type": "string",
      "description": "Source IP address or CIDR for network rules",
      "source": "group_vars/*.yml"
    },
    "path": {
      "type": "string",
      "description": "Filesystem path",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "string",
      "description": "File owner",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "string",
      "description": "File group",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "description": "File permission mode (octal string)",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "nopassword": {
      "type": "boolean",
      "description": "Whether sudo requires a password",
      "source": "roles/bastion/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "string",
      "description": "Organization name",
      "domain": [
        "chaincorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "string",
      "description": "Deployment environment",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "string",
      "description": "Compliance framework tier",
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml, inventory.ini"
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "SSH login to bastion host for members of sudo or dba groups",
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
        "equals": "bastion01.lab.local"
      },
      "service": {
        "equals": "ssh"
      },
      "zone": {
        "equals": "mgmt"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        6,
        9
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "SSH login to web server for members of sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        12,
        15
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "SSH login to app server for members of sudo or developers groups",
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        22,
        25
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "SSH login to database server for members of sudo or dba groups",
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        24,
        27
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Sudo on bastion for secret-clearance sudo-group users (password required)",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      }
    },
    "action": "sudoers:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "password_required",
        "detail": "nopassword=false enforced via sudoers rule"
      }
    ],
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        18,
        23
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow SSH/TCP from any source to bastion (internet-facing jump host)",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "port": {
        "equals": 22
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        11,
        16
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow HTTP/TCP from bastion subnet (10.0.0.0/24) to web servers",
    "subject_condition": {
      "source_ip": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "port": {
        "equals": 80
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        6,
        10
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Allow application port TCP from web subnet (10.0.1.0/24) to app servers",
    "subject_condition": {
      "source_ip": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
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
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        17,
        21
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Allow PostgreSQL/TCP from appservers subnet (10.0.2.0/24) to database server",
    "subject_condition": {
      "source_ip": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
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
        14,
        17
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "PostgreSQL superuser login for dba group members",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      "database": {
        "equals": "all"
      },
      "db_privilege": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
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
        9,
        12
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "PostgreSQL data directory ownership and permissions — owned by postgres, mode 0700",
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
        5,
        9
      ]
    }
  },
  {
    "rule_id": "rule-999",
    "description": "Default deny — all access not explicitly permitted above is denied",
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
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "inventory.ini, group_vars/all.yml",
      "task": "Default deny policy",
      "lines": [
        1,
        99
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
      "port": {
        "equals": 80
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
    "id": "rule-003",
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
    "id": "rule-004",
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
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "Ancient 2000 vulnerability, OpenSSH 9.1p1 far exceeds fix",
    "hosts_affected": [
      "bastion01.lab.local",
      "web01.lab.local",
      "app01.lab.local"
    ],
    "recommendation": "OpenSSH version is recent; ensure patch level is current per Ubuntu security notices."
  },
  {
    "cve_id": "CVE-2002-0639",
    "product": "openssh",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "2002 vulnerability, OpenSSH 9.x long fixed",
    "hosts_affected": [
      "bastion01.lab.local",
      "web01.lab.local",
      "app01.lab.local"
    ],
    "recommendation": "OpenSSH version is recent; ensure patch level is current per Ubuntu security notices."
  },
  {
    "cve_id": "CVE-2002-0083",
    "product": "openssh",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "2002 privilege separation issue, fixed in 3.3+",
    "hosts_affected": [
      "bastion01.lab.local",
      "web01.lab.local",
      "app01.lab.local"
    ],
    "recommendation": "OpenSSH version is recent; ensure patch level is current per Ubuntu security notices."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "2003 vulnerability in pre-3.7 versions",
    "hosts_affected": [
      "bastion01.lab.local",
      "web01.lab.local",
      "app01.lab.local"
    ],
    "recommendation": "OpenSSH version is recent; ensure patch level is current per Ubuntu security notices."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "2003 KARPAuthorization bypass, fixed in 3.7.1+",
    "hosts_affected": [
      "bastion01.lab.local",
      "web01.lab.local",
      "app01.lab.local"
    ],
    "recommendation": "OpenSSH version is recent; ensure patch level is current per Ubuntu security notices."
  },
  {
    "cve_id": "CVE-2017-3167",
    "product": "httpd",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "mod_ssl NULL pointer, fixed in 2.4.26, deployed version is 2.4.49",
    "hosts_affected": [
      "web01.lab.local"
    ],
    "recommendation": "UPGRADE to Apache httpd 2.4.51+ immediately. CVE-2021-42013 allows RCE via path traversal on mod_cgi."
  },
  {
    "cve_id": "CVE-2017-3169",
    "product": "httpd",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "mod_ssl NULL pointer, fixed in 2.4.26, deployed version is 2.4.49",
    "hosts_affected": [
      "web01.lab.local"
    ],
    "recommendation": "UPGRADE to Apache httpd 2.4.51+ immediately. CVE-2021-42013 allows RCE via path traversal on mod_cgi."
  },
  {
    "cve_id": "CVE-2017-7679",
    "product": "httpd",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "mod_http2 vulnerability, fixed in 2.4.26+",
    "hosts_affected": [
      "web01.lab.local"
    ],
    "recommendation": "UPGRADE to Apache httpd 2.4.51+ immediately. CVE-2021-42013 allows RCE via path traversal on mod_cgi."
  },
  {
    "cve_id": "CVE-2017-9788",
    "product": "httpd",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "Uninitialized memory in mod_auth_digest, fixed in 2.4.26+",
    "hosts_affected": [
      "web01.lab.local"
    ],
    "recommendation": "UPGRADE to Apache httpd 2.4.51+ immediately. CVE-2021-42013 allows RCE via path traversal on mod_cgi."
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "httpd",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "Apache Tomcat vulnerability, not HTTPD 2.4.49",
    "hosts_affected": [
      "web01.lab.local"
    ],
    "recommendation": "UPGRADE to Apache httpd 2.4.51+ immediately. CVE-2021-42013 allows RCE via path traversal on mod_cgi."
  },
  {
    "cve_id": "CVE-2018-1312",
    "product": "httpd",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "mod_session hash collision DoS, fixed in 2.4.26+",
    "hosts_affected": [
      "web01.lab.local"
    ],
    "recommendation": "UPGRADE to Apache httpd 2.4.51+ immediately. CVE-2021-42013 allows RCE via path traversal on mod_cgi."
  },
  {
    "cve_id": "CVE-2020-11984",
    "product": "httpd",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "CGI proxy vulnerability, fixed in 2.4.46+",
    "hosts_affected": [
      "web01.lab.local"
    ],
    "recommendation": "UPGRADE to Apache httpd 2.4.51+ immediately. CVE-2021-42013 allows RCE via path traversal on mod_cgi."
  },
  {
    "cve_id": "CVE-2021-41773",
    "product": "httpd",
    "affects_pinned_version": true,
    "severity": "HIGH",
    "cvss_score": 7.5,
    "reason": "Path traversal in 2.4.49 - YES this affects 2.4.49!",
    "hosts_affected": [
      "web01.lab.local"
    ],
    "recommendation": "UPGRADE to Apache httpd 2.4.51+ immediately. CVE-2021-42013 allows RCE via path traversal on mod_cgi."
  },
  {
    "cve_id": "CVE-2021-42013",
    "product": "httpd",
    "affects_pinned_version": true,
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "reason": "CVE-2021-41773 bypass - affects 2.4.49, fixed in 2.4.51",
    "hosts_affected": [
      "web01.lab.local"
    ],
    "recommendation": "UPGRADE to Apache httpd 2.4.51+ immediately. CVE-2021-42013 allows RCE via path traversal on mod_cgi."
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "affects_pinned_version": true,
    "severity": "CRITICAL",
    "cvss_score": 10.0,
    "reason": "Log4Shell RCE - AFFECTS log4j 2.14.1. Upgrade to 2.17.0+",
    "hosts_affected": [
      "app01.lab.local"
    ],
    "recommendation": "UPGRADE to log4j 2.17.1 or later. Remove log4j-core JAR and replace with patched version. Consider migrating to log4j 2.23+."
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "affects_pinned_version": true,
    "severity": "CRITICAL",
    "cvss_score": 9.0,
    "reason": "DOS vector in JNDI - AFFECTS 2.14.1. Upgrade to 2.16.0+",
    "hosts_affected": [
      "app01.lab.local"
    ],
    "recommendation": "UPGRADE to log4j 2.17.1 or later. Remove log4j-core JAR and replace with patched version. Consider migrating to log4j 2.23+."
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "Log4j1.x SQL appender, deployed version is 2.14.1",
    "hosts_affected": [
      "app01.lab.local"
    ],
    "recommendation": "UPGRADE to log4j 2.17.1 or later. Remove log4j-core JAR and replace with patched version. Consider migrating to log4j 2.23+."
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "XML decoding vulnerability, fixed in 2.13.0+",
    "hosts_affected": [
      "app01.lab.local"
    ],
    "recommendation": "UPGRADE to log4j 2.17.1 or later. Remove log4j-core JAR and replace with patched version. Consider migrating to log4j 2.23+."
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "affects_pinned_version": true,
    "severity": "HIGH",
    "cvss_score": 8.1,
    "reason": "SQL injection in JDBCAppender - AFFECTS log4j 2.x. Upgrade to 2.17.1+",
    "hosts_affected": [
      "app01.lab.local"
    ],
    "recommendation": "UPGRADE to log4j 2.17.1 or later. Remove log4j-core JAR and replace with patched version. Consider migrating to log4j 2.23+."
  },
  {
    "cve_id": "CVE-2022-23307",
    "product": "log4j",
    "affects_pinned_version": true,
    "severity": "HIGH",
    "cvss_score": 8.1,
    "reason": "JMSSink deserialization RCE - AFFECTS log4j 2.x. Upgrade to 2.17.1+",
    "hosts_affected": [
      "app01.lab.local"
    ],
    "recommendation": "UPGRADE to log4j 2.17.1 or later. Remove log4j-core JAR and replace with patched version. Consider migrating to log4j 2.23+."
  },
  {
    "cve_id": "CVE-2022-23302",
    "product": "log4j",
    "affects_pinned_version": true,
    "severity": "HIGH",
    "cvss_score": 8.1,
    "reason": " Chainsaw viewer XML RCE - AFFECTS log4j 2.x. Upgrade to 2.17.1+",
    "hosts_affected": [
      "app01.lab.local"
    ],
    "recommendation": "UPGRADE to log4j 2.17.1 or later. Remove log4j-core JAR and replace with patched version. Consider migrating to log4j 2.23+."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "2002 SQL injection, PG 9.2.3 long fixed",
    "hosts_affected": [
      "db01.lab.local"
    ],
    "recommendation": "MIGRATE to PostgreSQL 15+ (9.2.x is EOL). Apply all security patches for EOL version, or migrate to maintained branch."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "affects_pinned_version": false,
    "severity": "HIGH",
    "cvss_score": 7.0,
    "reason": "2007 vulnerability, PG 9.2.3 fixed",
    "hosts_affected": [
      "db01.lab.local"
    ],
    "recommendation": "MIGRATE to PostgreSQL 15+ (9.2.x is EOL). Apply all security patches for EOL version, or migrate to maintained branch."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "affects_pinned_version": true,
    "severity": "MEDIUM",
    "cvss_score": 6.5,
    "reason": "Fixed in 9.2.4, but 9.2.3 is vulnerable - UPGRADE to 9.2.4+",
    "hosts_affected": [
      "db01.lab.local"
    ],
    "recommendation": "MIGRATE to PostgreSQL 15+ (9.2.x is EOL). Apply all security patches for EOL version, or migrate to maintained branch."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "affects_pinned_version": true,
    "severity": "MEDIUM",
    "cvss_score": 5.0,
    "reason": "Random() seed exposure fixed in 9.2.4 - UPGRADE",
    "hosts_affected": [
      "db01.lab.local"
    ],
    "recommendation": "MIGRATE to PostgreSQL 15+ (9.2.x is EOL). Apply all security patches for EOL version, or migrate to maintained branch."
  },
  {
    "cve_id": "CVE-2015-0244",
    "product": "postgresql",
    "affects_pinned_version": true,
    "severity": "HIGH",
    "cvss_score": 7.5,
    "reason": "Memory corruption, fixed in 9.2.12 - UPGRADE from 9.2.3",
    "hosts_affected": [
      "db01.lab.local"
    ],
    "recommendation": "MIGRATE to PostgreSQL 15+ (9.2.x is EOL). Apply all security patches for EOL version, or migrate to maintained branch."
  },
  {
    "cve_id": "CVE-2015-3166",
    "product": "postgresql",
    "affects_pinned_version": true,
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "reason": "Double free in contrib modules, fixed in 9.4.0+",
    "hosts_affected": [
      "db01.lab.local"
    ],
    "recommendation": "MIGRATE to PostgreSQL 15+ (9.2.x is EOL). Apply all security patches for EOL version, or migrate to maintained branch."
  },
  {
    "cve_id": "CVE-2018-16850",
    "product": "postgresql",
    "affects_pinned_version": true,
    "severity": "HIGH",
    "cvss_score": 8.1,
    "reason": "SQL injection in postgresql_fdw, fixed in 10.5+",
    "hosts_affected": [
      "db01.lab.local"
    ],
    "recommendation": "MIGRATE to PostgreSQL 15+ (9.2.x is EOL). Apply all security patches for EOL version, or migrate to maintained branch."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "affects_pinned_version": true,
    "severity": "HIGH",
    "cvss_score": 8.8,
    "reason": "SQL injection via pg_cancel_backend, PG 9.2 EOL - migrate to PG 15+",
    "hosts_affected": [
      "db01.lab.local"
    ],
    "recommendation": "MIGRATE to PostgreSQL 15+ (9.2.x is EOL). Apply all security patches for EOL version, or migrate to maintained branch."
  }
]
```

## Report

# ABAC Policy Mining Report — chaincorp / production

## Executive Summary

An ABAC policy was mined from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`
(`eval_fixtures/f5_chained_vulnerabilities`). The configuration describes a 4-tier
production environment (bastion → web → app → database) governed by PCI-DSS
compliance requirements.

- **Organization**: chaincorp
- **Environment**: production (PCI-DSS)
- **Hosts**: 4 (bastion01, web01, app01, db01)
- **Users**: 3 (admin, developer, dba)
- **Rules extracted**: 12 (10 permits, 1 deny-explicit, 1 default-deny)
- **CVEs applicable to pinned versions**: 13 (2 CRITICAL, 5 HIGH, 3 MEDIUM)

---

## Phase 1 — Attribute Catalog

### Subjects

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| `user` | string | admin, developer, dba | group_vars/all.yml |
| `uid` | integer | 1001–1003 | group_vars/all.yml |
| `groups` | set | sudo, developers, dba | group_vars/all.yml |
| `clearance` | string | secret, confidential | group_vars/all.yml |
| `department` | string | operations, engineering, data | group_vars/all.yml |
| `source` | string | ansible | group_vars/all.yml |

### Subjects — Enumerated Groups

- `sudo` — operations/admin (secret clearance required for bastion sudo)
- `developers` — engineering/developer (confidential clearance)
- `dba` — data/dba (secret clearance)

### Resources

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| `hostname` | string | bastion01.lab.local, web01.lab.local, app01.lab.local, db01.lab.local | inventory.ini |
| `ip` | string | 10.0.0.5, 10.0.1.10, 10.0.2.10, 10.0.3.10 | inventory.ini |
| `role` | string | bastion, frontend, application, primary | inventory.ini |
| `zone` | string | mgmt, dmz, app, data | inventory.ini |
| `inventory_group` | string | bastion, webservers, appservers, dbservers, prod | inventory.ini |
| `service` | string | ssh, http, postgresql, app | group_vars/*.yml |
| `port` | integer | 22, 80, 5432, 8080 | group_vars/*.yml |
| `protocol` | string | tcp | roles/*/tasks/main.yml |
| `host_group` | string | bastion, webservers, appservers, dbservers | inventory.ini |
| `database` | string | all | roles/db/tasks/main.yml |
| `db_privilege` | string | SUPERUSER | roles/db/tasks/main.yml |
| `source_ip` | string | 10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24, 0.0.0.0/0 | group_vars/*.yml |
| `path` | string | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| `owner` | string | postgres | roles/db/tasks/main.yml |
| `group` | string | postgres | roles/db/tasks/main.yml |
| `mode` | string | 0700 | roles/db/tasks/main.yml |
| `nopassword` | boolean | true/false | roles/bastion/tasks/main.yml |

### Environment

| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| `org` | string | chaincorp | group_vars/all.yml |
| `environment` | string | production | inventory.ini |
| `compliance_tier` | string | pci | group_vars/all.yml, inventory.ini |

---

## Phase 1.5 — Vulnerability Assessment

### Identified Packages & Versions

| Product | Host(s) | Pinned Version | Source |
|---------|---------|----------------|--------|
| OpenSSH | bastion01 | 9.1p1-1ubuntu1 | group_vars/all.yml (ssh_version_bastion) |
| OpenSSH | web01, app01 | 9.9p1-3ubuntu1 | group_vars/all.yml (ssh_version) |
| Apache httpd | web01 | 2.4.49-1 | group_vars/all.yml (httpd_version) |
| Apache Log4j | app01 | 2.14.1 | group_vars/all.yml (log4j_version) |
| PostgreSQL | db01 | 9.2.3-1.pgdg20.04+1 | group_vars/all.yml (postgres_version) |

### Applicable Vulnerabilities (13 CVEs affect pinned versions)

#### CRITICAL

| CVE | Product | CVSS | Affects | Recommendation |
|-----|---------|------|---------|----------------|
| **CVE-2021-44228** | Log4j | 10.0 | 2.14.1 | **UPGRADE to log4j 2.17.1+ immediately.** Log4Shell RCE — allows remote code execution via crafted JNDI lookup. Remove log4j-core JAR from /opt/app/lib/ and replace with patched version. Consider migrating to log4j 2.23+. |
| **CVE-2021-45046** | Log4j | 9.0 | 2.14.1 | **UPGRADE to log4j 2.16.0+.** Denial-of-service vector via JNDI lookup in log4j 2.x series. Apply alongside CVE-2021-44228 patch. |
| **CVE-2021-42013** | httpd | 9.8 | 2.4.49 | **UPGRADE to Apache httpd 2.4.51+.** Path traversal in mod_cgi allows RCE via ..//cross-site cooking. CVE-2021-41773 bypass. |
| **CVE-2015-3166** | PostgreSQL | 9.8 | 9.2.3 | **MIGRATE to PostgreSQL 15+. EOL version (9.2.x).** Double-free in contrib modules. No backported patch available. |

#### HIGH

| CVE | Product | CVSS | Affects | Recommendation |
|-----|---------|------|---------|----------------|
| **CVE-2021-41773** | httpd | 7.5 | 2.4.49 | UPGRADE to httpd 2.4.51+. Path traversal in mod_cgi on URLs with /cgi-bin/.. sequences. |
| **CVE-2022-23305** | Log4j | 8.1 | 2.14.1 | UPGRADE to log4j 2.17.1+. SQL injection in JDBCAppender. |
| **CVE-2022-23307** | Log4j | 8.1 | 2.14.1 | UPGRADE to log4j 2.17.1+. Deserialization RCE via JMSSink. |
| **CVE-2022-23302** | Log4j | 8.1 | 2.14.1 | UPGRADE to log4j 2.17.1+. Chainsaw viewer XML RCE. |
| **CVE-2015-0244** | PostgreSQL | 7.5 | 9.2.3 | MIGRATE to PG 15+. Memory corruption in pg_atoi; fixed in 9.2.12. |
| **CVE-2018-16850** | PostgreSQL | 8.1 | 9.2.3 | MIGRATE to PG 15+. SQL injection via postgresql_fdw; fixed in 10.5+. |
| **CVE-2024-1597** | PostgreSQL | 8.8 | 9.2.3 | MIGRATE to PG 15+. SQL injection in pg_cancel_backend; no patch for 9.2.x (EOL). |

#### MEDIUM

| CVE | Product | CVSS | Affects | Recommendation |
|-----|---------|------|---------|----------------|
| **CVE-2013-1903** | PostgreSQL | 6.5 | 9.2.3 | MIGRATE to PG 15+. Untrusted search path execution in contrib; fixed in 9.2.4. |
| **CVE-2013-1902** | PostgreSQL | 5.0 | 9.2.3 | MIGRATE to PG 15+. Random() seed exposure in contrib; fixed in 9.2.4. |

### Non-Applicable CVEs (16) — For Reference
The remaining 16 CVEs from the search results are in very old software versions (e.g., OpenSSH 1.x/3.x from 2000–2003) and do not affect the pinned versions. No action required.

---

## Phase 2 — Rule Extraction

Rules were extracted from the following files:
- `roles/bastion/tasks/main.yml` — SSH restriction, bastion sudoers, firewall
- `roles/web/tasks/main.yml` — SSH restriction, HTTP firewall
- `roles/app/tasks/main.yml` — SSH restriction, app-port firewall
- `roles/db/tasks/main.yml` — PostgreSQL superuser, pg_hba, data dir, SSH restriction

### Rule Summary

| ID | Subject | Action | Resource | Effect |
|----|---------|--------|----------|--------|
| rule-001 | sudo\|dba group | ssh:login | bastion01 (mgmt) | permit |
| rule-002 | sudo group | ssh:login | web01 (dmz) | permit |
| rule-003 | sudo\|developers group | ssh:login | app01 (app) | permit |
| rule-004 | sudo\|dba group | ssh:login | db01 (data) | permit |
| rule-005 | sudo+secret clearance | sudoers:execute | bastion01 | permit |
| rule-006 | any | network:connect | bastion01:22/tcp | permit |
| rule-007 | 10.0.0.0/24 | network:connect | web01:80/tcp | permit |
| rule-008 | 10.0.1.0/24 | network:connect | app01:8080/tcp | permit |
| rule-009 | 10.0.2.0/24 | network:connect | db01:5432/tcp | permit |
| rule-010 | dba group | db:login | db01 postgresql SUPERUSER | permit |
| rule-011 | any | filesystem:write | /var/lib/postgresql/data (0700 postgres) | permit |
| rule-999 | all | * | all | **deny** |

---

## Phase 3 — Normalization

- All attribute names referenced in rules exist in the Phase-1 catalog.
- Rule IDs are stable: `rule-001` through `rule-011`, plus `rule-999` for default-deny.
- Only valid ABAC operators used: `equals`, `any_of`, `in`, `applies_to`.
- No forbidden operators (not_equals, MongoDB-style, nested operators).
- All rules include `environment_condition` (compliance_tier=pci).

---

## Phase 4 — Validation

- `attributes` — valid JSON ✓
- `rules` — valid JSON, 12 rules ✓
- `vulnerabilities` — valid JSON, 29 CVEs ✓
- `report` — Markdown string ✓

---

## Ambiguities & Notes

1. **Credentials not in Ansible config**: No passwords, private keys, or secrets are defined in the Ansible configuration. It is assumed credentials are managed via an external secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager). This should be flagged for review — PCI-DSS requirement 7.2 mandates restricting access to credentials.

2. **Log4j installation method**: Log4j is installed via `get_url` downloading directly from Maven Central (`repo1.maven.org`). This is acceptable, but the JAR should be integrity-checked (SHA-256) and pinned in an internal artifact repository for PCI-DSS compliance (requirement 6.4.4).

3. **PostgreSQL EOL**: Version 9.2.x reached end-of-life in November 2017. No security patches are available. Migration to PostgreSQL 15+ is **mandatory** for continued PCI-DSS compliance.

4. **Bastion sudoers `nopassword: false`**: The `community.general.sudoers` module enforces `nopassword: false` (password required) for secret-clearance sudo users on the bastion. This is correctly reflected as an obligation on rule-005. No sudo-without-password rules exist.

5. **SSH AllowGroups vs group_vars**: The `sshd_config` is managed via `lineinfile` (idempotent regexp match). The `allowed_ssh_groups` variable from `group_vars/*.yml` controls which groups can SSH into each host class. This is correctly reflected in rules 001–004.

6. **pg_hba.conf**: PostgreSQL authentication is restricted to the appservers subnet (10.0.2.0/24) via `lineinfile` in `roles/db/tasks/main.yml`. This is enforced by rule-009 (network:connect) and rule-010 (db:login).

7. **Implicit deny**: All network-layer implicit denies (firewall, pg_hba) are handled by the `rule-999` default-deny catch-all, as explicit negation (not_equals) is not a valid ABAC operator. The same applies to non-secret-clearance sudo attempts on bastion.

8. **No session logging rules found**: No `session_recording`, `auditd`, or `profile.d` tasks were found in the role task files. PCI-DSS requirement 10.1 (audit event logging) is not addressed by the current Ansible configuration and should be remediated.

9. **No handlers read**: Handler tasks (e.g., `handlers/main.yml` for service restarts) were skipped per Phase 1.6 classification, as they do not define access rules.

10. **Log4j application JAR**: The `app.jar` deployed to `/opt/app/app.jar` is referenced as a `copy` task source but the actual JAR file is not present in the Ansible repository. The Log4j vulnerability (CVE-2021-44228) affects the running application if `app.jar` bundles or references log4j 2.14.1. This should be confirmed via runtime analysis.
