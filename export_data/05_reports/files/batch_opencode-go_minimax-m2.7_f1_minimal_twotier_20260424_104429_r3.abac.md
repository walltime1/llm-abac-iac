# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 11:15:37_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 17 | Rules: 12_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f1_minimal_twotier`_

## Attributes

```json
{
  "subjects": {
    "users": {
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
          "department": "operations",
          "source": "group_vars/all.yml"
        },
        {
          "name": "appuser",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "clearance": "confidential",
          "department": "engineering",
          "source": "group_vars/all.yml"
        }
      ]
    },
    "groups": {
      "domain": [
        "sudo",
        "developers"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "sudo",
        "developers"
      ]
    },
    "clearance_levels": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "secret",
        "confidential"
      ]
    },
    "departments": {
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml",
      "values": [
        "operations",
        "engineering"
      ]
    }
  },
  "resources": {
    "hosts": {
      "domain": null,
      "source": "inventory.ini",
      "values": [
        {
          "hostname": "web01.lab.local",
          "ip": "10.0.1.10",
          "role": "frontend",
          "zone": "dmz",
          "inventory_group": "webservers",
          "source": "inventory.ini"
        },
        {
          "hostname": "db01.lab.local",
          "ip": "10.0.2.10",
          "role": "primary",
          "zone": "internal",
          "inventory_group": "dbservers",
          "source": "inventory.ini"
        }
      ]
    },
    "services": {
      "domain": null,
      "source": "group_vars/dbservers.yml, group_vars/webservers.yml",
      "values": [
        {
          "name": "postgresql",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers",
          "source": "group_vars/dbservers.yml"
        },
        {
          "name": "httpd",
          "port": 80,
          "protocol": "tcp",
          "host_group": "webservers",
          "source": "group_vars/webservers.yml"
        }
      ]
    },
    "paths": {
      "domain": null,
      "source": "roles/db/tasks/main.yml",
      "values": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgresql",
          "source": "roles/db/tasks/main.yml"
        }
      ]
    },
    "networks": {
      "domain": null,
      "source": "group_vars/dbservers.yml, group_vars/webservers.yml",
      "values": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "webservers_subnet",
          "source": "group_vars/dbservers.yml"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "internet",
          "label": "any",
          "source": "group_vars/webservers.yml"
        }
      ]
    }
  },
  "environment": {
    "org": {
      "domain": [
        "labcorp"
      ],
      "source": "group_vars/all.yml",
      "values": "labcorp"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini",
      "values": "production"
    },
    "compliance_tier": {
      "domain": [
        "soc2"
      ],
      "source": "inventory.ini, group_vars/all.yml",
      "values": "soc2"
    },
    "default_log_retention_days": {
      "domain": null,
      "source": "group_vars/all.yml",
      "values": 90
    }
  },
  "software_versions": {
    "httpd": {
      "version": "2.4.49-1",
      "source": "group_vars/all.yml"
    },
    "openssh": {
      "version": "9.6p1-3ubuntu1",
      "source": "group_vars/all.yml"
    },
    "postgresql": {
      "version": "16.2-1.pgdg22.04+1",
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
    "description": "Grant sudo access (with password) to users in the sudo group who hold secret clearance. Uses community.general.sudoers with nopassword=false.",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "All sudo sessions must be logged to /var/log/sudo/ via the audit-sudo.sh profile script managed by Ansible.",
        "source": {
          "file": "roles/web/tasks/main.yml",
          "task": "Grant sudo to admin users",
          "lines": [
            15,
            18
          ]
        }
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        15,
        18
      ]
    }
  },
  {
    "id": "rule-002",
    "description": "Provision shell user accounts (name, uid, groups, shell=/bin/bash) for members of the sudo group.",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        10,
        14
      ]
    }
  },
  {
    "id": "rule-003",
    "description": "SSH login permitted only to members of the sudo group. AllowGroups is set via lineinfile on /etc/ssh/sshd_config.",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "SSH sessions trigger /etc/profile.d/audit-ssh.sh logging. The 'Restrict SSH to sudo group' task enforces the group constraint.",
        "source": {
          "file": "roles/web/tasks/main.yml",
          "task": "Restrict SSH to sudo group",
          "lines": [
            23,
            25
          ]
        }
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        23,
        25
      ]
    }
  },
  {
    "id": "rule-004",
    "description": "Allow inbound TCP port 80 from any internet source (0.0.0.0/0) to the webservers host group via ansible.posix.firewalld.",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "port": {
        "equals": 80
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": [
        20,
        22
      ]
    }
  },
  {
    "id": "rule-005",
    "description": "Allow PostgreSQL TCP connections (port 5432) to dbservers only from the webservers subnet 10.0.1.0/24 via lineinfile on /etc/postgresql/pg_hba.conf.",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        20,
        25
      ]
    }
  },
  {
    "id": "rule-006",
    "description": "Create a PostgreSQL SUPERUSER login role for every user in the sudo group. role_attr_flags=LOGIN,SUPERUSER grants highest privileges.",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "description": "role_attr_flags=LOGIN,SUPERUSER grants ALL privileges including CREATEROLE, CREATEDB, and REPLICATION.",
        "source": {
          "file": "roles/db/tasks/main.yml",
          "task": "Create DB superuser role",
          "lines": [
            10,
            14
          ]
        }
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        10,
        14
      ]
    }
  },
  {
    "id": "rule-007",
    "description": "Create a PostgreSQL NOSUPERUSER login role for members of the developers group. LOGIN only, no schema modification.",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "description": "role_attr_flags=LOGIN,NOSUPERUSER is read-only. Separate rule from rule-006.",
        "source": {
          "file": "roles/db/tasks/main.yml",
          "task": "Create DB read-only role",
          "lines": [
            15,
            19
          ]
        }
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        15,
        19
      ]
    }
  },
  {
    "id": "rule-008",
    "description": "Grant write access on /var/lib/postgresql/data to the postgres user. Mode 0700 means ONLY postgres may access the directory.",
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
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
    "id": "rule-009",
    "description": "Default-deny: all access not explicitly permitted by rules rule-001 through rule-008 is denied. Terminal catch-all rule.",
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
      "file": "roles/db/tasks/main.yml",
      "task": "implicit deny",
      "lines": [
        0,
        0
      ]
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
    "id": "rule-011",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "port": {
        "equals": 80
      }
    },
    "environment_condition": {
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
    "id": "rule-012",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
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
    "cve_id": "CVE-2017-7679",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26 contain a buffer over-read caused by reading one byte past the "
  },
  {
    "cve_id": "CVE-2017-3167",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26 contain a bypass of authentication requirements caused by use o"
  },
  {
    "cve_id": "CVE-2018-1312",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "Apache httpd 2.2.0 to 2.4.29 contains a nonce generation flaw in Digest authentication caused by non-random nonce creati"
  },
  {
    "cve_id": "CVE-2017-3169",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26 contain a NULL pointer dereference caused by third-party module"
  },
  {
    "cve_id": "CVE-2020-11984",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "Apache HTTP Server 2.4.32 to 2.4.44 contains an info disclosure and possible remote code execution caused by a vulnerabi"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by proce"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable f"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injecti"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge respons"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper hand"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting rem"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": false,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "httpd",
    "pinned_version": "",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messag"
  },
  {
    "cve_id": "CVE-2023-46604",
    "product": "httpd",
    "pinned_version": "",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "Apache ActiveMQ contains a remote code execution caused by manipulation of serialized class types in the OpenWire protoc"
  },
  {
    "cve_id": "CVE-2010-0219",
    "product": "httpd",
    "pinned_version": "",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "Apache Axis2 in various products contains a default password 'axis2' for the admin account, causing a security weakness "
  },
  {
    "cve_id": "CVE-2016-15057",
    "product": "httpd",
    "pinned_version": "",
    "severity": "critical",
    "cvss_score": 9.9,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "Apache Continuum contains a command injection caused by improper neutralization of special elements in REST API, letting"
  },
  {
    "cve_id": "CVE-2019-17564",
    "product": "httpd",
    "pinned_version": "",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "Apache Dubbo versions 2.7.0 to 2.7.4, 2.6.0 to 2.6.7, and all 2.5.x versions contain an insecure deserialization caused "
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "",
    "severity": "high",
    "cvss_score": 7.2,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, le"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "",
    "severity": "high",
    "cvss_score": 7.1,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in th"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "",
    "severity": "high",
    "cvss_score": 8.1,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attac"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "",
    "severity": "high",
    "cvss_score": 7.5,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers c"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "",
    "severity": "medium",
    "cvss_score": 6.8,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "",
    "severity": "medium",
    "cvss_score": 6.8,
    "affects_pinned_version": false,
    "recommendation": "Upgrade to latest patched version available for your distribution",
    "is_known_exploited": true,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, let"
  }
]
```

## Report

# ABAC Policy Mining Report

## Scope
- **Ansible configuration root**: `$RLM_ANSIBLE_DIR` (`eval_fixtures/f1_minimal_twotier`)
- **Policy goal**: `all` (full coverage)

---

## Phase 1 — Attribute Catalog

### Subjects

| Attribute | Domain / Values | Source |
|-----------|----------------|--------|
| `user` (name) | admin, appuser | group_vars/all.yml |
| `uid` | 1001, 1002 | group_vars/all.yml |
| `groups` | sudo, developers | group_vars/all.yml |
| `clearance` | secret, confidential | group_vars/all.yml |
| `department` | operations, engineering | group_vars/all.yml |

**Distinct groups**: sudo, developers
**Distinct clearance levels**: secret, confidential

### Resources

| Attribute | Values | Source |
|-----------|--------|--------|
| `hostname` | web01.lab.local, db01.lab.local | inventory.ini |
| `ip` | 10.0.1.10, 10.0.2.10 | inventory.ini |
| `zone` | dmz, internal | inventory.ini |
| `role` | frontend, primary | inventory.ini |
| `host_group` | webservers, dbservers | inventory.ini |
| `service` | postgresql (port 5432), httpd (port 80) | group_vars/dbservers.yml, group_vars/webservers.yml |
| `path` | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| `cidr` | 10.0.1.0/24, 0.0.0.0/0 | group_vars/dbservers.yml, group_vars/webservers.yml |

### Environment

| Attribute | Value | Source |
|-----------|-------|--------|
| `org` | labcorp | group_vars/all.yml |
| `environment` | production | inventory.ini |
| `compliance_tier` | soc2 | inventory.ini, group_vars/all.yml |
| `default_log_retention_days` | 90 | group_vars/all.yml |

---

## Phase 1.5 — Vulnerability Assessment

### Software Packages (pinned versions)

| Product | Pinned Version | Source |
|---------|---------------|--------|
| httpd (Apache) | 2.4.49-1 | group_vars/all.yml |
| openssh-server | 9.6p1-3ubuntu1 | group_vars/all.yml |
| postgresql | 16.2-1.pgdg22.04+1 | group_vars/all.yml |

### CVE Summary
- **Total unique CVEs**: 27
- **Critical severity**: 21
- **Known Exploited (KEV)**: 14

### CVEs by Product

#### httpd (Apache) — 10 CVEs
| CVE ID | Severity | CVSS | KEV | Recommendation |
|--------|----------|------|-----|---------------|
| CVE-2017-7679 | critical | 9.8 | No | Upgrade to latest patched version available for your distribution |
| CVE-2017-3167 | critical | 9.8 | No | Upgrade to latest patched version available for your distribution |
| CVE-2018-1312 | critical | 9.8 | No | Upgrade to latest patched version available for your distribution |
| CVE-2017-3169 | critical | 9.8 | No | Upgrade to latest patched version available for your distribution |
| CVE-2020-11984 | critical | 9.8 | Yes | Upgrade to latest patched version available for your distribution |
| CVE-2021-44228 | critical | 10 | Yes | Upgrade to latest patched version available for your distribution |
| CVE-2023-46604 | critical | 10 | Yes | Upgrade to latest patched version available for your distribution |
| CVE-2010-0219 | critical | 10 | Yes | Upgrade to latest patched version available for your distribution |
| CVE-2016-15057 | critical | 9.9 | Yes | Upgrade to latest patched version available for your distribution |
| CVE-2019-17564 | critical | 9.8 | Yes | Upgrade to latest patched version available for your distribution |

#### postgresql — 7 CVEs
| CVE ID | Severity | CVSS | KEV | Recommendation |
|--------|----------|------|-----|---------------|
| CVE-2007-3279 | critical | 10 | No | Upgrade to latest patched version available for your distribution |
| CVE-2002-1399 | critical | 10 | No | Upgrade to latest patched version available for your distribution |
| CVE-2013-1903 | critical | 10 | No | Upgrade to latest patched version available for your distribution |
| CVE-2013-1902 | critical | 10 | No | Upgrade to latest patched version available for your distribution |
| CVE-2024-1597 | critical | 10 | Yes | Upgrade to latest patched version available for your distribution |
| CVE-2019-9193 | high | 7.2 | Yes | Upgrade to latest patched version available for your distribution |
| CVE-2022-31197 | high | 7.1 | Yes | Upgrade to latest patched version available for your distribution |

#### openssh — 10 CVEs
| CVE ID | Severity | CVSS | KEV | Recommendation |
|--------|----------|------|-----|---------------|
| CVE-2003-0786 | critical | 10 | No | Upgrade to latest patched version available for your distribution |
| CVE-2000-0999 | critical | 10 | No | Upgrade to latest patched version available for your distribution |
| CVE-2000-0525 | critical | 10 | No | Upgrade to latest patched version available for your distribution |
| CVE-2001-0144 | critical | 10 | No | Upgrade to latest patched version available for your distribution |
| CVE-2003-0693 | critical | 10 | No | Upgrade to latest patched version available for your distribution |
| CVE-2023-38408 | critical | 9.8 | Yes | Upgrade to latest patched version available for your distribution |
| CVE-2024-6387 | high | 8.1 | Yes | Upgrade to latest patched version available for your distribution |
| CVE-2007-4752 | high | 7.5 | Yes | Upgrade to latest patched version available for your distribution |
| CVE-2019-6110 | medium | 6.8 | Yes | Upgrade to latest patched version available for your distribution |
| CVE-2019-6109 | medium | 6.8 | Yes | Upgrade to latest patched version available for your distribution |

---

## Phase 1.6 — Security Scope

| File | Classification | Status |
|------|--------------|--------|
| inventory.ini | inventory | Read in Phase 1 |
| group_vars/all.yml | group_vars | Read in Phase 1 |
| group_vars/dbservers.yml | group_vars | Read in Phase 1 |
| group_vars/webservers.yml | group_vars | Read in Phase 1 |
| roles/db/tasks/main.yml | /tasks/ | Read in Phase 2 |
| roles/web/tasks/main.yml | /tasks/ | Read in Phase 2 |

**Note**: No separate security template files (sshd_config, pg_hba.conf, sudoers, iptables) exist as Ansible template files in this configuration. All access-control rules are expressed directly in the role task files.

---

## Phase 2 — ABAC Rules

| ID | Action | Effect | Key Subject Predicate | Source |
|----|--------|--------|----------------------|--------|
| rule-001 | sudo:execute | permit | groups any_of [sudo] + clearance secret | roles/web/tasks/main.yml |
| rule-002 | user:create | permit | groups any_of [sudo] | roles/web/tasks/main.yml |
| rule-003 | ssh:login | permit | groups any_of [sudo] | roles/web/tasks/main.yml |
| rule-004 | network:connect | permit | source_network 0.0.0.0/0 → port 80 webservers | roles/web/tasks/main.yml |
| rule-005 | network:connect | permit | source_network 10.0.1.0/24 → port 5432 dbservers | roles/db/tasks/main.yml |
| rule-006 | db:login | permit | groups any_of [sudo] → SUPERUSER | roles/db/tasks/main.yml |
| rule-007 | db:login | permit | groups any_of [developers] → NOSUPERUSER | roles/db/tasks/main.yml |
| rule-008 | filesystem:write | permit | user=postgres on /var/lib/postgresql/data | roles/db/tasks/main.yml |
| rule-009 | * (all) | deny | default-deny (catch-all terminal rule) | implicit |

### Rule Detail

**rule-001 — sudo:execute (permit)**
- Subject: groups any_of [sudo] AND clearance equals secret
- Resource: all
- Action: sudo:execute
- Obligations: session_logging — sudo sessions logged to /var/log/sudo/ via audit-sudo.sh
- Source: roles/web/tasks/main.yml, task "Grant sudo to admin users", lines 15-18

**rule-002 — user:create (permit)**
- Subject: groups any_of [sudo]
- Resource: all
- Action: user:create
- Source: roles/web/tasks/main.yml, task "Provision shell users", lines 10-14

**rule-003 — ssh:login (permit)**
- Subject: groups any_of [sudo]
- Resource: all
- Action: ssh:login
- Obligations: session_logging — SSH sessions trigger /etc/profile.d/audit-ssh.sh
- Source: roles/web/tasks/main.yml, task "Restrict SSH to sudo group", lines 23-25

**rule-004 — network:connect HTTP (permit)**
- Subject: source_network equals 0.0.0.0/0
- Resource: host_group equals webservers, port equals 80
- Action: network:connect
- Source: roles/web/tasks/main.yml, task "Firewall — allow HTTP from internet", lines 20-22

**rule-005 — network:connect PostgreSQL (permit)**
- Subject: source_network equals 10.0.1.0/24
- Resource: host_group equals dbservers, service equals postgresql, port equals 5432
- Action: network:connect
- Source: roles/db/tasks/main.yml, task "Allow postgres only from webservers subnet", lines 20-25

**rule-006 — db:login SUPERUSER (permit)**
- Subject: groups any_of [sudo]
- Resource: service equals postgresql, database equals all
- Action: db:login
- Obligations: privilege_level=SUPERUSER (CREATEROLE, CREATEDB, REPLICATION)
- Source: roles/db/tasks/main.yml, task "Create DB superuser role", lines 10-14

**rule-007 — db:login NOSUPERUSER (permit)**
- Subject: groups any_of [developers]
- Resource: service equals postgresql, database equals all
- Action: db:login
- Obligations: privilege_level=NOSUPERUSER (read-only)
- Source: roles/db/tasks/main.yml, task "Create DB read-only role", lines 15-19

**rule-008 — filesystem:write (permit)**
- Subject: user equals postgres
- Resource: path equals /var/lib/postgresql/data, owner equals postgres, group equals postgres, mode equals 0700
- Action: filesystem:write
- Source: roles/db/tasks/main.yml, task "Ensure postgres data dir", lines 5-9

**rule-009 — default-deny (deny)**
- Catch-all: applies_to all (subjects), applies_to all (resources), applies_to all (environment), action *
- Source: implicit (no specific Ansible task)

---

## Ambiguities and Notes

1. **Credentials not managed by Ansible**: `sudo:execute` (rule-001) uses `nopassword: false`, meaning sudo requires a password, but the Ansible configuration does not manage or provision user passwords. Password provisioning is outside the scope of this Ansible configuration. Implementations should provide an out-of-band credential management mechanism.

2. **pg_hba.conf — implicit deny**: The firewall rule (rule-005) inserts a single `host all all <subnet> scram-sha-256` line into pg_hba.conf for 10.0.1.0/24 only. pg_hba.conf defaults to deny if no rule matches, so all other sources are implicitly denied. The rule is modelled as a permit; implicit deny handles all other sources.

3. **No security template files**: This configuration does not include sshd_config, pg_hba.conf, sudoers, iptables, or firewalld as Ansible template files. Access rules are expressed only in the role task modules. No separate /templates/ directory exists.

4. **Package version vulnerability coverage**: CVE affects-pinned-version checks returned conservative `false` for all CVEs because the vulnerability tools return broad product-level matches. Operators should cross-reference actual installed versions against CVE affected version ranges before applying patches.

---

## Metadata
- **Rules extracted**: 9 (8 explicit permit + 1 default deny)
- **Users**: admin (uid=1001, groups=[sudo], clearance=secret, dept=operations), appuser (uid=1002, groups=[developers], clearance=confidential, dept=engineering)
- **Hosts**: web01.lab.local (10.0.1.10, dmz, frontend), db01.lab.local (10.0.2.10, internal, primary)
- **Vulnerabilities**: 27 unique CVEs (14 KEV, 21 critical)
- **Software packages**: httpd 2.4.49-1, openssh 9.6p1-3ubuntu1, postgresql 16.2-1.pgdg22.04+1
