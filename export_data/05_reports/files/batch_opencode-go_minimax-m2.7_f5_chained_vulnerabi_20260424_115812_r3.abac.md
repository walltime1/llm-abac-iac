# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 12:12:45_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 12 | Rules: 20_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "domain": null,
      "type": "string",
      "description": "Username of the subject",
      "source": "group_vars/all.yml"
    },
    "uid": {
      "domain": null,
      "type": "integer",
      "description": "Unix user ID",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "type": "set",
      "description": "Unix groups the user belongs to",
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "domain": [
        "confidential",
        "secret"
      ],
      "type": "string",
      "description": "Security clearance level",
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "type": "string",
      "description": "User's department",
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hostname": {
      "domain": null,
      "type": "string",
      "description": "FQDN of the target host",
      "source": "inventory.ini"
    },
    "ip": {
      "domain": null,
      "type": "string",
      "description": "IP address of the host",
      "source": "inventory.ini"
    },
    "role": {
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "type": "string",
      "description": "Functional role of the host",
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "type": "string",
      "description": "Network zone of the host",
      "source": "inventory.ini"
    },
    "inventory_group": {
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers",
        "prod"
      ],
      "type": "string",
      "description": "Ansible inventory group membership",
      "source": "inventory.ini"
    },
    "service": {
      "domain": [
        "ssh",
        "postgresql",
        "httpd",
        "app"
      ],
      "type": "string",
      "description": "Network service name",
      "source": "group_vars/dbservers.yml,group_vars/webservers.yml,group_vars/appservers.yml"
    },
    "port": {
      "domain": null,
      "type": "integer",
      "description": "TCP/UDP port number",
      "source": "group_vars/dbservers.yml,group_vars/webservers.yml,group_vars/appservers.yml"
    },
    "protocol": {
      "domain": [
        "tcp",
        "udp"
      ],
      "type": "string",
      "description": "Network protocol",
      "source": "group_vars/*"
    },
    "host_group": {
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers",
        "all"
      ],
      "type": "string",
      "description": "Host group for service binding",
      "source": "group_vars/*"
    },
    "path": {
      "domain": null,
      "type": "string",
      "description": "Filesystem path",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "domain": null,
      "type": "string",
      "description": "Unix owner of the path",
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "domain": null,
      "type": "string",
      "description": "Unix group of the path",
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "domain": null,
      "type": "string",
      "description": "Unix permission mode (octal)",
      "source": "roles/db/tasks/main.yml"
    },
    "source_ip": {
      "domain": null,
      "type": "string",
      "description": "Source IP address or CIDR for network-layer rules",
      "source": "group_vars/bastion.yml"
    },
    "source_network": {
      "domain": null,
      "type": "string",
      "description": "Source network CIDR for firewall rules",
      "source": "group_vars/dbservers.yml,group_vars/webservers.yml,group_vars/appservers.yml"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "chaincorp"
      ],
      "type": "string",
      "description": "Organization name",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "type": "string",
      "description": "Deployment environment",
      "source": "inventory.ini [prod:vars]"
    },
    "compliance_tier": {
      "domain": [
        "pci"
      ],
      "type": "string",
      "description": "Compliance tier (PCI-DSS)",
      "source": "inventory.ini [prod:vars]"
    },
    "default_log_retention_days": {
      "domain": null,
      "type": "integer",
      "description": "Log retention period in days",
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
    "description": "Sudo group members may SSH into bastion host",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
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
    "description": "DBA group members may SSH into bastion host",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "group_vars/bastion.yml",
      "task": "allowed_ssh_groups",
      "lines": [
        1,
        2
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Sudo group members may SSH into web servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        15,
        17
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Sudo and developers group members may SSH into app servers",
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
      },
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "group_vars/appservers.yml",
      "task": "allowed_ssh_groups",
      "lines": [
        2,
        3
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Sudo and DBA group members may SSH into database server",
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
      },
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        19,
        21
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Any source (0.0.0.0/0) may reach bastion SSH — internet-facing entry point",
    "subject_condition": {
      "source_ip": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "group_vars/bastion.yml",
      "task": "firewall_allow_from",
      "lines": [
        1,
        2
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Bastion subnet (10.0.0.0/24) may reach web server HTTP (port 80)",
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
        "equals": "httpd"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Web subnet (10.0.1.0/24) may reach app server port 8080",
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
        "equals": "app"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        15,
        19
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "App subnet (10.0.2.0/24) may connect to PostgreSQL on db servers (port 5432)",
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
      }
    },
    "environment_condition": {
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
        15,
        18
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "DBA group members get PostgreSQL SUPERUSER on dbservers — PCI-DSS logging required",
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
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "All SUPERUSER sessions must be logged per PCI-DSS requirement 10.2; logs retained 365 days",
        "source": {
          "file": "group_vars/all.yml",
          "task": "default_log_retention_days",
          "lines": [
            3,
            4
          ]
        }
      }
    ],
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
    "description": "Sudo group members with secret clearance may sudo with password on bastion",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "sudoers:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "password_required",
        "description": "Password is required for sudo (nopassword=false); PCI-DSS 8.3",
        "source": {
          "file": "roles/bastion/tasks/main.yml",
          "task": "Only secret-clearance may sudo",
          "lines": [
            11,
            19
          ]
        }
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        11,
        19
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "description": "PostgreSQL data directory (/var/lib/postgresql/data) is readable only by postgres user",
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
        "equals": "pci"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        4,
        9
      ]
    }
  },
  {
    "rule_id": "rule-013",
    "description": "PostgreSQL data directory is writable only by postgres user",
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
        "equals": "pci"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        4,
        9
      ]
    }
  },
  {
    "rule_id": "rule-014",
    "description": "Default deny — all access not explicitly permitted above is prohibited",
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
      "task": "implicit deny",
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
    "id": "rule-003",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
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
      "service": {
        "equals": "httpd"
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
    "id": "rule-005",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "app"
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
    "id": "rule-006",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
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
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "cvss_score": 10.0,
    "severity": "critical",
    "is_known_exploited": true,
    "description": "Apache Log4j2 <=2.14.1 allows remote code execution via unprotected JNDI lookup features (Log4Shell)",
    "remediation": "Upgrade to Log4j 2.17.0+ or configure -Dlog4j2.formatMsgNoLookups=true; also set JndiLookupClassPath=disabled",
    "source": "group_vars/all.yml (log4j_version: 2.14.1)"
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "cvss_score": 9.0,
    "severity": "critical",
    "is_known_exploited": false,
    "description": "Log4j 2.x allows RCE via thread context lookup pattern (Log4Shell DoS variant)",
    "remediation": "Upgrade to Log4j 2.17.0+",
    "source": "group_vars/all.yml (log4j_version: 2.14.1)"
  },
  {
    "cve_id": "CVE-2021-41773",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": true,
    "cvss_score": 9.8,
    "severity": "critical",
    "is_known_exploited": false,
    "description": "Apache httpd 2.4.49 allows path traversal and RCE via mod_proxy cgi-bin path",
    "remediation": "Upgrade to Apache 2.4.51+; disable mod_proxy cgi-bin if not needed",
    "source": "group_vars/all.yml (httpd_version: 2.4.49-1)"
  },
  {
    "cve_id": "CVE-2021-42013",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": true,
    "cvss_score": 9.8,
    "severity": "critical",
    "is_known_exploited": false,
    "description": "Apache httpd 2.4.50 path traversal via double-encoded slash sequences in mod_proxy",
    "remediation": "Upgrade to Apache 2.4.51+",
    "source": "group_vars/all.yml (httpd_version: 2.4.49-1)"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1 (bastion), 1:9.9p1-3ubuntu1 (non-bastion)",
    "affects_pinned_version": true,
    "cvss_score": 8.1,
    "severity": "high",
    "is_known_exploited": false,
    "description": "OpenSSH sshd contains a race condition in signal handler allowing unauthenticated RCE (regreSSHion)",
    "remediation": "Upgrade to OpenSSH 9.8p1+; set LoginGraceTime=0 as interim mitigation",
    "source": "group_vars/all.yml (ssh_version_bastion, ssh_version)"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1 (bastion), 1:9.9p1-3ubuntu1 (non-bastion)",
    "affects_pinned_version": true,
    "cvss_score": 9.8,
    "severity": "critical",
    "is_known_exploited": false,
    "description": "OpenSSH ssh-agent allows RCE via untrusted search path in PKCS#11 feature",
    "remediation": "Upgrade to OpenSSH 9.3p2+; avoid using ssh-agent with untrusted remote hosts",
    "source": "group_vars/all.yml (ssh_version_bastion, ssh_version)"
  },
  {
    "cve_id": "CVE-2022-41862",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": true,
    "cvss_score": 3.7,
    "severity": "low",
    "is_known_exploited": false,
    "description": "PostgreSQL unterminated string in Kerberos transport can cause client over-read",
    "remediation": "Upgrade PostgreSQL to 15.x+; version 9.2 is end-of-life and no longer supported",
    "source": "group_vars/all.yml (postgres_version: 9.2.3-1.pgdg20.04+1)"
  }
]
```

## Report

# ABAC Policy Report — ChainCorp Production Environment

**Organization:** chaincorp  
**Environment:** production  
**Compliance Tier:** PCI-DSS  
**Generated:** Automated from Ansible configuration at `RLM_ANSIBLE_DIR`  
**Source Files:** inventory.ini, group_vars/all.yml, group_vars/bastion.yml, group_vars/dbservers.yml, group_vars/appservers.yml, group_vars/webservers.yml, roles/*/tasks/main.yml

---

## Executive Summary

The Ansible configuration governs 4 hosts across bastion, web, app, and database tiers. Three local users are defined (admin, developer, dba) with group-based SSH access, sudo restrictions on bastion, and database SUPERUSER grants for DBAs. Seven confirmed vulnerabilities affect pinned package versions across all tiers.

---

## 1. Attribute Catalog

### 1.1 Subject Attributes

| Attribute | Type | Domain / Values | Source |
|---|---|---|---|
| `user` | string | admin, developer, dba | group_vars/all.yml |
| `uid` | integer | 1001, 1002, 1003 | group_vars/all.yml |
| `groups` | set | sudo, developers, dba | group_vars/all.yml |
| `clearance` | string | confidential, secret | group_vars/all.yml |
| `department` | string | operations, engineering, data | group_vars/all.yml |

**Users defined:**
- `admin` (uid=1001): groups=[sudo], clearance=secret, department=operations
- `developer` (uid=1002): groups=[developers], clearance=confidential, department=engineering
- `dba` (uid=1003): groups=[dba], clearance=secret, department=data

### 1.2 Resource Attributes

| Attribute | Type | Domain / Values | Source |
|---|---|---|---|
| `hostname` | string | bastion01.lab.local, web01.lab.local, app01.lab.local, db01.lab.local | inventory.ini |
| `ip` | string | 10.0.0.5, 10.0.1.10, 10.0.2.10, 10.0.3.10 | inventory.ini |
| `role` | string | bastion, frontend, application, primary | inventory.ini |
| `zone` | string | mgmt, dmz, app, data | inventory.ini |
| `inventory_group` | string | bastion, webservers, appservers, dbservers, prod | inventory.ini |
| `service` | string | ssh, postgresql, httpd, app | group_vars/* |
| `port` | integer | 22, 80, 8080, 5432 | group_vars/* |
| `path` | string | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| `owner` | string | postgres | roles/db/tasks/main.yml |
| `group` | string | postgres | roles/db/tasks/main.yml |
| `mode` | string | 0700 | roles/db/tasks/main.yml |
| `source_ip` | string | 0.0.0.0/0 | group_vars/bastion.yml |
| `source_network` | string | 10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24 | group_vars/* |

### 1.3 Environment Attributes

| Attribute | Type | Domain / Values | Source |
|---|---|---|---|
| `org` | string | chaincorp | group_vars/all.yml |
| `environment` | string | production | inventory.ini [prod:vars] |
| `compliance_tier` | string | pci | inventory.ini [prod:vars] |
| `default_log_retention_days` | integer | 365 | group_vars/all.yml |

---

## 2. Vulnerability Assessment (Phase 1.5)

Pinned package versions from `group_vars/all.yml`:

| Product | Pinned Version | CVEs Found | Max CVSS | KEV? |
|---|---|---|---|---|
| log4j | 2.14.1 | CVE-2021-44228, CVE-2021-45046 | 10.0 | **Yes** (CVE-2021-44228) |
| apache (httpd) | 2.4.49-1 | CVE-2021-41773, CVE-2021-42013 | 9.8 | No |
| openssh (bastion) | 1:9.1p1-1ubuntu1 | CVE-2024-6387, CVE-2023-38408 | 9.8 | No |
| openssh (non-bastion) | 1:9.9p1-3ubuntu1 | CVE-2024-6387, CVE-2023-38408 | 9.8 | No |
| postgresql | 9.2.3-1.pgdg20.04+1 | CVE-2022-41862 | 3.7 | No |

### Key Findings
- **Log4Shell (CVE-2021-44228, CVSS 10.0, KEV):** Affects app01.lab.local. Remote code execution via JNDI lookup in Log4j 2.14.1 — actively exploited in the wild. Critical priority.
- **Apache Path Traversal (CVE-2021-41773/42013, CVSS 9.8):** Affects web01.lab.local. mod_proxy cgi-bin path traversal allows RCE. Critical priority.
- **OpenSSH regreSSHion (CVE-2024-6387, CVSS 8.1):** Affects bastion01.lab.local AND all non-bastion hosts. Unauthenticated RCE via signal handler race condition. High priority.
- **OpenSSH Agent RCE (CVE-2023-38408, CVSS 9.8):** Affects all hosts with openssh installed. RCE via untrusted PKCS#11 search path. Critical priority.
- **PostgreSQL EOL (CVE-2022-41862, CVSS 3.7):** Affects db01.lab.local. Version 9.2 is end-of-life, no security support. Low priority but concerning.

---

## 3. ABAC Access Rules (14 rules)

### 3.1 SSH Access Rules (5 rules)

| Rule ID | Subjects | Resource | Action | Effect |
|---|---|---|---|---|
| rule-001 | groups:sudo | bastion01.lab.local (ssh) | ssh:login | permit |
| rule-002 | groups:dba | bastion01.lab.local (ssh) | ssh:login | permit |
| rule-003 | groups:sudo | webservers (ssh) | ssh:login | permit |
| rule-004 | groups:sudo,developers | appservers (ssh) | ssh:login | permit |
| rule-005 | groups:sudo,dba | dbservers (ssh) | ssh:login | permit |

### 3.2 Firewall / Network Rules (4 rules)

| Rule ID | Source | Destination | Action | Effect |
|---|---|---|---|---|
| rule-006 | 0.0.0.0/0 (any) | bastion01.lab.local:22 | network:connect | permit |
| rule-007 | 10.0.0.0/24 (bastion subnet) | webservers:httpd (80) | network:connect | permit |
| rule-008 | 10.0.1.0/24 (web subnet) | appservers:app (8080) | network:connect | permit |
| rule-009 | 10.0.2.0/24 (app subnet) | dbservers:postgresql (5432) | network:connect | permit |

### 3.3 Database Authorization Rules (1 rule)

| Rule ID | Subjects | Resource | Action | Effect |
|---|---|---|---|---|
| rule-010 | groups:dba | dbservers (postgresql) | db:login | permit |

**Obligation:** All SUPERUSER sessions must be logged per PCI-DSS requirement 10.2; logs retained 365 days.

### 3.4 Sudoers Rules (1 rule)

| Rule ID | Subjects | Resource | Action | Effect |
|---|---|---|---|---|
| rule-011 | groups:sudo + clearance:secret | bastion01.lab.local | sudoers:execute | permit |

**Obligation:** Password required for sudo (nopassword=false); PCI-DSS 8.3 compliance.

### 3.5 Filesystem ACL Rules (2 rules)

| Rule ID | Subject | Path | Mode | Action | Effect |
|---|---|---|---|---|---|
| rule-012 | user=postgres | /var/lib/postgresql/data | 0700 | filesystem:read | permit |
| rule-013 | user=postgres | /var/lib/postgresql/data | 0700 | filesystem:write | permit |

### 3.6 Default Deny (1 rule)

| Rule ID | Subject | Resource | Action | Effect |
|---|---|---|---|---|
| rule-014 | applies_to=all | applies_to=all | * | deny |

---

## 4. Security Observations

### 4.1 Access Control Gaps
- **Bastion is internet-reachable:** rule-006 permits `0.0.0.0/0` to SSH on bastion01.lab.local. While this is by design for bastion architecture, combined with CVE-2024-6387 (regreSSHion — unauthenticated RCE on OpenSSH), the bastion is critically exposed.
- **App server accessible from web subnet only:** rule-008 permits 10.0.1.0/24 → app01:8080. App01 has Log4j 2.14.1 installed — Log4Shell is exploitable from any host that can reach port 8080.
- **PostgreSQL accessible from app subnet:** rule-009 permits 10.0.2.0/24 → db01:5432. Combined with CVE-2022-41862 on EOL PostgreSQL 9.2.

### 4.2 Privilege Escalation Vectors
- `admin` (sudo + secret clearance) has full sudo on bastion via rule-011.
- `dba` (dba + secret clearance) has PostgreSQL SUPERUSER via rule-010 — this is the highest database privilege.
- `developer` has no privileged access beyond SSH to app servers (no sudo, no db access).

### 4.3 Compliance Concerns
- **PCI-DSS 3.2.1:** All 7 identified CVEs affect in-scope systems; the chaincorp environment is PCI-DSS tier=pci, requiring timely patching per PCI-DSS requirement 6.3.3.
- **PCI-DSS 10.2:** Logging obligation on rule-010 is explicitly defined, consistent with the 365-day retention in `group_vars/all.yml`.
- **PCI-DSS 8.3:** Password-required sudo on bastion is enforced (rule-011 nopassword=false).

### 4.4 Missing Controls
- No explicit firewall rule for web servers accessing database servers — this traffic is implicitly denied by default-deny.
- `developer` user has no explicit SSH rule for dbservers — caught by default-deny. This is correct behavior.
- No MFA/2FA enforcement in the Ansible config for any user.
- No session timeout or idle timeout configured in SSH.

---

## 5. Ambiguities

- **SSH key management:** No SSH authorized_keys, key-based auth config, or key distribution tasks found in the Ansible files. Only group-based `AllowGroups` is configured. It is ambiguous how users actually authenticate (password vs. key).
- **DB credentials:** No `postgresql_user` password hashing method specified; `pg_hba.conf` entries use `scram-sha-256` but no password management tasks exist.
- **Monitoring access:** No Nagios/Icinga monitoring configurations found; monitoring access rules cannot be extracted.
- **SELinux:** No SELinux seboolean tasks found in any role; no selinux:policy rules generated.
- **Load balancer:** No HAProxy/Nginx role files found; topology/routing rules not extracted.

---

## 6. Conclusion

The Ansible configuration defines a tiered production environment with clear group-based access controls, but all four tiers (bastion, web, app, db) run known-vulnerable software. The most critical risks are:
1. **Log4Shell on app01** — CVSS 10.0, KEV-listed, reachable from web subnet.
2. **Bastion internet exposure** — CVE-2024-6387 allows unauthenticated RCE on the internet-facing bastion.
3. **Apache path traversal on web01** — CVSS 9.8, allows RCE via mod_proxy.

All 14 ABAC rules are grounded in concrete Ansible tasks. The default-deny rule ensures no unlisted access is permitted. PCI-DSS obligations (session logging, password-required sudo) are attached as obligations to the relevant rules.
