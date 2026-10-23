# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 00:21:02_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "source": "group_vars/bastion.yml, group_vars/webservers.yml, group_vars/appservers.yml, group_vars/dbservers.yml"
    },
    "source_ip": {
      "source": "inventory.ini"
    },
    "source_zone": {
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    }
  },
  "resources": {
    "hostname": {
      "domain": [
        "bastion01.lab.local",
        "web01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "source": "inventory.ini"
    },
    "role": {
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "domain": [
        "ssh",
        "http",
        "app",
        "postgres"
      ],
      "source": "group_vars/all.yml, group_vars/webservers.yml, group_vars/appservers.yml, group_vars/dbservers.yml"
    },
    "port": {
      "domain": [
        22,
        80,
        8080,
        5432
      ],
      "source": "group_vars/all.yml, group_vars/webservers.yml, group_vars/appservers.yml, group_vars/dbservers.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "group_vars/all.yml"
    },
    "path": {
      "source": "roles/app/tasks/main.yml, roles/db/tasks/main.yml, roles/bastion/tasks/main.yml, roles/web/tasks/main.yml"
    },
    "owner": {
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "privilege_level": {
      "domain": [
        "SUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "chaincorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "domain": [
        "pci"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": "23-30"
    }
  },
  {
    "id": "rule-002",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "31-35"
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
      "host_group": {
        "equals": "bastion"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "8-13"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": "14-21"
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
      "host_group": {
        "equals": "bastion"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "nopassword": false
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "22-29"
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
      "host_group": {
        "equals": "dbservers"
      },
      "privilege_level": {
        "equals": "SUPERUSER"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
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
      "host_group": {
        "equals": "dbservers"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "23-28"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "29-33"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "13-20"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "21-25"
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "default",
      "task": "default-deny",
      "lines": "0"
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
        "equals": "appservers"
      },
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
      "host_group": {
        "equals": "bastion"
      },
      "port": {
        "equals": 22
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
      "host_group": {
        "equals": "dbservers"
      },
      "port": {
        "equals": 5432
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
      "host_group": {
        "equals": "webservers"
      },
      "port": {
        "equals": 80
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
    "recommendation": "Upgrade to Log4j 2.17.1 or later (remove JNDI lookup class)"
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to Log4j 2.17.1 or later; 2.15.0/2.16.0 are insufficient"
  },
  {
    "cve_id": "CVE-2021-41773",
    "product": "httpd",
    "pinned_version": "2.4.49",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to Apache HTTP Server 2.4.51 or later"
  },
  {
    "cve_id": "CVE-2021-42013",
    "product": "httpd",
    "pinned_version": "2.4.49",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to Apache HTTP Server 2.4.51 or later"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to PostgreSQL 9.2.4 or later"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to PostgreSQL 9.2.4 or later"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affects_pinned_version": true,
    "recommendation": "Revoke PUBLIC privileges and restrict plpgsql language usage"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3",
    "affects_pinned_version": false,
    "recommendation": "Affects pgjdbc JDBC driver, not the server package; verify driver version separately"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to OpenSSH 9.8p1 or later (regreSSHion)"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to OpenSSH 9.4p1 or later"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "recommendation": "Version 9.9p1 is not affected by regreSSHion"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "recommendation": "Version 9.9p1 is not affected"
  }
]
```

## Report

# ABAC Policy Mining Report — ChainCorp Ansible

## Summary
Mined an ABAC policy from the ChainCorp Ansible configuration (4 hosts, 4 roles, 5 group_vars files). The configuration models a production PCI environment with deliberately vulnerable pinned software packages.

## Attribute Catalog
- **Subjects**: 3 named users (admin, developer, dba), groups (sudo, developers, dba), clearance levels (secret, confidential), departments (operations, engineering, data), plus source-network and source-zone attributes for network-layer rules.
- **Resources**: 4 hosts (bastion, web, app, db), services (SSH, HTTP, App, PostgreSQL), networks (CIDR ranges), and paths.
- **Environment**: org=chaincorp, environment=production, compliance_tier=pci.

## Extracted Rules
11 ABAC rules were extracted (10 permit + 1 default-deny):
- **SSH access** scoped by host group and approved groups (`AllowGroups` in `sshd_config`).
- **Firewall rules** (`firewalld`) scoped by source subnet and destination port.
- **PostgreSQL superuser access** for DBAs (`LOGIN,SUPERUSER`).
- **Sudo access** restricted to secret-clearance users on the bastion (`nopassword: false`).

## Vulnerabilities
Multiple CVEs affect the pinned versions:
- **Log4j 2.14.1**: CVE-2021-44228 (Log4Shell), CVE-2021-45046 — critical, remote code execution.
- **Apache HTTP Server 2.4.49**: CVE-2021-41773, CVE-2021-42013 — path traversal.
- **PostgreSQL 9.2.3**: CVE-2013-1902, CVE-2013-1903, CVE-2007-3279 — insecure temp files / privilege escalation.
- **OpenSSH 9.1p1 (bastion)**: CVE-2024-6387 (regreSSHion), CVE-2023-38408 — remote code execution.
- **OpenSSH 9.9p1 (other hosts)**: Not affected by the above CVEs.
- **CVE-2024-1597** (pgjdbc) does not affect the server package.

## Ambiguities
- No explicit playbook (`site.yml`) was present; role-to-host-group mapping was inferred from file paths and `group_vars` scoping.
- Filesystem tasks (e.g., `file` module for `/var/lib/postgresql/data`) set `owner`/`group`/`mode` but do not explicitly grant access to any subject group; no filesystem ACL access rules were extracted.
- No credential management tasks (e.g., `ansible-vault`, `copy` of secrets) were found.
- No session logging, audit scripts, SELinux booleans, load-balancer backend definitions, or explicit `DENY` lines in `pg_hba.conf` / `sshd_config` were present; the policy relies on implicit default-deny behavior.

## Recommendations
- Upgrade Log4j to 2.17.1+ immediately.
- Upgrade Apache HTTP Server to 2.4.51+.
- Upgrade PostgreSQL to 9.2.4+ (or a modern supported release).
- Upgrade bastion OpenSSH to 9.8p1+.
- Add explicit `REJECT`/`DROP` firewall rules and `pg_hba.conf` deny lines to reduce reliance on implicit default-deny.
- Consider adding filesystem ACL tasks or the `acl` module to enforce explicit path access.
- Rotate any credentials that may have been exposed by the vulnerable packages.
