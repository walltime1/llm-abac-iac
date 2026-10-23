# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 21:01:03_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 19 | Rules: 24_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

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
      },
      {
        "name": "postgres",
        "uid": 999,
        "groups": [
          "postgres"
        ],
        "department": "data",
        "clearance": "secret",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": {
      "name": "groups",
      "values": [
        "sudo",
        "developers",
        "dba",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "name": "clearance",
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "name": "department",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "name": "source_network",
      "domain": [
        "0.0.0.0/0",
        "10.0.0.0/24",
        "10.0.1.0/24",
        "10.0.2.0/24"
      ],
      "source": "group_vars/bastion.yml,group_vars/webservers.yml,group_vars/appservers.yml,group_vars/dbservers.yml"
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "bastion01.lab.local",
        "ip": "10.0.0.5",
        "role": "bastion",
        "zone": "mgmt",
        "inventory_group": "bastion",
        "source": "inventory.ini"
      },
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers",
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
        "host_group": "bastion",
        "source": "roles/bastion/tasks/main.yml"
      },
      {
        "name": "httpd",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "group_vars/webservers.yml"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "roles/app/tasks/main.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "roles/db/tasks/main.yml"
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
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet",
        "source": "group_vars/bastion.yml"
      },
      {
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "mgmt_subnet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web_subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet",
        "source": "group_vars/dbservers.yml"
      }
    ],
    "privilege": {
      "name": "privilege",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER",
        "LOGIN",
        "ALL",
        "SELECT"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "name": "org",
      "value": "chaincorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "name": "environment",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "name": "compliance_tier",
      "domain": [
        "pci"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "name": "default_log_retention_days",
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
    "rule_id": "rule-001",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "9-12"
    }
  },
  {
    "rule_id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "9-12"
    }
  },
  {
    "rule_id": "rule-003",
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
      "lines": "14-18"
    }
  },
  {
    "rule_id": "rule-004",
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
        "type": "require_password",
        "value": true
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "20-26"
    }
  },
  {
    "rule_id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "ssh"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "22-25"
    }
  },
  {
    "rule_id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "ssh"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "22-25"
    }
  },
  {
    "rule_id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      },
      "privilege": {
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
      "lines": "12-15"
    }
  },
  {
    "rule_id": "rule-008",
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
      "service": {
        "equals": "postgresql"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "17-19"
    }
  },
  {
    "rule_id": "rule-009",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
    }
  },
  {
    "rule_id": "rule-010",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
    }
  },
  {
    "rule_id": "rule-011",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "7-12"
    }
  },
  {
    "rule_id": "rule-012",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "ssh"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "15-18"
    }
  },
  {
    "rule_id": "rule-013",
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
      "service": {
        "equals": "httpd"
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
      "lines": "11-14"
    }
  },
  {
    "rule_id": "rule-014",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "ssh"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "21-24"
    }
  },
  {
    "rule_id": "rule-015",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "ssh"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "21-24"
    }
  },
  {
    "rule_id": "rule-016",
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
      "service": {
        "equals": "app"
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
      "lines": "16-19"
    }
  },
  {
    "rule_id": "rule-017",
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
      "lines": "N/A"
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
      "applies_to": {
        "equals": "all"
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
      "applies_to": {
        "equals": "all"
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
      "applies_to": {
        "equals": "all"
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
    "id": "rule-004",
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
    "id": "rule-005",
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
      "service": {
        "equals": "postgresql"
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
    "id": "rule-006",
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
      },
      "service": {
        "equals": "httpd"
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
    "id": "rule-007",
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
        "equals": "app"
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
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to e",
    "recommendation": "Affects Log4j 2.14.1 (pinned). Upgrade to Log4j 2.17.1 or later immediately. This is a critical RCE actively exploited in the wild (Log4Shell)."
  },
  {
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "recommendation": "Affects PostgreSQL 9.2.x before 9.2.4 (pinned 9.2.3). Upgrade PostgreSQL to 9.2.4 or later."
  },
  {
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "recommendation": "Affects PostgreSQL before 9.2.4 (pinned 9.2.3). Upgrade PostgreSQL to 9.2.4 or later."
  },
  {
    "cve_id": "CVE-2021-41773",
    "severity": "high",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "description": "Apache HTTP Server 2.4.49 contains a path traversal caused by flawed path normalization, letting attackers map URLs outside the document root and potentially access sensitive files or leak source code",
    "recommendation": "Affects Apache httpd 2.4.49 (pinned). Upgrade to Apache httpd 2.4.51 or later. Path traversal vulnerability actively exploited."
  },
  {
    "cve_id": "CVE-2021-42013",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "description": "Apache HTTP Server 2.4.49 and 2.4.50 contain a path traversal caused by flawed path normalization, letting attackers access files outside the document root and potentially execute remote code if mod_c",
    "recommendation": "Affects Apache httpd 2.4.49/2.4.50 (pinned 2.4.49). Upgrade to Apache httpd 2.4.51 or later. Bypass of CVE-2021-41773 fix."
  }
]
```

## Report

# ABAC Policy Mining Report — Chaincorp Ansible Configuration

## Executive Summary

This report presents an Attribute-Based Access Control (ABAC) policy mined from the Chaincorp Ansible configuration. The policy covers 4 hosts across 4 network zones, 3 defined users plus the `postgres` system account, and 17 access control rules spanning SSH login, sudo execution, database access, network connectivity, and filesystem permissions.

## Attribute Catalog

### Subjects

| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |
| postgres | 999 | postgres | data | secret |

**Groups:** sudo, developers, dba, postgres  
**Clearance Levels:** confidential, secret  
**Departments:** operations, engineering, data

### Resources

**Hosts:**

| Hostname | IP | Role | Zone | Inventory Group |
|----------|-----|------|------|----------------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt | bastion |
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

**Services:** SSH (port 22), HTTPD (port 80), App (port 8080), PostgreSQL (port 5432)

**Paths:** `/var/lib/postgresql/data` (owner=postgres, group=postgres, mode=0700)

**Networks:**

| CIDR | Zone | Label |
|------|------|-------|
| 0.0.0.0/0 | internet | internet |
| 10.0.0.0/24 | mgmt | mgmt_subnet |
| 10.0.1.0/24 | dmz | web_subnet |
| 10.0.2.0/24 | app | app_subnet |

### Environment

- **Organization:** chaincorp
- **Environment:** production
- **Compliance Tier:** pci
- **Log Retention:** 365 days

## Access Control Rules

### SSH Access Rules

| Rule ID | Groups | Host Group | Action | Effect |
|---------|--------|------------|--------|--------|
| rule-001 | sudo | bastion | ssh:login | permit |
| rule-002 | dba | bastion | ssh:login | permit |
| rule-005 | sudo | dbservers | ssh:login | permit |
| rule-006 | dba | dbservers | ssh:login | permit |
| rule-012 | sudo | webservers | ssh:login | permit |
| rule-014 | sudo | appservers | ssh:login | permit |
| rule-015 | developers | appservers | ssh:login | permit |

### Sudo Rules

| Rule ID | Condition | Host Group | Action | Effect | Obligations |
|---------|-----------|------------|--------|--------|-------------|
| rule-004 | groups=sudo AND clearance=secret | bastion | sudo:execute | permit | require_password=true |

### Database Access Rules

| Rule ID | Groups | Host Group | Privilege | Action | Effect |
|---------|--------|------------|-----------|--------|--------|
| rule-007 | dba | dbservers | SUPERUSER | db:login | permit |

### Network Connectivity Rules

| Rule ID | Source Network | Host Group | Port | Service | Action | Effect |
|---------|---------------|------------|------|---------|--------|--------|
| rule-003 | 0.0.0.0/0 | bastion | 22 | ssh | network:connect | permit |
| rule-008 | 10.0.2.0/24 | dbservers | 5432 | postgresql | network:connect | permit |
| rule-013 | 10.0.0.0/24 | webservers | 80 | httpd | network:connect | permit |
| rule-016 | 10.0.1.0/24 | appservers | 8080 | app | network:connect | permit |

### Filesystem Rules

| Rule ID | User | Path | Mode | Action | Effect |
|---------|------|------|------|--------|--------|
| rule-009 | postgres | /var/lib/postgresql/data | 0700 | filesystem:read | permit |
| rule-010 | postgres | /var/lib/postgresql/data | 0700 | filesystem:write | permit |
| rule-011 | postgres | /var/lib/postgresql/data | 0700 | filesystem:execute | permit |

### Default Deny

| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-017 | all | all | * | deny |

## Vulnerability Assessment

### Critical Vulnerabilities Affecting Pinned Versions

| CVE | Severity | CVSS | Remote | KEV | Pinned Version | Recommendation |
|-----|----------|------|--------|-----|----------------|----------------|
| CVE-2021-44228 | critical | 10.0 | Yes | Yes | Log4j 2.14.1 | Upgrade to Log4j 2.17.1+ immediately (Log4Shell RCE) |
| CVE-2013-1903 | critical | 10.0 | Yes | No | PostgreSQL 9.2.3 | Upgrade PostgreSQL to 9.2.4+ |
| CVE-2013-1902 | critical | 10.0 | Yes | No | PostgreSQL 9.2.3 | Upgrade PostgreSQL to 9.2.4+ |
| CVE-2021-41773 | high | 9.8 | Yes | Yes | Apache httpd 2.4.49 | Upgrade to Apache httpd 2.4.51+ (path traversal) |
| CVE-2021-42013 | critical | 9.8 | Yes | Yes | Apache httpd 2.4.49 | Upgrade to Apache httpd 2.4.51+ (bypass of CVE-2021-41773) |

### Pinned Package Versions

| Package | Pinned Version | Host Group | Vulnerable? |
|---------|---------------|------------|-------------|
| openssh-server | 9.1p1 | bastion | No critical CVEs found for this version |
| openssh-server | 9.9p1 | webservers, appservers, dbservers | No critical CVEs found for this version |
| apache2 | 2.4.49 | webservers | **YES** — CVE-2021-41773, CVE-2021-42013 |
| log4j-core | 2.14.1 | appservers | **YES** — CVE-2021-44228 (Log4Shell) |
| postgresql-9.2 | 9.2.3 | dbservers | **YES** — CVE-2013-1903, CVE-2013-1902 |

## Ambiguities and Open Questions

1. **Credentials in Ansible:** The configuration does not explicitly manage passwords or API keys via Ansible Vault. It is unclear how user authentication credentials are provisioned beyond SSH key-based access controlled by `AllowGroups`.

2. **pg_hba implicit deny:** The `pg_hba.conf` configuration only allows connections from `10.0.2.0/24`. PostgreSQL's default behavior is to deny connections not explicitly allowed, which constitutes an implicit deny. This is captured by the default-deny rule (rule-017).

3. **Bastion SSH exposure:** The bastion host allows SSH from `0.0.0.0/0` (the entire internet), which is a significant security risk, especially given the vulnerable OpenSSH version (9.1p1) pinned on the bastion.

4. **Log4j on appservers:** The Log4j 2.14.1 library is explicitly deployed on appservers, which is critically vulnerable to Log4Shell (CVE-2021-44228). This should be patched immediately.

5. **Sudo restriction scope:** The sudoers rule on the bastion only applies to users who are both in the `sudo` group AND have `secret` clearance. The `admin` user meets both criteria, but it is unclear if other users might be added to the `sudo` group without `secret` clearance.

6. **Filesystem access for postgres user:** The `postgres` user is a system account created by the PostgreSQL package, not one of the defined users in `group_vars/all.yml`. The filesystem rules assume this user exists and has the specified ownership.

7. **Network zone isolation:** The firewall rules create a network flow: internet → bastion (mgmt) → webservers (dmz) → appservers (app) → dbservers (data). However, there is no explicit firewall rule allowing SSH from the bastion to other hosts, which may indicate SSH relies on host-based access controls (AllowGroups) rather than network firewalls for internal communication.
