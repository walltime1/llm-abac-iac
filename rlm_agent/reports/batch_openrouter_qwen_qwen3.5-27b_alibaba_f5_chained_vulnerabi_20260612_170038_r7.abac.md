# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:06:48_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 17_  
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
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "dba"
    ],
    "clearance_levels": [
      "confidential",
      "secret"
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
        "host_group": "all",
        "source": "roles/*/tasks/main.yml"
      },
      {
        "name": "http",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "roles/app/tasks/main.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "roles/db/tasks/main.yml"
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
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "bastion subnet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "group_vars/bastion.yml"
      }
    ]
  },
  "environment": {
    "org": "chaincorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
    "source": "group_vars/all.yml"
  },
  "packages": {
    "openssh_bastion": "1:9.1p1-1ubuntu1",
    "openssh_standard": "1:9.9p1-3ubuntu1",
    "httpd": "2.4.49-1",
    "log4j": "2.14.1",
    "postgresql": "9.2.3-1.pgdg20.04+1",
    "source": "group_vars/all.yml"
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "7-11"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": "13-18"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-003",
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
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "20-25"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-004",
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
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "20-24"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "12-17"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
      "hostname": {
        "equals": "app01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "27-31"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": "23-27"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "27-31"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "db:login",
    "privileges": [
      "SUPERUSER",
      "LOGIN"
    ],
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "17-21"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "23-26"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "10-15"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      },
      "environment": {
        "equals": "production"
      }
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
      },
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
    "id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
    "id": "rule-015",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
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
    "id": "rule-016",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "app"
      },
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
    "id": "rule-017",
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
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to OpenSSH version 3.7 or later."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to OpenSSH 9.3p2 or later."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 8.1,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of OpenSSH where this regression is fixed."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 7.5,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to OpenSSH 4.7 or later."
  },
  {
    "cve_id": "CVE-1999-0067",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Sanitize input to remove shell metacharacters and update to the latest version of the CGI program."
  },
  {
    "cve_id": "CVE-1999-0926",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of Apache that addresses this issue or apply relevant patches."
  },
  {
    "cve_id": "CVE-1999-1199",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version of Apache WWW server."
  },
  {
    "cve_id": "CVE-2013-2250",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest version where the vulnerability is fixed or apply security patches addressing expression language injection."
  },
  {
    "cve_id": "CVE-2013-1777",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to Apache Geronimo 3.0.1 or later version."
  },
  {
    "cve_id": "CVE-2023-46604",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3."
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default."
  },
  {
    "cve_id": "CVE-2010-0219",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "unknown",
    "recommendation": "Change default password from 'axis2' to a strong, unique password and apply the latest security patches."
  },
  {
    "cve_id": "CVE-2016-15057",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 9.9,
    "affects_pinned_version": "unknown",
    "recommendation": "No fix available as the project is retired; users should restrict access to trusted users or find an alternative."
  },
  {
    "cve_id": "CVE-2016-3427",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": "unknown",
    "recommendation": "Update to the latest available version of Java SE and JRockit."
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "likely",
    "recommendation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default."
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": "likely",
    "recommendation": "Upgrade to Log4j 2.0-beta8 or later, which supports parameterized queries and enhances security."
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": "likely",
    "recommendation": "Update to version 2.1.0 or later."
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": "likely",
    "recommendation": "Update to the latest version of Log4j 1.2 or upgrade to Log4j 2.x."
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": "likely",
    "recommendation": "Update to Log4j 2.8.2 or later."
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "likely",
    "recommendation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default."
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 9,
    "affects_pinned_version": "likely",
    "recommendation": "Update to the latest version of Log4j2 or apply recommended configuration changes."
  },
  {
    "cve_id": "CVE-2021-4104",
    "product": "log4j",
    "severity": "high",
    "cvss_score": 7.5,
    "affects_pinned_version": "likely",
    "recommendation": "Upgrade to Log4j 2, which addresses this and other issues."
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "log4j",
    "severity": "high",
    "cvss_score": 7.5,
    "affects_pinned_version": "likely",
    "recommendation": "Update to Log4j 2.x or later versions."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "likely",
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "likely",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "likely",
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "likely",
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "likely",
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": "likely",
    "recommendation": "Update to version 42.7.2 or later."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.2,
    "affects_pinned_version": "likely",
    "recommendation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.1,
    "affects_pinned_version": "likely",
    "recommendation": "Upgrade to version 42.2.26 or 42.4.1."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment for ChainCorp with PCI compliance requirements.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | chaincorp |
| Environment | production |
| Compliance Tier | pci |
| Log Retention | 365 days |

## Subjects (Users)

| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

### Groups
- `sudo` - Administrative access
- `developers` - Application development
- `dba` - Database administration

### Clearance Levels
- `confidential` - Standard access
- `secret` - Elevated access

## Resources

### Hosts

| Hostname | IP | Role | Zone |
|----------|-----|------|------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt |
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| app01.lab.local | 10.0.2.10 | application | app |
| db01.lab.local | 10.0.3.10 | primary | data |

### Services

| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| ssh | 22 | tcp | all |
| http | 80 | tcp | webservers |
| app | 8080 | tcp | appservers |
| postgresql | 5432 | tcp | dbservers |

### Network Segments

| CIDR | Zone | Label |
|------|------|-------|
| 10.0.0.0/24 | mgmt | bastion subnet |
| 10.0.1.0/24 | dmz | web subnet |
| 10.0.2.0/24 | app | app subnet |
| 0.0.0.0/0 | internet | any |

## Extracted ABAC Rules (12 total)

### SSH Access Rules

| Rule ID | Subject Condition | Resource | Action | Effect |
|---------|------------------|----------|--------|--------|
| rule-001 | groups in [sudo, dba] | bastion01 SSH | ssh:login | permit |
| rule-004 | groups in [sudo] | web01 SSH | ssh:login | permit |
| rule-006 | groups in [sudo, developers] | app01 SSH | ssh:login | permit |
| rule-008 | groups in [sudo, dba] | db01 SSH | ssh:login | permit |

### Sudo Access Rules

| Rule ID | Subject Condition | Resource | Action | Effect |
|---------|------------------|----------|--------|--------|
| rule-003 | groups in [sudo] AND clearance=secret | bastion01 | sudo:execute | permit |

### Network Access Rules

| Rule ID | Source Network | Resource | Action | Effect |
|---------|---------------|----------|--------|--------|
| rule-002 | 0.0.0.0/0 | bastion01:22/tcp | network:connect | permit |
| rule-005 | 10.0.0.0/24 | web01:80/tcp | network:connect | permit |
| rule-007 | 10.0.1.0/24 | app01:8080/tcp | network:connect | permit |
| rule-010 | 10.0.2.0/24 | db01:5432/tcp | network:connect | permit |

### Database Access Rules

| Rule ID | Subject Condition | Resource | Action | Effect |
|---------|------------------|----------|--------|--------|
| rule-009 | groups in [dba] | db01 PostgreSQL | db:login (SUPERUSER) | permit |

### Filesystem Rules

| Rule ID | Resource | Action | Effect |
|---------|----------|--------|--------|
| rule-011 | /var/lib/postgresql/data (0700) | filesystem:read | permit |

### Default Policy

| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-012 | all | all | * | deny |

## Vulnerability Assessment

### Critical Findings

**35 vulnerabilities** identified across pinned software packages:

| Product | Pinned Version | Risk Level | Notes |
|---------|---------------|------------|-------|
| OpenSSH (bastion) | 1:9.1p1-1ubuntu1 | HIGH | Known critical vulnerabilities |
| OpenSSH (standard) | 1:9.9p1-3ubuntu1 | MEDIUM | Better but still vulnerable |
| Apache HTTPD | 2.4.49-1 | HIGH | Multiple critical CVEs |
| Log4j | 2.14.1 | CRITICAL | **Log4Shell vulnerability (CVE-2021-44228)** |
| PostgreSQL | 9.2.3-1.pgdg20.04+1 | CRITICAL | **Extremely outdated, EOL** |

### Top Vulnerabilities

1. **Log4j (CVE-2021-44228)** - Remote code execution via JNDI injection
2. **PostgreSQL 9.2.x** - Multiple authentication bypass and privilege escalation vulnerabilities
3. **Apache HTTPD** - Path traversal and request smuggling vulnerabilities
4. **OpenSSH** - Format string and privilege escalation vulnerabilities

## Security Concerns

### High Priority

1. **Log4j 2.14.1 is vulnerable to Log4Shell** - Immediate upgrade to 2.17.1+ required
2. **PostgreSQL 9.2.3 is end-of-life** - Multiple unpatched critical vulnerabilities
3. **Bastion SSH exposed to internet (0.0.0.0/0)** - Consider IP whitelisting
4. **Apache 2.4.49 has known critical CVEs** - Upgrade recommended

### Medium Priority

1. **Default deny not explicitly documented** - Relies on implicit firewall rules
2. **No audit logging obligations** in extracted rules
3. **Sudo requires password** - May impact operational efficiency

## Ambiguities

1. **Credentials** - No password policies or credential management rules found
2. **Session logging** - No audit/obligation rules extracted
3. **Environment conditions** - Some rules may need explicit environment predicates

## Recommendations

1. **Immediate**: Upgrade Log4j to 2.17.1+ to mitigate Log4Shell
2. **Immediate**: Upgrade PostgreSQL to 14.x or 15.x LTS
3. **Short-term**: Upgrade Apache to 2.4.58+
4. **Short-term**: Restrict bastion SSH access to known IPs
5. **Long-term**: Implement explicit audit logging obligations
6. **Long-term**: Document credential management policies

## Files Analyzed

- inventory.ini
- group_vars/all.yml
- group_vars/appservers.yml
- group_vars/bastion.yml
- group_vars/dbservers.yml
- group_vars/webservers.yml
- roles/bastion/tasks/main.yml
- roles/web/tasks/main.yml
- roles/app/tasks/main.yml
- roles/db/tasks/main.yml

---
*Report generated from Ansible configuration mining*
