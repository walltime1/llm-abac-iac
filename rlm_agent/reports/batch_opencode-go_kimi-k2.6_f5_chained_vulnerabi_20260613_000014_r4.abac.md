# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 00:10:35_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 15 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "domain": null,
      "source": "group_vars/all.yml",
      "entries": [
        {
          "name": "admin",
          "uid": 1001,
          "groups": [
            "sudo"
          ],
          "department": "operations",
          "clearance": "secret"
        },
        {
          "name": "developer",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "department": "engineering",
          "clearance": "confidential"
        },
        {
          "name": "dba",
          "uid": 1003,
          "groups": [
            "dba"
          ],
          "department": "data",
          "clearance": "secret"
        }
      ]
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
      "domain": [
        "10.0.1.0/24",
        "0.0.0.0/0",
        "10.0.2.0/24",
        "10.0.0.0/24"
      ],
      "source": "group_vars/*.yml"
    }
  },
  "resources": {
    "hosts": {
      "domain": null,
      "source": "inventory.ini",
      "entries": [
        {
          "hostname": "bastion01.lab.local",
          "ip": "10.0.0.5",
          "role": "bastion",
          "zone": "mgmt",
          "inventory_group": "bastion"
        },
        {
          "hostname": "web01.lab.local",
          "ip": "10.0.1.10",
          "role": "frontend",
          "zone": "dmz",
          "inventory_group": "webservers"
        },
        {
          "hostname": "app01.lab.local",
          "ip": "10.0.2.10",
          "role": "application",
          "zone": "app",
          "inventory_group": "appservers"
        },
        {
          "hostname": "db01.lab.local",
          "ip": "10.0.3.10",
          "role": "primary",
          "zone": "data",
          "inventory_group": "dbservers"
        }
      ]
    },
    "services": {
      "domain": null,
      "source": "group_vars/*.yml",
      "entries": [
        {
          "name": "http",
          "port": 80,
          "protocol": "tcp",
          "host_group": "webservers"
        },
        {
          "name": "app",
          "port": 8080,
          "protocol": "tcp",
          "host_group": "appservers"
        },
        {
          "name": "postgres",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers"
        },
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "all"
        }
      ]
    },
    "paths": {
      "domain": null,
      "source": "roles/db/tasks/main.yml",
      "entries": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgres"
        }
      ]
    },
    "networks": {
      "domain": null,
      "source": "group_vars/*.yml",
      "entries": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "app",
          "label": "appservers_allow_from"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "mgmt",
          "label": "bastion_allow_from"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "data",
          "label": "dbservers_allow_from"
        },
        {
          "cidr": "10.0.0.0/24",
          "zone": "dmz",
          "label": "webservers_allow_from"
        }
      ]
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
        "http",
        "app",
        "postgres",
        "ssh"
      ],
      "source": "group_vars/*.yml"
    },
    "port": {
      "domain": [
        22,
        80,
        8080,
        5432
      ],
      "source": "group_vars/*.yml"
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
    }
  },
  "environment": {
    "org": {
      "domain": null,
      "source": "group_vars/all.yml",
      "value": "chaincorp"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini",
      "value": "production"
    },
    "compliance_tier": {
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml",
      "value": "pci"
    },
    "default_log_retention_days": {
      "domain": null,
      "source": "group_vars/all.yml",
      "value": 365
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
    "id": "rule-002",
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
      "lines": "21-26"
    }
  },
  {
    "id": "rule-003",
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
      "lines": "31-36"
    }
  },
  {
    "id": "rule-004",
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
      "lines": "29-34"
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
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "22-30"
    },
    "nopassword": false
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
        "equals": "postgres"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login:superuser",
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
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "host_group": {
        "equals": "dbservers"
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
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "app"
      },
      "host_group": {
        "equals": "appservers"
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
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "bastion"
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
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "http"
      },
      "host_group": {
        "equals": "webservers"
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
    "id": "rule-011",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "host_group": {
        "equals": "dbservers"
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
    "id": "rule-012",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "host_group": {
        "equals": "dbservers"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "23-28"
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "inventory.ini",
      "task": "default-deny",
      "lines": "1-1"
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
        "equals": "app"
      },
      "host_group": {
        "equals": "appservers"
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
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "bastion"
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
    "id": "rule-016",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "http"
      },
      "host_group": {
        "equals": "webservers"
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
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Upgrade OpenSSH to 9.3p2 or later on bastion hosts.",
    "source": "cve_details"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Upgrade OpenSSH to 9.8p1 or later on bastion hosts.",
    "source": "cve_details"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Version 9.9p1 is not affected; no action required.",
    "source": "cve_details"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Version 9.9p1 is not affected; no action required.",
    "source": "cve_details"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Upgrade to Log4j 2.17.0 or later and remove JNDI lookup class.",
    "source": "vuln_search"
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 9.0,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Upgrade to Log4j 2.16.0 or later.",
    "source": "vuln_search"
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 9.0,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Upgrade to Log4j 2.17.1 or later.",
    "source": "vuln_search"
  },
  {
    "cve_id": "CVE-2021-4104",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "CVE affects Log4j 1.x; pinned version is 2.14.1. No action required.",
    "source": "vuln_search"
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "CVE affects Log4j 1.x; pinned version is 2.14.1. No action required.",
    "source": "cve_details"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "CVE affects pgjdbc JDBC driver, not the PostgreSQL server itself. No action required for the pinned server version.",
    "source": "cve_details"
  },
  {
    "cve_id": "CVE-2003-0789",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "CVE predates Apache HTTP Server 2.4.49. No action required.",
    "source": "vuln_search"
  },
  {
    "cve_id": "CVE-1999-1237",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "CVE predates Apache HTTP Server 2.4.49. No action required.",
    "source": "vuln_search"
  },
  {
    "cve_id": "CVE-1999-1293",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "CVE predates Apache HTTP Server 2.4.49. No action required.",
    "source": "vuln_search"
  },
  {
    "cve_id": "CVE-2013-1777",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "CVE predates Apache HTTP Server 2.4.49. No action required.",
    "source": "vuln_search"
  },
  {
    "cve_id": "CVE-2009-2412",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "recommendation": "CVE predates Apache HTTP Server 2.4.49. No action required.",
    "source": "vuln_search"
  },
  {
    "cve_id": "CVE-2023-46604",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "CVE affects Apache ActiveMQ, not Apache HTTP Server. Discard as unrelated product.",
    "source": "cve_details"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": true,
    "recommendation": "CVE affects Log4j, not Apache HTTP Server. Discard as unrelated product.",
    "source": "vuln_search"
  }
]
```

## Report

# ABAC Policy Mining Report — ChainCorp Ansible

## 1. Policy Goal
Full ABAC policy mined from the Ansible configuration under `RLM_ANSIBLE_DIR`.

## 2. Attribute Catalog Summary
- **Subjects**: 3 users (admin, developer, dba) with groups, departments, and clearance levels.
- **Resources**: 4 hosts, 4 services, 1 filesystem path, and 4 network allow-lists.
- **Environment**: `production`, `pci` compliance tier, `chaincorp` org.

## 3. Extracted Rules
A total of 13 rules were extracted, including:
- **4 SSH access rules** (`ssh:login`) scoped by host group and user group.
- **1 sudo rule** (`sudo:execute`) on bastion for `secret` clearance users with `nopassword: false`.
- **2 database rules** (`db:superuser`, `db:login`) for the `dba` group on PostgreSQL.
- **4 network connectivity rules** (`network:connect`) for firewall allowances.
- **1 explicit deny rule** for PostgreSQL from non-appserver sources.
- **1 default-deny catch-all**.

## 4. Vulnerability Assessment
Vulnerable pinned packages were identified in `group_vars/all.yml`:
- **OpenSSH (bastion)**: `1:9.1p1-1ubuntu1` — affected by CVE-2023-38408 and CVE-2024-6387.
- **OpenSSH (other hosts)**: `1:9.9p1-3ubuntu1` — not affected.
- **Apache httpd**: `2.4.49-1` — no confirmed KEV hits for the pinned version; unrelated CVEs discarded.
- **Log4j**: `2.14.1` — affected by CVE-2021-44228, CVE-2021-45046, CVE-2021-44832.
- **PostgreSQL server**: `9.2.3-1.pgdg20.04+1` — CVE-2024-1597 affects the JDBC driver, not the server.

## 5. Ambiguities & Observations
- **Credentials**: No explicit password or key management tasks are present; SSH and DB access rely on external authentication not modeled in the playbooks.
- **pg_hba.conf**: Uses `scram-sha-256` but the exact user-to-database mapping is not specified.
- **Sudo**: The `nopassword: false` flag is present but password policy enforcement is not defined.
- **Package versions**: The bastion explicitly pins a vulnerable OpenSSH version; other hosts pin a safe version.

## 6. Recommendations
- Upgrade OpenSSH on bastion to at least `9.8p1` to address CVE-2024-6387.
- Upgrade Log4j to `2.17.1` or later to mitigate Log4Shell-related CVEs.
- Review firewall rules for `0.0.0.0/0` on bastion SSH (internet exposure).
- Add explicit `pg_hba.conf` deny lines for all non-matching sources (implicit default is modeled but not enforced by the playbook itself).
