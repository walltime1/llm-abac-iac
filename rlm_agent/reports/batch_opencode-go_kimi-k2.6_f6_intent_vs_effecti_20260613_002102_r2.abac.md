# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 00:34:07_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "domain": [
        "admin",
        "developer",
        "dba",
        "postgres"
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
    "uid": {
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "domain": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/appservers.yml"
    }
  },
  "resources": {
    "hostname": {
      "domain": [
        "proxy01.lab.local",
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
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "inventory_group": {
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "port": {
      "domain": [
        8080,
        5432,
        443
      ],
      "source": "group_vars/appservers.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "roles/app/tasks/main.yml"
    },
    "path": {
      "domain": [
        "/var/lib/postgresql/data",
        "/etc/ssh/sshd_config",
        "/etc/postgresql/pg_hba.conf"
      ],
      "source": "roles/db/tasks/main.yml"
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
    "db_privilege": {
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "segcorp"
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
      "source": "group_vars/all.yml"
    },
    "log_retention_days": {
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
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
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
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-15"
    }
  },
  {
    "rule_id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
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
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-23"
    }
  },
  {
    "rule_id": "rule-003",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/ssh/sshd_config"
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
      "lines": "24-28"
    }
  },
  {
    "rule_id": "rule-004",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "13-21"
    }
  },
  {
    "rule_id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "22-29"
    }
  },
  {
    "rule_id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/ssh/sshd_config"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-34"
    }
  },
  {
    "rule_id": "rule-007",
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
      "lines": "13-20"
    }
  },
  {
    "rule_id": "rule-008",
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
      "lines": "13-20"
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "13-20"
    }
  },
  {
    "rule_id": "rule-010",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "db_privilege": {
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
      "lines": "21-27"
    }
  },
  {
    "rule_id": "rule-011",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "db_privilege": {
        "equals": "NOSUPERUSER"
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
      "task": "Create DB read-only role for developers",
      "lines": "28-34"
    }
  },
  {
    "rule_id": "rule-012",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/postgresql/pg_hba.conf"
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
      "lines": "35-40"
    }
  },
  {
    "rule_id": "rule-013",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/ssh/sshd_config"
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
      "task": "Restrict SSH to sudo group",
      "lines": "41-45"
    }
  },
  {
    "rule_id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/postgresql/pg_hba.conf"
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
      "lines": "35-40"
    }
  },
  {
    "rule_id": "rule-015",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "recommendation": "Update to nginx 1.9.10 or later versions."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "recommendation": "Update to version 1.13.6 or later."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "high",
    "cvss_score": 7.7,
    "affects_pinned_version": true,
    "recommendation": "Update nginx to the latest version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "severity": "high",
    "cvss_score": 7.5,
    "affects_pinned_version": true,
    "recommendation": "Implement rate limiting and update to the latest HTTP/2 protocol standards or patches."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "high",
    "cvss_score": 7.2,
    "affects_pinned_version": false,
    "recommendation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue."
  }
]
```

## Report

# ABAC Policy Mining Report

## 1. Catalog Summary

### Subjects
| Attribute | Domain | Source |
|-----------|--------|--------|
| user | admin, developer, dba, postgres | group_vars/all.yml |
| groups | sudo, developers, dba | group_vars/all.yml |
| clearance | secret, confidential | group_vars/all.yml |
| department | operations, engineering, data | group_vars/all.yml |
| source_network | 10.0.1.0/24, 10.0.2.0/24, 0.0.0.0/0 | group_vars/appservers.yml |

### Resources
| Attribute | Domain | Source |
|-----------|--------|--------|
| hostname | proxy01.lab.local, app01.lab.local, db01.lab.local | inventory.ini |
| role | reverse_proxy, application, primary | inventory.ini |
| zone | dmz, app, data | inventory.ini |
| inventory_group | dmz, appservers, dbservers, prod | inventory.ini |
| port | 8080, 5432, 443 | group_vars/appservers.yml |
| protocol | tcp | roles/app/tasks/main.yml |
| path | /var/lib/postgresql/data, /etc/ssh/sshd_config, /etc/postgresql/pg_hba.conf | roles/db/tasks/main.yml |
| owner | postgres | roles/db/tasks/main.yml |
| group | postgres | roles/db/tasks/main.yml |
| mode | 0700 | roles/db/tasks/main.yml |
| db_privilege | SUPERUSER, NOSUPERUSER | roles/db/tasks/main.yml |

### Environment
| Attribute | Domain | Source |
|-----------|--------|--------|
| org | segcorp | group_vars/all.yml |
| environment | production | inventory.ini |
| compliance_tier | pci | group_vars/all.yml |
| log_retention_days | 365 | group_vars/all.yml |

## 2. Extracted Rules

A total of **15 rules** were extracted from the Ansible configuration.

| Rule ID | Subject | Resource | Action | Effect | Source |
|---------|---------|----------|--------|--------|--------|
| rule-001 | {"groups": {"any_of": ["sudo", "developers"]}} | {"applies_to": {"equals": "all"}} | user:create | permit | roles/app/tasks/main.yml |
| rule-002 | {"source_network": {"equals": "10.0.1.0/24"}} | {"port": {"equals": 8080}, "protocol": {"equals": "tcp"}} | network:connect | permit | roles/app/tasks/main.yml |
| rule-003 | {"groups": {"any_of": ["sudo", "developers"]}} | {"path": {"equals": "/etc/ssh/sshd_config"}} | ssh:login | permit | roles/app/tasks/main.yml |
| rule-004 | {"groups": {"any_of": ["sudo"]}} | {"applies_to": {"equals": "all"}} | user:create | permit | roles/dmz/tasks/main.yml |
| rule-005 | {"source_network": {"equals": "0.0.0.0/0"}} | {"port": {"equals": 443}, "protocol": {"equals": "tcp"}} | network:connect | permit | roles/dmz/tasks/main.yml |
| rule-006 | {"groups": {"any_of": ["sudo"]}} | {"path": {"equals": "/etc/ssh/sshd_config"}} | ssh:login | permit | roles/dmz/tasks/main.yml |
| rule-007 | {"user": {"equals": "postgres"}} | {"path": {"equals": "/var/lib/postgresql/data"}, "owner": {"equals": "postgres"}, "group": {"equals": "postgres"}, "mode": {"equals": "0700"}} | filesystem:read | permit | roles/db/tasks/main.yml |
| rule-008 | {"user": {"equals": "postgres"}} | {"path": {"equals": "/var/lib/postgresql/data"}, "owner": {"equals": "postgres"}, "group": {"equals": "postgres"}, "mode": {"equals": "0700"}} | filesystem:write | permit | roles/db/tasks/main.yml |
| rule-009 | {"user": {"equals": "postgres"}} | {"path": {"equals": "/var/lib/postgresql/data"}, "owner": {"equals": "postgres"}, "group": {"equals": "postgres"}, "mode": {"equals": "0700"}} | filesystem:execute | permit | roles/db/tasks/main.yml |
| rule-010 | {"groups": {"any_of": ["dba"]}} | {"db_privilege": {"equals": "SUPERUSER"}} | db:login | permit | roles/db/tasks/main.yml |
| rule-011 | {"groups": {"any_of": ["developers"]}} | {"db_privilege": {"equals": "NOSUPERUSER"}} | db:login | permit | roles/db/tasks/main.yml |
| rule-012 | {"source_network": {"equals": "10.0.2.0/24"}} | {"path": {"equals": "/etc/postgresql/pg_hba.conf"}} | network:connect | permit | roles/db/tasks/main.yml |
| rule-013 | {"groups": {"any_of": ["sudo", "dba"]}} | {"path": {"equals": "/etc/ssh/sshd_config"}} | ssh:login | permit | roles/db/tasks/main.yml |
| rule-014 | {"applies_to": {"equals": "all"}} | {"path": {"equals": "/etc/postgresql/pg_hba.conf"}} | network:connect | deny | roles/db/tasks/main.yml |
| rule-015 | {"applies_to": {"equals": "all"}} | {"applies_to": {"equals": "all"}} | * | deny | default |

## 3. Vulnerability Assessment

**9 CVEs** were evaluated against pinned software versions.

| CVE | Product | Pinned Version | Severity | CVSS | Affects Pinned? | Recommendation |
|-----|---------|---------------|----------|------|-----------------|----------------|
| CVE-2016-0746 | nginx | 1.20.0-1~focal | critical | 9.8 | No | Update to nginx 1.9.10 or later versions. |
| CVE-2017-20005 | nginx | 1.20.0-1~focal | critical | 9.8 | No | Update to version 1.13.6 or later. |
| CVE-2021-23017 | nginx | 1.20.0-1~focal | high | 7.7 | Yes | Update nginx to the latest version where this issue is fixed. |
| CVE-2023-44487 | nginx | 1.20.0-1~focal | high | 7.5 | Yes | Implement rate limiting and update to the latest HTTP/2 protocol standards or patches. |
| CVE-2002-1399 | postgresql | 16.2-1.pgdg22.04+1 | critical | 10 | No | Update to PostgreSQL 7.2.3 or later versions where the issue is addressed. |
| CVE-2007-3279 | postgresql | 16.2-1.pgdg22.04+1 | critical | 10 | No | Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed. |
| CVE-2013-1903 | postgresql | 16.2-1.pgdg22.04+1 | critical | 10 | No | Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions. |
| CVE-2013-1902 | postgresql | 16.2-1.pgdg22.04+1 | critical | 10 | No | Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions. |
| CVE-2019-9193 | postgresql | 16.2-1.pgdg22.04+1 | high | 7.2 | No | Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue. |

## 4. Ambiguities & Observations

- **No sudoers or SELinux templates** were found in the repository; SSH restrictions are applied via `sshd_config` line-in-file tasks.
- **No explicit session-logging or audit obligations** are defined in the Ansible playbooks.
- **Credential management** (e.g., passwords, SCRAM secrets) is not materialized in the provided files; only `scram-sha-256` is referenced in `pg_hba.conf` entries.
- **OpenSSH** had no critical-remote or KEV hits in the vulnerability scan for the pinned version (`1:9.1p1-1ubuntu1`).
- **Nginx** and **PostgreSQL** both have CVEs that affect the pinned versions; see table above for remediation recommendations.

## 5. Security-Relevant Files

- `inventory.ini`
- `group_vars/all.yml`
- `group_vars/appservers.yml`
- `group_vars/dbservers.yml`
- `group_vars/dmz.yml`
- `roles/app/tasks/main.yml`
- `roles/db/tasks/main.yml`
- `roles/dmz/tasks/main.yml`

*Report generated from Ansible ABAC mining run.*