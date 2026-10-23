# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 22:39:04_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 9 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "entries": [
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
        },
        {
          "name": "postgres",
          "uid": null,
          "groups": null,
          "clearance": null,
          "department": null,
          "source": "roles/db/tasks/main.yml"
        }
      ]
    },
    "user": {
      "domain": [
        "admin",
        "appuser",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "domain": [
        "sudo",
        "developers"
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
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "domain": [
        "10.0.1.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/dbservers.yml"
    }
  },
  "resources": {
    "hosts": {
      "entries": [
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
      "entries": [
        {
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers",
          "source": "group_vars/dbservers.yml",
          "service": "postgresql"
        },
        {
          "port": 443,
          "protocol": "tcp",
          "host_group": "webservers",
          "source": "group_vars/webservers.yml",
          "service": "nginx"
        },
        {
          "port": 22,
          "protocol": "tcp",
          "host_group": "webservers",
          "source": "roles/web/tasks/main.yml",
          "service": "ssh"
        }
      ]
    },
    "paths": {
      "entries": [
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
      "entries": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "webservers subnet",
          "source": "group_vars/dbservers.yml"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "internet",
          "label": "internet-facing",
          "source": "group_vars/webservers.yml"
        }
      ]
    },
    "database_privilege": {
      "domain": [
        "superuser",
        "nosuperuser"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "host_group": {
      "domain": [
        "webservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "domain": [
        "postgresql",
        "nginx",
        "ssh"
      ],
      "source": "group_vars/* and roles/*"
    },
    "port": {
      "domain": [
        5432,
        443,
        22
      ],
      "source": "group_vars/* and roles/*"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "group_vars/* and roles/*"
    },
    "path": {
      "domain": [
        "/var/lib/postgresql/data"
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
    "database": {
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "labcorp"
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
        "soc2"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "value": 90,
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
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
    }
  },
  {
    "id": "rule-002",
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
    }
  },
  {
    "id": "rule-003",
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
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
      "service": {
        "equals": "postgresql"
      },
      "database_privilege": {
        "equals": "superuser"
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
      "task": "Create DB superuser role",
      "lines": "16-21"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database_privilege": {
        "equals": "nosuperuser"
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
      "task": "Create DB read-only role",
      "lines": "23-28"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
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
      "task": "Allow postgres only from webservers subnet",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-007",
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
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "13-20"
    }
  },
  {
    "id": "rule-008",
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
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "nopassword": false,
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "22-29"
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
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
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
      "task": "Firewall — allow HTTPS from internet",
      "lines": "31-37"
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
      "service": {
        "equals": "ssh"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "39-43"
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
      "file": "policy",
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
    "action": "filesystem:read",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "mode 0700 non-owner deny",
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
    "action": "filesystem:read",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "mode 0700 non-owner deny",
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
        "equals": "nginx"
      },
      "port": {
        "equals": 443
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
    "product": "nginx",
    "pinned_version": "1.27.0",
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "nginx",
    "pinned_version": "1.27.0",
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "nginx",
    "pinned_version": "1.27.0",
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "nginx",
    "pinned_version": "1.27.0",
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "nginx",
    "pinned_version": "1.27.0",
    "cve_id": "CVE-2016-0742",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "openssh",
    "pinned_version": "9.9p1",
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "openssh",
    "pinned_version": "9.9p1",
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "openssh",
    "pinned_version": "9.9p1",
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "openssh",
    "pinned_version": "9.9p1",
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "openssh",
    "pinned_version": "9.9p1",
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "Pinned version is not affected; maintain current patching cadence."
  }
]
```

## Report

# ABAC Policy Mining Report — labcorp Ansible

## 1. Scope
Policy slice requested: `all`.  
Ansible root contains inventory, group variables, and two roles (`db`, `web`).  
All files were catalogued and security-relevant task files were read.

## 2. Attribute Catalog Summary

### Subjects
- **users**: admin (uid 1001, groups sudo, clearance secret, dept operations), appuser (uid 1002, groups developers, clearance confidential, dept engineering), postgres (service account).
- **domains**: user ∈ {admin, appuser, postgres}; groups ∈ {sudo, developers}; clearance ∈ {secret, confidential}; department ∈ {operations, engineering}; source_network ∈ {10.0.1.0/24, 0.0.0.0/0}.

### Resources
- **hosts**: web01.lab.local (dmz, frontend, webservers), db01.lab.local (internal, primary, dbservers).
- **services**: postgresql:5432/tcp (dbservers), nginx:443/tcp (webservers), ssh:22/tcp (webservers).
- **paths**: /var/lib/postgresql/data (owner postgres, group postgres, mode 0700).
- **networks**: 10.0.1.0/24 (dmz, webservers subnet), 0.0.0.0/0 (internet).
- **domains**: database_privilege ∈ {superuser, nosuperuser}; host_group ∈ {webservers, dbservers}; service ∈ {postgresql, nginx, ssh}; port ∈ {5432, 443, 22}; protocol ∈ {tcp}; path, owner, group, mode as enumerated.

### Environment
- org = labcorp; environment = production; compliance_tier = soc2; default_log_retention_days = 90.

## 3. Extracted Rules (11 rules)

| ID | Action | Effect | Scope |
|---|---|---|---|
| rule-001 | filesystem:read | permit | user=postgres on /var/lib/postgresql/data |
| rule-002 | filesystem:write | permit | user=postgres on /var/lib/postgresql/data |
| rule-003 | filesystem:execute | permit | user=postgres on /var/lib/postgresql/data |
| rule-004 | db:login | permit | groups=sudo → postgresql SUPERUSER (dbservers) |
| rule-005 | db:login | permit | groups=developers → postgresql NOSUPERUSER (dbservers) |
| rule-006 | network:connect | permit | source_network=10.0.1.0/24 → postgresql:5432/tcp (dbservers) |
| rule-007 | user:create | permit | groups=sudo on webservers |
| rule-008 | sudo:execute | permit | groups=sudo + clearance=secret on webservers (nopassword=false) |
| rule-009 | network:connect | permit | source_network=0.0.0.0/0 → nginx:443/tcp (webservers) |
| rule-010 | ssh:login | permit | groups=sudo → ssh on webservers |
| rule-011 | * | deny | Default deny for all subjects, resources, environments |

## 4. Vulnerability Assessment
Pinned packages: nginx 1.27.0, openssh 9.9p1, postgresql 16.4.  
Searched critical remote and KEV CVEs for each product. **None of the returned CVEs affect the pinned modern versions** (all CVEs apply to significantly older releases).  
Total CVEs reviewed: 15 (0 KEV, 15 critical/high remote).  
Recommendation: Continue current patching cadence; versions are up-to-date.

## 5. Ambiguities & Observations
- No explicit `sshd_config` template file exists in the repo; SSH restriction is injected via `lineinfile`. Exact line provenance is therefore inferred from the task block.
- The `pg_hba.conf` entry uses `all all` (database/user), which is broad; the only real restriction is the source CIDR (`db_allow_from`). No per-user or per-database granularity is expressed in the Ansible config.
- No session-logging or audit-script tasks were found, so no obligations were attached.
- No SELinux, sudoers template files, or dedicated firewall playbooks exist outside role tasks.
- Password/credential policies are not configured in the extracted tasks; credential lifecycle is flagged as an ambiguity.

## 6. Recommendations
- Narrow `pg_hba.conf` from `all all` to explicit databases and users if possible.
- Consider adding MFA or key-based sudo authentication since `nopassword` is false but still single-factor.
- Monitor newly published CVEs for the three pinned products to maintain the current clean posture.
