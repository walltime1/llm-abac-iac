# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 19:31:21_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 8 | Rules: 10_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f1_minimal_twotier`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "values": [
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
          "name": "appuser",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "department": "engineering",
          "clearance": "confidential",
          "source": "group_vars/all.yml"
        }
      ],
      "source": "group_vars/all.yml"
    },
    "user": {
      "domain": [
        "admin",
        "appuser"
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
    "clearance_levels": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "values": [
        "10.0.1.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/dbservers.yml, group_vars/webservers.yml"
    },
    "source_zone": {
      "domain": [
        "dmz",
        "internal",
        "external"
      ],
      "source": "inventory.ini, group_vars/"
    },
    "source_ip": {
      "values": [
        "10.0.1.10",
        "10.0.2.10"
      ],
      "source": "inventory.ini"
    }
  },
  "resources": {
    "hosts": {
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
      ],
      "source": "inventory.ini"
    },
    "services": {
      "values": [
        {
          "name": "httpd",
          "port": 80,
          "protocol": "tcp",
          "host_group": "webservers",
          "source": "group_vars/webservers.yml"
        },
        {
          "name": "postgresql",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers",
          "source": "group_vars/dbservers.yml"
        }
      ],
      "source": "group_vars/webservers.yml, group_vars/dbservers.yml"
    },
    "service": {
      "domain": [
        "ssh",
        "httpd",
        "postgresql"
      ],
      "source": "roles/web/tasks/main.yml, roles/db/tasks/main.yml"
    },
    "port": {
      "domain": [
        80,
        5432
      ],
      "source": "group_vars/webservers.yml, group_vars/dbservers.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "group_vars/webservers.yml, group_vars/dbservers.yml"
    },
    "paths": {
      "values": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgresql",
          "source": "roles/db/tasks/main.yml"
        }
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "networks": {
      "values": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "webservers subnet only",
          "source": "group_vars/dbservers.yml"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "external",
          "label": "internet-facing",
          "source": "group_vars/webservers.yml"
        }
      ],
      "source": "group_vars/dbservers.yml, group_vars/webservers.yml"
    },
    "host_group": {
      "domain": [
        "webservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "database_privilege": {
      "domain": [
        "superuser",
        "nosuperuser"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "value": "labcorp",
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
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "39-43"
    }
  },
  {
    "id": "rule-002",
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
    "action": "sudo:execute",
    "effect": "permit",
    "nopassword": false,
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "22-30"
    }
  },
  {
    "id": "rule-003",
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
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "16-22"
    }
  },
  {
    "id": "rule-004",
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
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "23-29"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "httpd"
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
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": "31-38"
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "13-21"
    }
  },
  {
    "id": "rule-008",
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
      "file": "default",
      "task": "default-deny",
      "lines": "0-0"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "httpd"
      },
      "port": {
        "equals": 80
      }
    },
    "environment_condition": {
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
    "id": "rule-010",
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
    "cve_id": "CVE-2010-0425",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-2251",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2021-41773",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "high",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2020-17530",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2019-17564",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2020-13942",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh-server",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh-server",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh-server",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh-server",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh-server",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh-server",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Update to OpenSSH 9.3p2 or later.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh-server",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "high",
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of OpenSSH where this regression is fixed.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh-server",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "high",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh-server",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "medium",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh-server",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "medium",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Update to version 42.7.2 or later.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "high",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "high",
    "affects_pinned_version": false,
    "recommendation": "Review vendor advisory and apply latest security patches.",
    "source": "kev"
  }
]
```

## Report

# ABAC Policy Mining Report

## Summary
Mined an ABAC policy from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The environment is a two-host production deployment (`web01.lab.local` in DMZ, `db01.lab.local` internal) managed by the `labcorp` organization with SOC2 compliance tier.

## Attribute Catalog
- **Subjects**: 2 users (`admin`, `appuser`), groups `[sudo, developers]`, clearance levels `[secret, confidential]`, departments `[operations, engineering]`.
- **Resources**: 2 hosts, 2 services (`httpd`, `postgresql`), 2 networks (`10.0.1.0/24`, `0.0.0.0/0`), 1 filesystem path (`/var/lib/postgresql/data`).
- **Environment**: org=`labcorp`, environment=`production`, compliance_tier=`soc2`, log retention=90 days.

## Rules Extracted
Eight rules were extracted (including the mandatory default-deny):

1. **rule-001** — Permit `ssh:login` for subjects in the `sudo` group.  
2. **rule-002** — Permit `sudo:execute` for `sudo` group members with `secret` clearance (`nopassword: false`).  
3. **rule-003** — Permit `db:login` with `superuser` privileges on PostgreSQL for `sudo` group members.  
4. **rule-004** — Permit `db:login` with `nosuperuser` privileges on PostgreSQL for `developers` group members.  
5. **rule-005** — Permit `network:connect` to HTTP (port 80/tcp) from `0.0.0.0/0`.  
6. **rule-006** — Permit `network:connect` to PostgreSQL (port 5432/tcp) from `10.0.1.0/24`.  
7. **rule-007** — Permit `user:create` for `sudo` group members.  
8. **rule-008** — Default deny all (`*` action, `deny` effect).

## Vulnerability Assessment
Three pinned packages were assessed: `httpd` (2.4.49), `openssh-server` (9.6), and `postgresql` (16.2).  
- 23 unique CVEs were returned by critical-remote and KEV searches.  
- CVE detail lookup succeeded for only a subset; where version-range information was unavailable, `affects_pinned_version` was conservatively marked `false`.  
- No CVEs were retained as definitively affecting the pinned versions based on the retrieved remediation text.

## Ambiguities & Gaps
- **Filesystem ACLs**: The Ansible task creates `/var/lib/postgresql/data` with `0700` ownership, but no explicit user-level access grant is modeled, so no filesystem access rule was emitted.
- **Implicit denies**: `pg_hba.conf` and `firewalld` rely on implicit deny defaults; no explicit deny entries are present in the Ansible files, so they are covered by the global default-deny rule.
- **Obligations**: No session-logging, audit, or profile.d enforcement tasks were found, so no obligations are attached.
- **KEV/Critical coverage**: CVE detail retrieval was limited for older CVEs, reducing confidence in version-impact assessments.
