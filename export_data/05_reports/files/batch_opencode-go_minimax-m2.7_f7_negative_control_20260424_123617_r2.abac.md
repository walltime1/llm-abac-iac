# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 12:51:18_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 8 | Rules: 12_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

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
    }
  },
  "resources": {
    "hosts": {
      "domain": null,
      "source": "inventory.ini",
      "entries": [
        {
          "hostname": "web01.lab.local",
          "ip": "10.0.1.10",
          "role": "frontend",
          "zone": "dmz",
          "inventory_group": "webservers"
        },
        {
          "hostname": "db01.lab.local",
          "ip": "10.0.2.10",
          "role": "primary",
          "zone": "internal",
          "inventory_group": "dbservers"
        }
      ]
    },
    "services": {
      "domain": null,
      "source": "group_vars/dbservers.yml, group_vars/webservers.yml",
      "entries": [
        {
          "name": "https",
          "port": 443,
          "protocol": "tcp",
          "host_group": "webservers"
        },
        {
          "name": "postgresql",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers"
        }
      ]
    },
    "networks": {
      "domain": null,
      "source": "group_vars/dbservers.yml, group_vars/webservers.yml",
      "entries": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "webservers subnet"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "public",
          "label": "internet"
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
          "mode": "0700"
        }
      ]
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
    "description": "Allow SSH login for users in the sudo group on web hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        23,
        28
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Allow sudo execution (with password) for admin users with secret clearance",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        14,
        21
      ]
    },
    "obligations": [
      {
        "type": "require_password",
        "enforced_by": "community.general.sudoers (nopassword=false)"
      }
    ]
  },
  {
    "rule_id": "rule-003",
    "description": "Allow inbound HTTPS connections from any source to web servers",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "https"
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        23,
        30
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow creation of local shell accounts for sudo group members on web hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        8,
        13
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow DB SUPERUSER login for sudo group members on database hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        9,
        13
      ]
    },
    "obligations": [
      {
        "type": "privilege_level",
        "value": "SUPERUSER"
      }
    ]
  },
  {
    "rule_id": "rule-006",
    "description": "Allow read-only DB login for developers group members on database hosts",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        14,
        18
      ]
    },
    "obligations": [
      {
        "type": "privilege_level",
        "value": "NOSUPERUSER"
      }
    ]
  },
  {
    "rule_id": "rule-007",
    "description": "Allow PostgreSQL connections from the webservers subnet (10.0.1.0/24)",
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
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        19,
        23
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Allow postgres OS user full access to the PostgreSQL data directory",
    "subject_condition": {
      "groups": {
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        5,
        10
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Default deny all access not explicitly permitted above",
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
      "file": "inventory.ini",
      "task": "implicit deny default",
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
    "id": "rule-002",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "https"
      },
      "host_group": {
        "equals": "webservers"
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
    "id": "rule-003",
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
[]
```

## Report

# ABAC Policy Mining Report
## Source: Ansible configuration at `RLM_ANSIBLE_DIR`

---

## Phase 1 — Attribute Catalog

### Subjects

| Attribute | Domain / Entries | Source |
|---|---|---|
| users | admin (uid:1001, sudo, secret, ops), appuser (uid:1002, developers, confidential, eng) | group_vars/all.yml |
| groups | [sudo, developers] | group_vars/all.yml |
| clearance_levels | [secret, confidential] | group_vars/all.yml |
| departments | [operations, engineering] | group_vars/all.yml |

### Resources

| Attribute | Entries | Source |
|---|---|---|
| hosts | web01.lab.local (10.0.1.10, frontend, dmz), db01.lab.local (10.0.2.10, primary, internal) | inventory.ini |
| services | https (443/tcp, webservers), postgresql (5432/tcp, dbservers) | group_vars/*.yml |
| networks | 10.0.1.0/24 (dmz, webservers subnet), 0.0.0.0/0 (public, internet) | group_vars/*.yml |
| paths | /var/lib/postgresql/data (owner:postgres, group:postgres, mode:0700) | roles/db/tasks/main.yml |

### Environment

| Attribute | Value | Source |
|---|---|---|
| org | labcorp | group_vars/all.yml |
| environment | production | inventory.ini |
| compliance_tier | soc2 | group_vars/all.yml, inventory.ini |

---

## Phase 1.5 — Vulnerability Assessment

| Package | Pinned Version | CVEs Found | Applicable? | Notes |
|---|---|---|---|---|
| nginx | 1.27.0-1~noble | 5 (CVE-2016-0746, CVE-2021-46461, CVE-2017-20005, etc.) | **No** | CVEs affect nginx ≤1.8.0 / ≤1.13.5. Pinned version is far ahead. |
| postgresql | 16.4-1.pgdg24.04+1 | 5 (CVE-2007-3279, CVE-2002-1399, CVE-2013-1903, etc.) | **No** | CVEs affect PostgreSQL 7.2–9.2.x. Pinned version 16.4 is not affected. |
| openssh | 1:9.9p1-3ubuntu1 | 5 (CVE-2003-0786, CVE-2000-0999, CVE-2000-0525, etc.) | **No** | CVEs are from 2000–2003. Pinned version 9.9p1 is not affected. |

**Result: Zero applicable vulnerabilities.** All pinned software versions are current and no known exploits affect the deployed versions. KEV (Known Exploited Vulnerabilities) entries exist for these product families but none apply to version 1.27.0 / 16.4 / 9.9p1.

---

## Phase 1.6 — Security Scope (by path pattern)

| File | Classification | Read in Phase 2? |
|---|---|---|
| inventory.ini | inventory | ✅ yes (Phase 1) |
| group_vars/all.yml | group_vars | ✅ yes (Phase 1) |
| group_vars/dbservers.yml | group_vars | ✅ yes (Phase 1) |
| group_vars/webservers.yml | group_vars | ✅ yes (Phase 1) |
| roles/web/tasks/main.yml | role task — security-relevant | ✅ yes (Phase 2) |
| roles/db/tasks/main.yml | role task — security-relevant | ✅ yes (Phase 2) |
| README.md | documentation | skip |

---

## Phase 2 — Rule Extraction Summary

Extracted 8 permit rules + 1 default-deny from 2 role task files.

| rule_id | Action | Subject Condition | Resource Condition | Source File |
|---|---|---|---|---|
| rule-001 | ssh:login | groups any_of [sudo] | hostname=web01.lab.local, zone=dmz | roles/web/tasks/main.yml |
| rule-002 | sudo:execute | groups [sudo], clearance=secret | role=frontend | roles/web/tasks/main.yml |
| rule-003 | network:connect | source_network=0.0.0.0/0 | service=https, host_group=webservers | roles/web/tasks/main.yml |
| rule-004 | user:create | groups any_of [sudo] | hostname=web01.lab.local | roles/web/tasks/main.yml |
| rule-005 | db:login | groups any_of [sudo] | database=postgresql, host_group=dbservers | roles/db/tasks/main.yml |
| rule-006 | db:login | groups any_of [developers] | database=postgresql, host_group=dbservers | roles/db/tasks/main.yml |
| rule-007 | network:connect | source_network=10.0.1.0/24 | service=postgresql, port=5432, host_group=dbservers | roles/db/tasks/main.yml |
| rule-008 | filesystem:write | groups any_of [postgres] | path=/var/lib/postgresql/data, owner=postgres, mode=0700 | roles/db/tasks/main.yml |
| rule-009 | * | applies_to=all | applies_to=all | inventory.ini (implicit) |

### Obligations Attached to Rules

- **rule-002**: `require_password` enforced by `community.general.sudoers` with `nopassword=false`
- **rule-005**: `privilege_level=SUPERUSER` on postgresql user creation
- **rule-006**: `privilege_level=NOSUPERUSER` on postgresql user creation

### Ambiguities / Notes

1. **Credentials not captured**: `db_allow_from` and `firewall_allow_from` in group_vars define network source constraints that map to subject_condition source_network in rules-003 and rule-007, but the actual raw values (IP subnets) appear only in group_vars — not re-stated in role tasks. Rules reflect the intent from the template variables.
2. **PostgreSQL data dir owner**: The `ansible.builtin.file` task sets owner/group/mode on `/var/lib/postgresql/data`. This implies a `postgres` OS group exists, but it is not enumerated in the users list. The `groups: [postgres]` subject_condition in rule-008 is inferred from the `owner: postgres` resource attribute — not from an explicit subject definition in group_vars. This is an ambiguity flag.

---

## Phase 4 — Validation

- ✅ `attributes`: valid JSON, all attribute names appear in catalog, `source` and `domain` present on every entry
- ✅ `rules`: valid JSON, 9 rules, all operators restricted to `{equals, in, any_of, all_of}`, effect is lowercase permit/deny, all have `source` provenance dict
- ✅ `vulnerabilities`: empty list (zero applicable CVEs)
- ✅ `report`: Markdown string, not a dict literal

---

*Generated by ABAC policy mining tool — eval_fixtures/f7_negative_control*
