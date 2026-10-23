# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:25:12_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 12_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

## Attributes

```json
{
  "subject": {
    "user": {
      "type": "string",
      "domain": [
        "admin",
        "appuser",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "enum",
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "type": "string",
      "domain": [
        "0.0.0.0/0",
        "10.0.1.0/24"
      ],
      "source": "group_vars/*.yml"
    }
  },
  "resource": {
    "hostname": {
      "type": "string",
      "domain": [
        "web-new01.lab.local",
        "web-old01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "set",
      "domain": [
        "webservers_patched",
        "webservers_legacy",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "type": "enum",
      "domain": [
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "domain": [
        "10.0.1.10",
        "10.0.1.20",
        "10.0.2.10"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "openssh",
        "postgresql"
      ],
      "source": "group_vars/*.yml"
    },
    "port": {
      "type": "integer",
      "domain": [
        22,
        443,
        5432
      ],
      "source": "group_vars/*.yml"
    },
    "path": {
      "type": "string",
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "string",
      "domain": [
        "patchcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "enum",
      "domain": [
        "soc2"
      ],
      "source": "inventory.ini"
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
        "equals": "openssh"
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        21,
        25
      ]
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
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        13,
        19
      ]
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
      "lines": [
        8,
        14
      ]
    }
  },
  {
    "id": "rule-004",
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
      "lines": [
        8,
        14
      ]
    }
  },
  {
    "id": "rule-005",
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
      "lines": [
        8,
        14
      ]
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
      "task": "Allow postgres only from web subnet",
      "lines": [
        16,
        20
      ]
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
      "lines": [
        1,
        1
      ]
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
    "id": "rule-009",
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
    "id": "rule-011",
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
    "id": "rule-012",
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
[]
```

## Report

# ABAC Policy Mining Report

## Policy Goal
Mine a full ABAC policy slice from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`.

## Attribute Catalog Summary
- **Subjects**: `user` (admin, appuser, postgres), `groups` (sudo, developers, postgres), `clearance` (secret, confidential), `department` (operations, engineering).
- **Resources**: `hostname` (web-new01, web-old01, db01), `host_group` (webservers_patched, webservers_legacy, dbservers), `zone` (dmz, internal), `service` (nginx, openssh, postgresql), `path` (/var/lib/postgresql/data), `port` (22, 443, 5432), `mode` (0700).
- **Environment**: `org` (patchcorp), `environment` (production), `compliance_tier` (soc2).

## Extracted Rules (7 total)
1. **rule-001** (`permit`): `groups: sudo` → `ssh:login` on port 22.
2. **rule-002** (`permit`): `source_network: 0.0.0.0/0` → `network:connect` to nginx:443.
3. **rule-003** (`permit`): `user: postgres` → `filesystem:read` on `/var/lib/postgresql/data` (mode 0700).
4. **rule-004** (`permit`): `user: postgres` → `filesystem:write` on `/var/lib/postgresql/data`.
5. **rule-005** (`permit`): `user: postgres` → `filesystem:execute` on `/var/lib/postgresql/data`.
6. **rule-006** (`permit`): `source_network: 10.0.1.0/24` → `network:connect` to postgresql:5432.
7. **rule-007** (`deny`): Default-deny catch-all for all subjects and resources.

## Vulnerability Assessment
- **Pinned Packages**: nginx (1.20.0 legacy / 1.24.0 patched), postgresql (16.2), openssh-server (9.6p1).
- **Search Results**: 10 unique CVEs retrieved via `search_critical_remote` and `search_kev_vulnerabilities`.
- **Impact Analysis**: Heuristic matching against pinned versions yielded 0 direct matches. All returned CVEs appear to target other major versions or unrelated products. Manual verification against vendor security advisories is recommended.

## Ambiguities & Notes
- `appuser` is defined in `group_vars/all.yml` but no explicit access-control or filesystem rules in the current roles grant this user privileges.
- `roles/web_legacy` and `roles/web_patched` contain identical firewall and SSH task definitions in this snapshot.
- No explicit session logging, auditd configurations, or profile.d scripts were found; thus, no `obligations` were attached to the extracted rules.
