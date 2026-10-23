# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 14:07:52_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 13 | Rules: 11_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

## Attributes

```json
{
  "subject": {
    "user": {
      "type": "enum",
      "domain": [
        "admin",
        "appuser"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "domain": [
        1001,
        1002
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers"
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
    "source_ip": {
      "type": "cidr",
      "source": "group_vars/dbservers.yml"
    },
    "source_network": {
      "type": "cidr",
      "source": "group_vars/dbservers.yml"
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal",
        "internet"
      ],
      "source": "inventory.ini"
    }
  },
  "resource": {
    "hostname": {
      "type": "enum",
      "domain": [
        "web-new01.lab.local",
        "web-old01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "ip",
      "domain": [
        "10.0.1.10",
        "10.0.1.20",
        "10.0.2.10"
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
    "zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "webservers_patched",
        "webservers_legacy",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "postgresql",
        "openssh-server"
      ],
      "source": "group_vars/all.yml"
    },
    "port": {
      "type": "integer",
      "domain": [
        22,
        443,
        5432
      ],
      "source": "group_vars/dbservers.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp"
      ],
      "source": "roles/web_legacy/tasks/main.yml"
    },
    "database": {
      "type": "enum",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "path": {
      "type": "enum",
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "owner": {
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "enum",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "enum",
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
    },
    "default_log_retention_days": {
      "type": "integer",
      "domain": [
        90
      ],
      "source": "group_vars/all.yml"
    }
  },
  "networks": [
    {
      "cidr": "10.0.1.0/24",
      "zone": "dmz",
      "label": "web_subnet"
    },
    {
      "cidr": "0.0.0.0/0",
      "zone": "internet",
      "label": "internet"
    }
  ]
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
      "host_group": {
        "in": [
          "webservers_patched",
          "webservers_legacy"
        ]
      },
      "service": {
        "equals": "openssh-server"
      },
      "port": {
        "equals": 22
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        20,
        23
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
      "host_group": {
        "equals": "webservers_patched"
      },
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall allow HTTPS from internet",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers_legacy"
      },
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall allow HTTPS from internet",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
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
      "database": {
        "equals": "all"
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
      "task": "Allow postgres only from web subnet",
      "lines": [
        14,
        16
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_zone": {
        "equals": "internet"
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
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet (implicit deny)",
      "lines": [
        14,
        16
      ]
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:read",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        13
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:write",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        13
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
    "action": "filesystem:execute",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        13
      ]
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
      "task": "implicit default-deny",
      "lines": [
        1,
        1
      ]
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
      "host_group": {
        "equals": "webservers_patched"
      },
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
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
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
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
      "host_group": {
        "equals": "webservers_legacy"
      },
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
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
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "epss_score": 0.14,
    "description": "nginx DNS response length validation flaw allowing out-of-bounds read",
    "pinned_versions": "1.24.0-2ubuntu1 (patched), 1.20.0-1~focal (legacy)",
    "affects_pinned_version": true,
    "recommendation": "Upgrade legacy nginx 1.20.0 to 1.24.0+ on webservers_legacy hosts"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "epss_score": 0.0,
    "description": "NGINX Unit before 1.26.1 reachable assertion failure causing remote DoS",
    "pinned_versions": "1.24.0-2ubuntu1 (patched), 1.20.0-1~focal (legacy)",
    "affects_pinned_version": true,
    "recommendation": "Critical: upgrade legacy nginx 1.20.0 to 1.24.0+; verify patch on patched hosts"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "epss_score": 0.0,
    "description": "NGINX before 1.13.3 heap-based buffer over-read in ngx_http_parse_chunked",
    "pinned_versions": "1.24.0-2ubuntu1 (patched), 1.20.0-1~focal (legacy)",
    "affects_pinned_version": true,
    "recommendation": "Both versions exceed 1.13.3 so likely patched; upgrade legacy regardless"
  }
]
```

## Report

# ABAC Policy Report — Patchcorp Ansible Configuration

## Summary

Mined an ABAC policy from the Patchcorp Ansible configuration managing 3 host groups (webservers_patched, webservers_legacy, dbservers) in a SOC2 production environment.

- **9 rules** (7 specific + 1 network deny + 1 default-deny)
- **25 attributes** across subject (8), resource (13), environment (4)
- **3 CVEs** affecting nginx legacy deployment

## Access Control Rules

| ID | Effect | Action | Subject | Resource | Source |
|---|---|---|---|---|---|
| rule-001 | permit | ssh:login | groups \u222b sudo | web servers, SSH 22 | web_patched |
| rule-002 | permit | network:connect | src 0.0.0.0/0 | patched web, HTTPS 443 | web_patched |
| rule-003 | permit | network:connect | src 0.0.0.0/0 | legacy web, HTTPS 443 | web_legacy |
| rule-004 | permit | db:login | src 10.0.1.0/24 | dbservers, PostgreSQL 5432 | db |
| rule-005 | deny | db:login | src_zone=internet | dbservers, PostgreSQL 5432 | db |
| rule-006-008 | deny | filesystem:r/w/x | all | /var/lib/postgresql/data (0700) | db |
| rule-009 | deny | * | all | all | default |

## Vulnerability Assessment

3 critical/high CVEs found for nginx. The legacy nginx 1.20.0 on webservers_legacy is especially exposed since it accepts HTTPS from 0.0.0.0/0. No critical remote CVEs found for PostgreSQL 16.2 or OpenSSH 9.6p1.

## Ambiguities

1. **Firewall 0.0.0.0/0** to HTTPS on both web groups is broad, especially given legacy nginx vulnerabilities.
2. **SSH restricted to sudo group only** — appuser (developers) cannot SSH to web servers; no alternative access mechanism defined.
3. **postgres OS user** not in Ansible-managed users list — filesystem deny rules (006-008) apply to managed users but postgres system user bypasses them.
4. **No explicit SSH deny** for non-sudo groups — covered by default-deny but explicit denial would improve audit clarity.
5. **No session logging/audit obligations** defined, which may be relevant for SOC2 compliance.