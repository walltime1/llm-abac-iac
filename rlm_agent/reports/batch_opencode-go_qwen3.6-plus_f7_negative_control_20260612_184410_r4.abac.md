# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:49:53_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 12_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

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
    ],
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance_levels": [
      "secret",
      "confidential"
    ],
    "departments": [
      "operations",
      "engineering"
    ]
  },
  "resources": {
    "hosts": [
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
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
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
      },
      {
        "name": "sshd",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
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
      },
      {
        "path": "/var/www/html",
        "owner": null,
        "group": null,
        "mode": null,
        "service": "nginx",
        "source": "group_vars/webservers.yml"
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": null,
        "group": null,
        "mode": null,
        "service": "sshd",
        "source": "roles/web/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "dmz",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
      }
    ]
  },
  "environment": {
    "org": "labcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "sources": {
      "org": "group_vars/all.yml",
      "environment": "inventory.ini",
      "compliance_tier": "inventory.ini",
      "retention": "group_vars/all.yml"
    }
  },
  "attribute_schema": {
    "clearance": {
      "domain": [
        "secret",
        "confidential"
      ],
      "type": "enum",
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "operations",
        "engineering"
      ],
      "type": "enum",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "domain": [
        "sudo",
        "developers"
      ],
      "type": "set",
      "source": "group_vars/all.yml"
    },
    "zone": {
      "domain": [
        "dmz",
        "internal"
      ],
      "type": "enum",
      "source": "inventory.ini"
    },
    "role": {
      "domain": [
        "frontend",
        "primary"
      ],
      "type": "enum",
      "source": "inventory.ini"
    },
    "inventory_group": {
      "domain": [
        "webservers",
        "dbservers"
      ],
      "type": "enum",
      "source": "inventory.ini"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "type": "enum",
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "domain": [
        "soc2"
      ],
      "type": "enum",
      "source": "inventory.ini"
    },
    "source_network": {
      "domain": [
        "0.0.0.0/0",
        "10.0.1.0/24"
      ],
      "type": "cidr",
      "source": "group_vars/dbservers.yml"
    },
    "service": {
      "domain": [
        "nginx",
        "postgresql",
        "sshd"
      ],
      "type": "enum",
      "source": "group_vars/webservers.yml"
    },
    "port": {
      "domain": [
        22,
        443,
        5432
      ],
      "type": "integer",
      "source": "group_vars/webservers.yml"
    },
    "path": {
      "domain": [],
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "domain": [
        "postgres"
      ],
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "domain": [
        "postgres"
      ],
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "domain": [
        "0700"
      ],
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    }
  },
  "pinned_versions": {
    "nginx": "1.27.0-1~noble",
    "openssh-server": "1:9.9p1-3ubuntu1",
    "postgresql": "16.4-1.pgdg24.04+1",
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
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        19,
        27
      ]
    },
    "obligations": []
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sshd"
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
      "lines": [
        46,
        50
      ]
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
      "applies_to": {
        "equals": "all"
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
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        29,
        36
      ]
    },
    "obligations": [
      {
        "type": "password_required",
        "detail": "nopassword is false; password prompt enforced"
      }
    ]
  },
  {
    "id": "rule-004",
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
      "zone": {
        "equals": "dmz"
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
      "lines": [
        38,
        44
      ]
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
        9,
        14
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
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
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        16,
        20
      ]
    },
    "obligations": [
      {
        "type": "privilege_level",
        "detail": "SUPERUSER"
      }
    ]
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "developers"
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
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        22,
        26
      ]
    },
    "obligations": [
      {
        "type": "privilege_level",
        "detail": "NOSUPERUSER"
      }
    ]
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
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        28,
        32
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
      "file": "policy-default",
      "task": "default-deny",
      "lines": [
        0,
        0
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
[
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ",
    "recommendation": "Apply vendor patches for nginx; current pinned version 1.27.0 may be vulnerable"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "recommendation": "Apply vendor patches for nginx; current pinned version 1.27.0 may be vulnerable"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "affects_pinned_version": true,
    "severity": "high",
    "cvss_score": 7.7,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "recommendation": "Apply vendor patches for nginx; current pinned version 1.27.0 may be vulnerable"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "affects_pinned_version": true,
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many streams quickly, letting attackers consume server resources, exploit has been observed in the wild f",
    "recommendation": "CRITICAL: Actively exploited (KEV). Upgrade nginx immediately beyond 1.27.0"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.4",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "recommendation": "Apply vendor patches for postgresql; current pinned version 16.4 may be vulnerable"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.4",
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "recommendation": "CRITICAL: Actively exploited (KEV). Upgrade postgresql immediately beyond 16.4"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.4",
    "affects_pinned_version": true,
    "severity": "high",
    "cvss_score": 7.1,
    "is_kev": true,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the a",
    "recommendation": "CRITICAL: Actively exploited (KEV). Upgrade postgresql immediately beyond 16.4"
  }
]
```

## Report

# ABAC Policy Report — labcorp Ansible Configuration

## Executive Summary
Mined ABAC policy from Ansible configuration at `RLM_ANSIBLE_DIR`. Coverage: **all** slices (ssh, sudo, db-access, firewall, filesystem). Found **9 rules** (8 permit, 1 default-deny) and **7 relevant vulnerabilities** across nginx and postgresql.

## Attribute Catalog

### Subjects
| Attribute | Domain | Source |
|-----------|--------|--------|
| `groups` | sudo, developers | group_vars/all.yml |
| `clearance` | secret, confidential | group_vars/all.yml |
| `department` | operations, engineering | group_vars/all.yml |

**Users:** admin (uid=1001, sudo, secret, operations), appuser (uid=1002, developers, confidential, engineering)

### Resources
| Attribute | Domain | Source |
|-----------|--------|--------|
| `service` | nginx, postgresql, sshd | group_vars + roles |
| `port` | 22, 443, 5432 | group_vars |
| `zone` | dmz, internal | inventory.ini |
| `path` | /var/lib/postgresql/data, /var/www/html | roles/db + group_vars |
| `owner` | postgres | roles/db/tasks/main.yml |
| `mode` | 0700 | roles/db/tasks/main.yml |
| `source_network` | 0.0.0.0/0, 10.0.1.0/24 | group_vars |

**Hosts:** web01.lab.local (10.0.1.10, frontend, dmz), db01.lab.local (10.0.2.10, primary, internal)

### Environment
| Attribute | Value | Source |
|-----------|-------|--------|
| `org` | labcorp | group_vars/all.yml |
| `environment` | production | inventory.ini |
| `compliance_tier` | soc2 | inventory.ini |
| `log_retention` | 90 days | group_vars/all.yml |

## Rules Extracted

| ID | Action | Subject Condition | Resource Condition | Effect | Source |
|----|--------|-------------------|-------------------|--------|--------|
| rule-001 | user:create | groups in [sudo] | all | permit | roles/web/tasks/main.yml |
| rule-002 | ssh:login | groups in [sudo] | service=sshd, port=22 | permit | roles/web/tasks/main.yml |
| rule-003 | sudo:execute | groups in [sudo], clearance=secret | all | permit | roles/web/tasks/main.yml |
| rule-004 | network:connect | source_network=0.0.0.0/0 | service=nginx, port=443, zone=dmz | permit | roles/web/tasks/main.yml |
| rule-005 | filesystem:execute | all | path=/var/lib/postgresql/data, owner=postgres, mode=0700 | permit | roles/db/tasks/main.yml |
| rule-006 | db:login | groups in [sudo] | service=postgresql, port=5432 | permit | roles/db/tasks/main.yml |
| rule-007 | db:login | groups in [developers] | service=postgresql, port=5432 | permit | roles/db/tasks/main.yml |
| rule-008 | network:connect | source_network=10.0.1.0/24 | service=postgresql, port=5432 | permit | roles/db/tasks/main.yml |
| rule-009 | * (all) | all | all | deny | policy-default |

## Vulnerability Assessment

| CVE | Product | Severity | CVSS | Affects Pinned | Recommendation |
|-----|---------|----------|------|----------------|----------------|
| CVE-2021-46461 | nginx | critical | 9.8 | true | Apply vendor patches |
| CVE-2017-20005 | nginx | critical | 9.8 | true | Apply vendor patches |
| CVE-2021-23017 | nginx | high | 7.7 | true | Apply vendor patches |
| CVE-2023-44487 | nginx | high | 7.5 | true | CRITICAL: Actively exploited (KEV) |
| CVE-2024-1597 | postgresql | critical | 10.0 | true | Apply vendor patches |
| CVE-2024-1597 | postgresql | critical | 10.0 | true | CRITICAL: Actively exploited (KEV) |
| CVE-2022-31197 | postgresql | high | 7.1 | true | CRITICAL: Actively exploited (KEV) |

## Ambiguities
- **Pinned version applicability:** The heuristic version check may over-estimate vulnerability coverage for very old CVEs (pre-2020) against recent versions (nginx 1.27.0, openssh 9.9p1, postgresql 16.4). Manual verification recommended.
- **Credential handling:** No explicit credential storage or secret management tasks found in the Ansible configuration. This is noted as a potential gap — verify that database passwords and SSH keys are managed via Ansible Vault or external secret store.
- **Filesystem paths:** `/var/www/html` and `/etc/ssh/sshd_config` appear in configuration but lack explicit owner/group/mode definitions in the tasks — only their existence is implied.

## Notes
- Openssh-server (9.9p1) has no applicable CVEs returned in the vulnerability search.
- Session logging / audit scripts: No explicit audit obligations found in the current configuration.
