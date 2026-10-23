# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 11:40:40_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 8 | Rules: 8_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

## Attributes

```json
{
  "subjects": {
    "users": {
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
    "department": {
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": {
      "attrs": [
        "hostname",
        "ip",
        "role",
        "zone",
        "inventory_group"
      ],
      "source": "inventory.ini"
    },
    "services": {
      "attrs": [
        "name",
        "port",
        "protocol",
        "host_group"
      ],
      "source": "group_vars/*.yml"
    },
    "paths": {
      "attrs": [
        "path",
        "owner",
        "group",
        "mode"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "networks": {
      "attrs": [
        "cidr",
        "zone"
      ],
      "source": "group_vars/dbservers.yml"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "patchcorp"
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
      "source": "inventory.ini, group_vars/all.yml"
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "Allow SSH login only for users in sudo group on web servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
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
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "12-15"
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Deny SSH login for developers group on web servers",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
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
    "effect": "deny",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "12-15"
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Allow PostgreSQL database login from web subnet",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": "11-15"
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow HTTPS access from internet to web servers",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "port": {
        "equals": 443
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "8-14"
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow postgres user full access to PostgreSQL data directory",
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
      "lines": "4-10"
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Default deny all access not explicitly permitted",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "inventory.ini",
      "task": "default-deny",
      "lines": "1-21"
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
      "port": {
        "equals": 443
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
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to patched version"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to nginx 1.24.0 or later"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": true,
    "recommendation": "Upgrade to nginx 1.24.0 or later"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": true,
    "recommendation": "Upgrade njs module to latest version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Version not affected"
  }
]
```

## Report

# ABAC Policy Mining Report

## Environment
- **Organization**: patchcorp
- **Environment**: production
- **Compliance Tier**: soc2

## Phase 1: Attribute Catalog

### Subjects
| Attribute | Domain | Source |
|-----------|--------|--------|
| users | [admin, appuser] | group_vars/all.yml |
| groups | [sudo, developers] | group_vars/all.yml |
| clearance | [secret, confidential] | group_vars/all.yml |

### Resources
| Type | Attributes | Source |
|------|------------|--------|
| hosts | hostname, ip, role, zone | inventory.ini |
| services | name, port, host_group | group_vars/*.yml |
| paths | path, owner, group, mode | roles/db/tasks/main.yml |

## Phase 1.5: Vulnerability Assessment

### Packages Tracked
| Package | Version | Status |
|---------|---------|--------|
| openssh-server | 1:9.6p1-3ubuntu1 | Current |
| postgresql | 16.2-1.pgdg22.04+1 | Current |
| nginx (patched) | 1.24.0-2ubuntu1 | Patched |
| nginx (legacy) | 1.20.0-1~focal | VULNERABLE |

### Critical Findings
- **CVE-2017-20005** (nginx 1.20.0): Buffer overflow - URGENT
- **CVE-2024-1597** (postgresql): SQL injection

## Phase 2: Extracted Rules (6 total)

| Rule ID | Action | Subject | Resource | Effect |
|---------|--------|---------|----------|--------|
| rule-001 | ssh:login | groups:[sudo] | role:frontend | permit |
| rule-002 | ssh:login | groups:[developers] | role:frontend | deny |
| rule-003 | db:login | source:10.0.1.0/24 | service:postgresql | permit |
| rule-004 | network:connect | source:0.0.0.0/0 | port:443 | permit |
| rule-005 | filesystem:write | user:postgres | path:/var/lib/postgresql/data | permit |
| rule-006 | * | applies_to:all | applies_to:all | deny |

## Ambiguities & Notes
1. Firewall allows 0.0.0.0/0 for HTTPS - deliberate design for public web servers
2. PostgreSQL auth uses scram-sha-256 method
3. Legacy nginx servers require upgrade to 1.24.0
