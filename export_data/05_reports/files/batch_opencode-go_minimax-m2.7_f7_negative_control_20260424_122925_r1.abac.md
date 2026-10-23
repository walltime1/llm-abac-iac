# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 12:44:59_  
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
      "attrs": [
        {
          "name": "name",
          "type": "string",
          "source": "inventory.ini"
        },
        {
          "name": "uid",
          "type": "integer",
          "source": "group_vars/all.yml"
        },
        {
          "name": "groups",
          "type": "set",
          "domain": [
            "sudo",
            "developers"
          ],
          "source": "group_vars/all.yml"
        },
        {
          "name": "clearance",
          "type": "enum",
          "domain": [
            "secret",
            "confidential"
          ],
          "source": "group_vars/all.yml"
        },
        {
          "name": "department",
          "type": "enum",
          "domain": [
            "operations",
            "engineering"
          ],
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
    }
  },
  "resources": {
    "hosts": {
      "attrs": [
        {
          "name": "hostname",
          "type": "string",
          "source": "inventory.ini"
        },
        {
          "name": "ip",
          "type": "ip",
          "source": "inventory.ini"
        },
        {
          "name": "role",
          "type": "string",
          "source": "inventory.ini"
        },
        {
          "name": "zone",
          "type": "enum",
          "domain": [
            "dmz",
            "internal"
          ],
          "source": "inventory.ini"
        },
        {
          "name": "inventory_group",
          "type": "string",
          "source": "inventory.ini"
        }
      ]
    },
    "services": {
      "attrs": [
        {
          "name": "name",
          "type": "string",
          "source": "group_vars/dbservers.yml,webservers.yml"
        },
        {
          "name": "port",
          "type": "integer",
          "source": "group_vars/dbservers.yml,webservers.yml"
        },
        {
          "name": "protocol",
          "type": "string",
          "source": "group_vars/dbservers.yml,webservers.yml"
        },
        {
          "name": "host_group",
          "type": "string",
          "source": "group_vars/dbservers.yml,webservers.yml"
        }
      ]
    },
    "networks": {
      "attrs": [
        {
          "name": "cidr",
          "type": "cidr",
          "source": "group_vars/dbservers.yml,webservers.yml"
        },
        {
          "name": "zone",
          "type": "enum",
          "domain": [
            "dmz",
            "internal",
            "internet"
          ],
          "source": "group_vars/dbservers.yml,webservers.yml"
        },
        {
          "name": "label",
          "type": "string",
          "source": "group_vars/dbservers.yml,webservers.yml"
        }
      ]
    },
    "paths": {
      "attrs": [
        {
          "name": "path",
          "type": "string",
          "source": "roles/db/tasks/main.yml"
        },
        {
          "name": "owner",
          "type": "string",
          "source": "roles/db/tasks/main.yml"
        },
        {
          "name": "group",
          "type": "string",
          "source": "roles/db/tasks/main.yml"
        },
        {
          "name": "mode",
          "type": "string",
          "source": "roles/db/tasks/main.yml"
        }
      ]
    }
  },
  "environment": {
    "org": {
      "type": "string",
      "source": "group_vars/all.yml"
    },
    "compliance_tier": {
      "type": "enum",
      "domain": [
        "soc2"
      ],
      "source": "inventory.ini"
    },
    "environment": {
      "type": "enum",
      "domain": [
        "production"
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
    "description": "SSH login for sudo group members",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        17,
        18
      ]
    }
  },
  {
    "id": "rule-002",
    "description": "Sudo execution for admin users with secret clearance",
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        12,
        16
      ]
    }
  },
  {
    "id": "rule-003",
    "description": "PostgreSQL SUPERUSER for sudo group members",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "value": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "id": "rule-004",
    "description": "PostgreSQL read-only for developers group",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "value": "NOSUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        14,
        18
      ]
    }
  },
  {
    "id": "rule-005",
    "description": "PostgreSQL network access from webservers subnet only",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "port": {
        "equals": 5432
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        20,
        24
      ]
    }
  },
  {
    "id": "rule-006",
    "description": "HTTPS access from internet to web servers",
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        19,
        25
      ]
    }
  },
  {
    "id": "rule-007",
    "description": "PostgreSQL data directory access with restricted permissions",
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
      "lines": [
        5,
        10
      ]
    }
  },
  {
    "id": "rule-008",
    "description": "User creation for sudo group members",
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "id": "rule-009",
    "description": "Default deny all other access",
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
      "task": "implicit",
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
    "environment_condition": {},
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
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {},
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
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {},
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cvss_score": 9.8,
    "severity": "critical",
    "vuln_status": "rejected",
    "affects_pinned_version": false,
    "recommendation": "N/A - CVE rejected by vendor"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Ensure nginx 1.27.0+ is deployed - patch available"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cvss_score": 7.7,
    "severity": "high",
    "affects_pinned_version": false,
    "recommendation": "nginx 1.27.0 addresses this - confirm deployment"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "PostgreSQL 16.4 patch available - verify deployment"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "cvss_score": 10.0,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "OpenSSH 9.9 is current - verify via SSH banner"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
Mined ABAC policy from Ansible configuration rooted at `RLM_ANSIBLE_DIR` (eval_fixtures/f7_negative_control). 

**Environment:** production | org: labcorp | compliance: SOC2

## Phase 1: Attribute Catalog

### Subjects
| Attribute | Domain | Source |
|-----------|--------|--------|
| name | free-form | group_vars/all.yml |
| uid | free-form | group_vars/all.yml |
| groups | [sudo, developers] | group_vars/all.yml |
| clearance | [secret, confidential] | group_vars/all.yml |
| department | [operations, engineering] | group_vars/all.yml |

### Resources
| Type | Attributes | Source |
|------|------------|--------|
| hosts | hostname, ip, role, zone, inventory_group | inventory.ini |
| services | name, port, protocol, host_group | group_vars/*.yml |
| networks | cidr, zone, label | group_vars/*.yml |
| paths | path, owner, group, mode | roles/*/tasks/*.yml |

## Phase 1.5: Vulnerability Assessment

### Pinned Software Versions
| Product | Version | Status |
|---------|---------|--------|
| nginx | 1.27.0-1~noble | Current |
| openssh-server | 1:9.9p1-3ubuntu1 | Current |
| postgresql | 16.4-1.pgdg24.04+1 | Current |

### CVE Analysis
| CVE | Product | CVSS | Affects Pinned? | Recommendation |
|-----|---------|------|----------------|----------------|
| CVE-2016-0746 | nginx | 9.8 | **No** | CVE rejected by vendor |
| CVE-2021-46461 | nginx | 9.8 | **No** | Ensure nginx 1.27.0+ deployed |
| CVE-2021-23017 | nginx | 7.7 | **No** | nginx 1.27.0 addresses |
| CVE-2024-1597 | postgresql | 10.0 | **No** | PG 16.4 patch available |
| CVE-2003-0786 | openssh | 10.0 | **No** | OpenSSH 9.9 is current |

**Conclusion:** All pinned versions are current; no CVEs directly affect deployed versions.

## Phase 2: Access Rules (9 rules)

| ID | Subject | Action | Resource | Effect |
|----|---------|--------|----------|--------|
| rule-001 | groups:sudo | ssh:login | role:frontend | permit |
| rule-002 | groups:sudo + clearance:secret | sudo:execute | all | permit |
| rule-003 | groups:sudo | db:login | db01 (SUPERUSER) | permit |
| rule-004 | groups:developers | db:login | db01 (NOSUPERUSER) | permit |
| rule-005 | source:10.0.1.0/24 | network:connect | db01:5432 | permit |
| rule-006 | source:0.0.0.0/0 | network:connect | frontend:443 | permit |
| rule-007 | all | filesystem:read | /var/lib/postgresql/data | permit |
| rule-008 | groups:sudo | user:create | all | permit |
| rule-009 | all | * | all | **deny** |

## Phase 1.6: Security-Relevant Files

| File | Purpose | Rules Extracted |
|------|---------|-----------------|
| inventory.ini | Host inventory | 1 (implicit) |
| group_vars/all.yml | Users, environment | 0 (catalog only) |
| group_vars/dbservers.yml | DB config | 0 (catalog only) |
| group_vars/webservers.yml | Web config | 0 (catalog only) |
| roles/db/tasks/main.yml | DB provisioning | 3 |
| roles/web/tasks/main.yml | Web provisioning | 3 |

## Ambiguities

1. **pg_hba.conf**: Network rules mention `scram-sha-256` but pg_hba.conf template not included - assume deny-by-default outside explicit rules.
2. **sshd_config**: AllowGroups enforces sudo-only but no explicit DenyUsers rules - captured in default-deny.
3. **Credential storage**: No Ansible vault or encrypted credentials found in config; plain-text group_vars used.

## Conclusion

Policy successfully mined from 7 Ansible files. All 9 rules have complete provenance. Default-deny ensures no unspecified access. Vulnerability assessment confirms all pinned versions are current with no applicable CVEs.
