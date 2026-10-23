# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:29:06_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 10 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

## Attributes

```json
{
  "subject_attributes": {
    "user": {
      "type": "string",
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
      "source": "inventory.ini, group_vars/dbservers.yml, group_vars/webservers.yml"
    },
    "source_network": {
      "type": "cidr",
      "source": "group_vars/dbservers.yml, group_vars/webservers.yml"
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    }
  },
  "resource_attributes": {
    "hostname": {
      "type": "string",
      "domain": [
        "web01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "domain": [
        "10.0.1.10",
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
        "webservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "openssh-server",
        "postgresql"
      ],
      "source": "roles/web/tasks/main.yml, roles/db/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "domain": [
        443,
        22,
        5432
      ],
      "source": "group_vars/webservers.yml, group_vars/dbservers.yml"
    },
    "path": {
      "type": "string",
      "domain": [
        "/var/lib/postgresql/data",
        "/etc/postgresql/pg_hba.conf",
        "/etc/ssh/sshd_config"
      ],
      "source": "roles/db/tasks/main.yml, roles/web/tasks/main.yml"
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
    },
    "database": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp"
      ],
      "source": "roles/web/tasks/main.yml, roles/db/tasks/main.yml"
    }
  },
  "environment_attributes": {
    "org": {
      "type": "enum",
      "domain": [
        "labcorp"
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
      "source": "inventory.ini, group_vars/all.yml"
    },
    "log_retention_days": {
      "type": "integer",
      "domain": [
        90
      ],
      "source": "group_vars/all.yml"
    }
  },
  "enumerated_values": {
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
    ],
    "host_groups": [
      "webservers",
      "dbservers",
      "prod"
    ],
    "zones": [
      "dmz",
      "internal"
    ],
    "roles": [
      "frontend",
      "primary"
    ],
    "services": [
      "nginx",
      "openssh-server",
      "postgresql"
    ]
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
        "equals": "openssh-server"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        39,
        43
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        22,
        29
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "obligations": [
      {
        "type": "authentication",
        "requirement": "password_required",
        "description": "nopassword is false; password authentication required"
      }
    ]
  },
  {
    "id": "rule-003",
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
        13,
        20
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "obligations": [
      {
        "type": "provisioning",
        "shell": "/bin/bash"
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
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        31,
        37
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database": {
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
        21
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "obligations": [
      {
        "type": "privilege_level",
        "level": "SUPERUSER"
      }
    ]
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        23,
        28
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "obligations": [
      {
        "type": "privilege_level",
        "level": "NOSUPERUSER"
      }
    ]
  },
  {
    "id": "rule-007",
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        30,
        34
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
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
        8,
        14
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
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
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        14
      ]
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
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
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "default",
      "task": "implicit default-deny",
      "lines": [
        0,
        0
      ]
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
    "id": "rule-016",
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
    "cve_id": "CVE-2024-1597",
    "product": "postgresql_jdbc_driver",
    "pinned_version": "16.4",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "PostgreSQL JDBC Driver deserialization vulnerability",
    "recommendation": "Not applicable: CVE targets JDBC Driver library, not PostgreSQL server. Pinned server version 16.4 is unaffected."
  }
]
```

## Report

# ABAC Policy Report — Ansible Configuration Mining

## Executive Summary
Mined an Attribute-Based Access Control (ABAC) policy from an Ansible configuration for **labcorp**'s production environment (SOC2 compliance tier). The configuration defines 2 users, 2 hosts, and 10 explicit permit rules plus 1 default-deny rule covering SSH, sudo, database access, firewall, filesystem, and user provisioning.

## Environment
| Attribute | Value | Source |
|-----------|-------|--------|
| Organization | labcorp | group_vars/all.yml |
| Environment | production | inventory.ini |
| Compliance Tier | SOC2 | inventory.ini, group_vars/all.yml |
| Log Retention | 90 days | group_vars/all.yml |

## Subjects
| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

## Resources
| Host | IP | Role | Zone | Group |
|------|----|------|------|-------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Pinned Software Versions
- nginx: 1.27.0-1~noble
- openssh-server: 1:9.9p1-3ubuntu1
- postgresql: 16.4-1.pgdg24.04+1

## Rules Summary
| Rule | Action | Subject | Resource | Effect |
|------|--------|---------|----------|--------|
| rule-001 | ssh:login | groups in [sudo] | openssh-server:22 | permit |
| rule-002 | sudo:execute | groups in [sudo] AND clearance=secret | all | permit |
| rule-003 | user:create | groups in [sudo] | all | permit |
| rule-004 | network:connect | source=0.0.0.0/0 | nginx:443/tcp | permit |
| rule-005 | db:login | groups in [sudo] | postgresql:all (SUPERUSER) | permit |
| rule-006 | db:login | groups in [developers] | postgresql:all (NOSUPERUSER) | permit |
| rule-007 | network:connect | source=10.0.1.0/24 | postgresql:5432 | permit |
| rule-008 | filesystem:read | groups in [sudo] | /var/lib/postgresql/data (0700) | permit |
| rule-009 | filesystem:write | groups in [sudo] | /var/lib/postgresql/data (0700) | permit |
| rule-010 | filesystem:execute | groups in [sudo] | /var/lib/postgresql/data (0700) | permit |
| rule-011 | * | all | all | deny |

## Vulnerability Assessment
One CVE of note was identified: **CVE-2024-1597** (CVSS 10.0, critical) affecting the PostgreSQL JDBC Driver (not the PostgreSQL server). The pinned PostgreSQL server version 16.4 is **not affected**. All other CVEs returned by vulnerability scanners target versions significantly older than the pinned versions and are not applicable.

## Ambiguities & Observations
1. **No explicit HTTPS redirect or TLS configuration** was found in the Ansible tasks. Only a firewall rule opening port 443 was present.
2. **No explicit SSH port configuration** — rule-001 assumes default port 22 based on standard sshd_config behavior.
3. **pg_hba.conf entries** use `scram-sha-256` authentication but no explicit DENY rules are configured; the default PostgreSQL behavior (deny if no match) is relied upon.
4. **No credentials/hardcoded secrets** were detected in the Ansible configuration files.
5. **Session logging/audit**: The default_log_retention_days is set to 90 days, but no explicit audit logging tasks were found in the role definitions.
6. **Firewall rule-004** permits HTTPS from any source (0.0.0.0/0) — this is intentional for an internet-facing web server but should be monitored.
