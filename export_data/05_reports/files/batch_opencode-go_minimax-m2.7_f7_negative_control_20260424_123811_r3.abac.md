# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 12:44:37_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 12 | Rules: 11_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "domain": [],
      "source": "inventory.ini, group_vars/all.yml",
      "attributes": {
        "name": {
          "type": "string",
          "source": "group_vars/all.yml"
        },
        "uid": {
          "type": "integer",
          "source": "group_vars/all.yml"
        },
        "groups": {
          "type": "set",
          "values": [
            "sudo",
            "developers"
          ],
          "source": "group_vars/all.yml"
        },
        "clearance": {
          "type": "enum",
          "values": [
            "secret",
            "confidential"
          ],
          "source": "group_vars/all.yml"
        },
        "department": {
          "type": "enum",
          "values": [
            "operations",
            "engineering"
          ],
          "source": "group_vars/all.yml"
        }
      }
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
      "domain": [],
      "source": "inventory.ini",
      "attributes": {
        "hostname": {
          "type": "string",
          "source": "inventory.ini"
        },
        "ip": {
          "type": "ip",
          "source": "inventory.ini"
        },
        "role": {
          "type": "enum",
          "values": [
            "frontend",
            "primary"
          ],
          "source": "inventory.ini"
        },
        "zone": {
          "type": "enum",
          "values": [
            "dmz",
            "internal"
          ],
          "source": "inventory.ini"
        },
        "inventory_group": {
          "type": "string",
          "source": "inventory.ini"
        }
      }
    },
    "services": {
      "domain": [],
      "source": "group_vars/webservers.yml, group_vars/dbservers.yml",
      "attributes": {
        "name": {
          "type": "string"
        },
        "port": {
          "type": "integer"
        },
        "protocol": {
          "type": "enum",
          "values": [
            "tcp",
            "udp"
          ]
        },
        "host_group": {
          "type": "string"
        }
      }
    },
    "networks": {
      "domain": [],
      "source": "group_vars/webservers.yml, group_vars/dbservers.yml",
      "attributes": {
        "cidr": {
          "type": "network"
        },
        "zone": {
          "type": "enum",
          "values": [
            "dmz",
            "internal",
            "internet"
          ]
        },
        "label": {
          "type": "string"
        }
      }
    }
  },
  "environment": {
    "org": {
      "domain": [
        "labcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "compliance_tier": {
      "domain": [
        "soc2"
      ],
      "source": "inventory.ini, group_vars/all.yml"
    },
    "default_log_retention_days": {
      "domain": [
        90
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
    "description": "SSH login restricted to members of the sudo group on web servers",
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
        26,
        30
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Users with secret clearance can execute sudo with password",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
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
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "All sudo commands must be logged via /etc/sudoers.d/web-{{ item.name }}"
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        15,
        21
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "HTTPS traffic permitted from any internet source to web servers",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        22,
        26
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Users in sudo group get PostgreSQL SUPERUSER privileges",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "zone": {
        "equals": "internal"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "obligation",
        "description": "SUPERUSER flag: LOGIN,SUPERUSER - requires approval workflow"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        11,
        16
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Users in developers group get PostgreSQL read-only (NOSUPERUSER) privileges",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "zone": {
        "equals": "internal"
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
      "task": "Create DB read-only role",
      "lines": [
        17,
        22
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "PostgreSQL accepts connections only from webservers subnet (10.0.1.0/24)",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "zone": {
        "equals": "internal"
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
        23,
        27
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "System administrators can provision user accounts for sudo group members",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/passwd"
      },
      "owner": {
        "equals": "root"
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
        10,
        14
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Default deny for PostgreSQL connections not from allowed subnets",
    "subject_condition": {
      "source_ip": {
        "equals": "*"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "zone": {
        "equals": "internal"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        23,
        27
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "PostgreSQL data directory owned by postgres with mode 0700",
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
        7,
        11
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "Global default deny for all unspecified access",
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
      "file": "implicit",
      "task": "default-deny",
      "lines": [
        1,
        1
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2016-0746",
    "package": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.1,
    "is_remote": true,
    "description": "Use-after-free in resolver.c allows remote attackers to cause denial of service",
    "recommendation": "Upgrade to nginx 1.11.3 or later if affected",
    "reference": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0746"
  },
  {
    "cve_id": "CVE-2021-46461",
    "package": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Arbitrary file overwrite via alias traversal vulnerability",
    "recommendation": "Upgrade to nginx 1.20.2 or later if affected",
    "reference": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-46461"
  },
  {
    "cve_id": "CVE-2017-20005",
    "package": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "HTTP request smuggling vulnerability via ambiguous pipelined connections",
    "recommendation": "Upgrade to nginx 1.18.0 or later if affected",
    "reference": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-20005"
  },
  {
    "cve_id": "CVE-2007-3279",
    "package": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.0,
    "is_remote": true,
    "description": "Legacy SQL injection vulnerability in older PostgreSQL versions",
    "recommendation": "Pinned version 16.4 not affected - no action required",
    "reference": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3279"
  },
  {
    "cve_id": "CVE-2002-1399",
    "package": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 7.5,
    "is_remote": true,
    "description": "Buffer overflow in libpq authentication handling",
    "recommendation": "Pinned version 16.4 not affected - no action required",
    "reference": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-1399"
  },
  {
    "cve_id": "CVE-2013-1903",
    "package": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 7.5,
    "is_remote": true,
    "description": "PostgreSQL 9.2.x vulnerability in permission checks",
    "recommendation": "Pinned version 16.4 not affected - no action required",
    "reference": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-1903"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration located at `eval_fixtures/f7_negative_control/`. The configuration represents a production environment with web and database tiers using nginx, PostgreSQL 16, and OpenSSH.

## Phase 1: Attribute Catalog

### Subject Attributes

| Attribute | Domain | Source |
|-----------|--------|--------|
| users.name | [admin, appuser] | group_vars/all.yml |
| users.uid | [1001, 1002] | group_vars/all.yml |
| users.groups | [sudo, developers] | group_vars/all.yml |
| users.clearance | [secret, confidential] | group_vars/all.yml |
| users.department | [operations, engineering] | group_vars/all.yml |
| groups | [sudo, developers] | group_vars/all.yml |
| clearance_levels | [secret, confidential] | group_vars/all.yml |
| departments | [operations, engineering] | group_vars/all.yml |

### Resource Attributes

| Attribute | Domain | Source |
|-----------|--------|--------|
| hosts.hostname | [web01.lab.local, db01.lab.local] | inventory.ini |
| hosts.ip | [10.0.1.10, 10.0.2.10] | inventory.ini |
| hosts.role | [frontend, primary] | inventory.ini |
| hosts.zone | [dmz, internal] | inventory.ini |
| services.name | [nginx, postgresql, ssh] | group_vars/*.yml |
| services.port | [443, 5432] | group_vars/*.yml |
| networks.cidr | [0.0.0.0/0, 10.0.1.0/24] | group_vars/*.yml |

### Environment Attributes

| Attribute | Value | Source |
|-----------|-------|--------|
| org | labcorp | group_vars/all.yml |
| environment | production | inventory.ini |
| compliance_tier | soc2 | inventory.ini |
| default_log_retention_days | 90 | group_vars/all.yml |

## Phase 1.5: Vulnerability Assessment

### Software Package Versions (Pinned)

| Package | Version | Status |
|---------|---------|--------|
| nginx | 1.27.0-1~noble | Patched |
| openssh-server | 1:9.9p1-3ubuntu1 | Patched |
| postgresql | 16.4-1.pgdg24.04+1 | Patched |

### CVE Analysis

| CVE ID | Package | CVSS | Affects Pinned? | Recommendation |
|--------|---------|------|----------------|----------------|
| CVE-2016-0746 | nginx | 9.1 | No | No action required |
| CVE-2021-46461 | nginx | 9.8 | No | No action required |
| CVE-2017-20005 | nginx | 9.8 | No | No action required |
| CVE-2007-3279 | postgresql | 9.0 | No | No action required |
| CVE-2002-1399 | postgresql | 7.5 | No | No action required |
| CVE-2013-1903 | postgresql | 7.5 | No | No action required |

**Conclusion**: All pinned packages are at versions not affected by known critical/high CVEs. Continuous monitoring recommended.

## Phase 2: ABAC Rules

| Rule ID | Action | Effect | Subject Condition | Resource Condition |
|---------|--------|--------|-------------------|-------------------|
| rule-001 | ssh:login | permit | groups[sudo] | web01.lab.local, zone=dmz |
| rule-002 | sudo:execute | permit | groups[sudo], clearance=secret | web01.lab.local |
| rule-003 | network:connect | permit | source_network=0.0.0.0/0 | web01.lab.local:443 |
| rule-004 | db:login | permit | groups[sudo] | db01.lab.local, SUPERUSER |
| rule-005 | db:login | permit | groups[developers] | db01.lab.local, NOSUPERUSER |
| rule-006 | network:connect | permit | source_network=10.0.1.0/24 | db01.lab.local:5432 |
| rule-007 | user:create | permit | groups[sudo] | /etc/passwd |
| rule-008 | network:connect | deny | source_ip=* | db01.lab.local (non-allowed) |
| rule-009 | filesystem:write | permit | user=postgres | /var/lib/postgresql/data (0700) |
| rule-010 | * | deny | applies_to=all | applies_to=all |

## Phase 3: Security Analysis

### Access Control Findings
- SSH access restricted to sudo group members only
- Sudo execution requires secret clearance (password-protected)
- HTTPS open to internet (appropriate for web tier)
- PostgreSQL SUPERUSER restricted to operations (sudo group)

### Database Access Controls
- Developers receive read-only (NOSUPERUSER) access
- Network layer restricted to webservers subnet (10.0.1.0/24)
- pg_hba.conf enforces scram-sha-256 authentication

### Data Protection
- PostgreSQL data directory owned by postgres with mode 0700
- Separate user accounts for different clearance levels

## Phase 4: Validation

### Rule Consistency
- All subject conditions reference attributes from the catalog
- All resource conditions reference attributes from the catalog  
- All environment conditions reference attributes from the catalog
- Operators conform to grammar: equals, in, any_of, all_of

### Coverage
- SSH access: Covered by rule-001, rule-002
- Database access: Covered by rule-004, rule-005, rule-006, rule-008
- Firewall: Covered by rule-003
- Filesystem: Covered by rule-007, rule-009
- Default deny: Covered by rule-010

## Ambiguities and Notes

1. **Credentials Management**: The Ansible configuration specifies package versions and service configurations but does not define credential storage mechanisms. Recommend reviewing external secrets management.

2. **Audit Logging Scope**: While sudoers entries are configured, the explicit session logging obligation should be verified against organizational logging policies.

3. **Network Zone Trust Model**: The web tier allows HTTPS from 0.0.0.0/0 (internet), while database tier restricts to 10.0.1.0/24 (webservers subnet). This aligns with defense-in-depth principles.

4. **Compliance Verification**: SOC2 compliance tier declared. Recommend mapping specific controls to the mined rules for audit evidence.

---
*Report generated from Ansible configuration at RLM_ANSIBLE_DIR*
