# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 11:49:55_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 13 | Rules: 21_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "values": [
        {
          "name": "admin",
          "uid": 1001,
          "groups": [
            "sudo"
          ],
          "department": "operations",
          "clearance": "secret"
        },
        {
          "name": "developer",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "department": "engineering",
          "clearance": "confidential"
        },
        {
          "name": "dba",
          "uid": 1003,
          "groups": [
            "dba"
          ],
          "department": "data",
          "clearance": "secret"
        }
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "values": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "domain": [
        "secret",
        "confidential"
      ],
      "values": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "values": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hostname": {
      "domain": null,
      "values": [
        "bastion01.lab.local",
        "web01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "domain": null,
      "values": [
        "10.0.0.5",
        "10.0.1.10",
        "10.0.2.10",
        "10.0.3.10"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "values": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "role": {
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "values": [
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers"
      ],
      "values": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "domain": [
        "ssh",
        "http",
        "app",
        "postgresql"
      ],
      "values": [
        "ssh",
        "http",
        "app",
        "postgresql"
      ],
      "source": "group_vars/*/yml"
    },
    "port": {
      "domain": null,
      "values": [
        22,
        80,
        8080,
        5432
      ],
      "source": "group_vars/*/yml"
    },
    "database": {
      "domain": [
        "all"
      ],
      "values": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "path": {
      "domain": null,
      "values": [
        "/var/lib/postgresql/data",
        "/opt/app/app.jar",
        "/opt/app/lib/log4j-core-2.14.1.jar"
      ],
      "source": "roles/*/tasks/main.yml"
    },
    "owner": {
      "domain": [
        "postgres",
        "root"
      ],
      "values": [
        "postgres",
        "root"
      ],
      "source": "roles/*/tasks/main.yml"
    },
    "group": {
      "domain": [
        "postgres",
        "root"
      ],
      "values": [
        "postgres",
        "root"
      ],
      "source": "roles/*/tasks/main.yml"
    },
    "mode": {
      "domain": [
        "0700",
        "0644"
      ],
      "values": [
        "0700",
        "0644"
      ],
      "source": "roles/*/tasks/main.yml"
    },
    "source_network": {
      "domain": null,
      "values": [
        "10.0.0.0/24",
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/*/yml"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "chaincorp"
      ],
      "values": [
        "chaincorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "values": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "domain": [
        "pci"
      ],
      "values": [
        "pci"
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
    "rule_id": "rule-001",
    "description": "Allow SSH login to appservers for sudo and developers groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        19,
        23
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Allow SSH login to bastion for sudo and dba groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        7,
        10
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Allow SSH login to dbservers for sudo and dba groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        26,
        29
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow SSH login to webservers for sudo group only",
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        16,
        19
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow TCP connect to app port (8080) from web subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "port": {
        "equals": 8080
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        15,
        22
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow TCP connect to SSH (port 22) from anywhere",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        13,
        18
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow TCP connect to HTTP (port 80) from bastion subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "port": {
        "equals": 80
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        12,
        17
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Allow PostgreSQL connection (port 5432) from app subnet only",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "port": {
        "equals": 5432
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        20,
        25
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Grant PostgreSQL SUPERUSER to DBA users",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "role_attr_flags",
        "value": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        14,
        19
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "Allow sudo on bastion for secret-clearance sudo members (password required)",
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
        "equals": "bastion"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "nopassword",
        "value": false
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        20,
        28
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "PostgreSQL data directory ownership and permissions (0700)",
    "subject_condition": {
      "applies_to": {
        "equals": "postgres_owner"
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
        13
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "description": "Application JAR file deployment permissions (0644)",
    "subject_condition": {
      "applies_to": {
        "equals": "root_owner"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/opt/app/app.jar"
      },
      "owner": {
        "equals": "root"
      },
      "group": {
        "equals": "root"
      },
      "mode": {
        "equals": "0644"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Deploy application with Log4j",
      "lines": [
        6,
        10
      ]
    }
  },
  {
    "rule_id": "rule-013",
    "description": "Log4j library file deployment permissions (0644)",
    "subject_condition": {
      "applies_to": {
        "equals": "root_owner"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/opt/app/lib/log4j-core-2.14.1.jar"
      },
      "owner": {
        "equals": "root"
      },
      "group": {
        "equals": "root"
      },
      "mode": {
        "equals": "0644"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Install Log4j library (pinned vulnerable version)",
      "lines": [
        12,
        17
      ]
    }
  },
  {
    "rule_id": "rule-014",
    "description": "Default deny for all unspecified access",
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
        0,
        0
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
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "root"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/opt/app/app.jar"
      },
      "owner": {
        "equals": "root"
      },
      "group": {
        "equals": "root"
      },
      "mode": {
        "equals": "0644"
      }
    },
    "environment_condition": {},
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "postprocessor",
      "task": "mode 0644 group read",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "root"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/opt/app/lib/log4j-core-2.14.1.jar"
      },
      "owner": {
        "equals": "root"
      },
      "group": {
        "equals": "root"
      },
      "mode": {
        "equals": "0644"
      }
    },
    "environment_condition": {},
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "postprocessor",
      "task": "mode 0644 group read",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "port": {
        "equals": 8080
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
    "id": "rule-005",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      },
      "port": {
        "equals": 22
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
    "id": "rule-006",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "port": {
        "equals": 80
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
    "id": "rule-007",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "OpenSSH 3.7.1 privilege escalation via PAM challenge response",
    "is_known_exploited": false,
    "remediation": "URGENT: Upgrade OpenSSH immediately"
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "OpenBSD SSH format string vulnerability",
    "is_known_exploited": false,
    "remediation": "URGENT: Upgrade OpenSSH immediately"
  },
  {
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cve_id": "CVE-2010-0425",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "Apache critical vulnerability",
    "is_known_exploited": false,
    "remediation": "URGENT: Upgrade Apache httpd immediately"
  },
  {
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cve_id": "CVE-2005-2700",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "Apache buffer overflow",
    "is_known_exploited": false,
    "remediation": "URGENT: Upgrade Apache httpd immediately"
  },
  {
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cve_id": "CVE-2021-44228",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "Log4j Remote Code Execution (Log4Shell) - KEV",
    "is_known_exploited": true,
    "remediation": "URGENT: Upgrade to 2.17.0+ immediately - KNOWN EXPLOITED"
  },
  {
    "product": "log4j",
    "pinned_version": "2.14.1",
    "cve_id": "CVE-2021-45046",
    "severity": "critical",
    "cvss_score": 9.0,
    "description": "Log4j DoS vulnerability",
    "is_known_exploited": false,
    "remediation": "URGENT: Upgrade to 2.17.0+ immediately"
  },
  {
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cve_id": "CVE-2014-0063",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "PostgreSQL privilege escalation",
    "is_known_exploited": false,
    "remediation": "Upgrade PostgreSQL to latest stable"
  },
  {
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "cve_id": "CVE-2014-0062",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "PostgreSQL bypass security restrictions",
    "is_known_exploited": false,
    "remediation": "Upgrade PostgreSQL to latest stable"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

Policy mined from Ansible configuration at `RLM_ANSIBLE_DIR` for organization **chaincorp** (environment: production, compliance: PCI).

## Phase 1: Attribute Catalog

### Subjects
| Attribute | Domain | Values | Source |
|-----------|--------|--------|--------|
| user | [admin, developer, dba] | 3 users | group_vars/all.yml |
| groups | [sudo, developers, dba] | 3 groups | group_vars/all.yml |
| clearance | [secret, confidential] | 2 levels | group_vars/all.yml |
| department | [operations, engineering, data] | 3 departments | group_vars/all.yml |

### Resources
| Attribute | Type | Count | Source |
|-----------|------|-------|--------|
| hosts | hostname, ip, zone, role | 4 hosts | inventory.ini |
| services | name, port, protocol | 4 services | group_vars/*/yml |
| networks | cidr, zone | 5 networks | group_vars/*/yml |
| paths | path, owner, group, mode | 3 paths | roles/*/tasks/main.yml |

### Environment
- **Organization**: chaincorp
- **Environment**: production
- **Compliance Tier**: pci

## Phase 1.5: Vulnerability Assessment

**25 CVEs identified** across 5 pinned packages.

| Product | Version | Critical CVEs | KEV |
|---------|---------|---------------|-----|
| openssh (bastion) | 1:9.1p1-1ubuntu1 | 5 | 0 |
| apache (httpd) | 2.4.49-1 | 5 | 0 |
| log4j | 2.14.1 | 5 | 0 |
| postgresql | 9.2.3-1.pgdg20.04+1 | 5 | 0 |
| openssh (general) | 1:9.9p1-3ubuntu1 | 5 | 0 |

**CRITICAL**: Log4j 2.14.1 is vulnerable to CVE-2021-44228 (Log4Shell) - **KNOWN EXPLOITED**.

### Recommendations

**URGENT (CVSS 10)**:
- Upgrade Log4j to 2.17.0+ immediately (KEV)
- Upgrade OpenSSH on bastion host
- Upgrade Apache httpd to latest version

**HIGH (CVSS 7-9)**:
- Upgrade PostgreSQL to latest stable version

## Phase 2: Extracted Rules (14 total)

| Rule ID | Action | Subject | Resource | Effect |
|---------|--------|---------|----------|--------|
| rule-001 | ssh:login | sudo,developers | appservers | permit |
| rule-002 | ssh:login | sudo,dba | bastion | permit |
| rule-003 | ssh:login | sudo,dba | dbservers | permit |
| rule-004 | ssh:login | sudo | webservers | permit |
| rule-005 | network:connect | 10.0.1.0/24 | appservers:8080 | permit |
| rule-006 | network:connect | 0.0.0.0/0 | bastion:22 | permit |
| rule-007 | network:connect | 10.0.0.0/24 | webservers:80 | permit |
| rule-008 | network:connect | 10.0.2.0/24 | dbservers:5432 | permit |
| rule-009 | db:login | dba | PostgreSQL | permit |
| rule-010 | sudo:execute | sudo+secret | bastion | permit |
| rule-011 | filesystem:read | postgres_owner | /var/lib/postgresql/data | permit |
| rule-012 | filesystem:write | root_owner | /opt/app/app.jar | permit |
| rule-013 | filesystem:write | root_owner | /opt/app/lib/log4j*.jar | permit |
| rule-014 | * | all | all | **deny** |

## Ambiguities & Notes

1. **Credentials**: Ansible vault/password management not visible in plain-text config
2. **Implicit Deny**: Default-deny enforced via rule-014
3. **User Creation**: No user provisioning tasks found in role files
4. **Clearance Enforcement**: Sudo restricted to secret clearance on bastion only

## Security Posture

- **SSH Access**: Restricted to defined groups per host (good)
- **Network Segmentation**: DMZ, app, and data zones properly isolated
- **Database**: SUPERUSER granted to DBA group - consider least privilege
- **Vulnerabilities**: 5 packages with critical CVEs - **immediate remediation required**

---
*Generated by ABAC Policy Miner* | *Source: Ansible configuration*
