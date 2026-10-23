# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:05:54_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 17 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "type": "object",
    "domain": null,
    "values": [
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
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "group_vars/all.yml"
      },
      {
        "name": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "clearance": "secret",
        "department": "data",
        "source": "group_vars/all.yml"
      }
    ],
    "source": "group_vars/all.yml"
  },
  "groups": {
    "type": "string",
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
    "type": "string",
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
    "type": "string",
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
  },
  "hosts": {
    "type": "object",
    "domain": null,
    "values": [
      {
        "hostname": "bastion01.lab.local",
        "ip": "10.0.0.5",
        "role": "bastion",
        "zone": "mgmt",
        "inventory_group": "bastion",
        "source": "inventory.ini"
      },
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "app01.lab.local",
        "ip": "10.0.2.10",
        "role": "application",
        "zone": "app",
        "inventory_group": "appservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.3.10",
        "role": "primary",
        "zone": "data",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "source": "inventory.ini"
  },
  "inventory_group": {
    "type": "string",
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
  "zone": {
    "type": "string",
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
  "service": {
    "type": "string",
    "domain": [
      "ssh",
      "postgresql",
      "httpd",
      "app"
    ],
    "values": [
      "ssh",
      "postgresql",
      "httpd",
      "app"
    ],
    "source": "role task files"
  },
  "port": {
    "type": "integer",
    "domain": null,
    "values": [
      22,
      80,
      5432,
      8080
    ],
    "source": "role task files"
  },
  "source_network": {
    "type": "string",
    "domain": null,
    "values": [
      "0.0.0.0/0",
      "10.0.0.0/24",
      "10.0.1.0/24",
      "10.0.2.0/24"
    ],
    "source": "role task files"
  },
  "path": {
    "type": "string",
    "domain": null,
    "values": [
      "/var/lib/postgresql/data",
      "/opt/app/app.jar",
      "/etc/ssh/sshd_config",
      "/etc/postgresql/pg_hba.conf"
    ],
    "source": "role task files"
  },
  "owner": {
    "type": "string",
    "domain": [
      "postgres",
      "root"
    ],
    "values": [
      "postgres",
      "root"
    ],
    "source": "role task files"
  },
  "group": {
    "type": "string",
    "domain": [
      "postgres",
      "root"
    ],
    "values": [
      "postgres",
      "root"
    ],
    "source": "role task files"
  },
  "mode": {
    "type": "string",
    "domain": [
      "0700"
    ],
    "values": [
      "0700"
    ],
    "source": "role task files"
  },
  "environment": {
    "type": "string",
    "domain": [
      "production"
    ],
    "values": [
      "production"
    ],
    "source": "group_vars/all.yml, inventory.ini"
  },
  "org": {
    "type": "string",
    "domain": [
      "chaincorp"
    ],
    "values": [
      "chaincorp"
    ],
    "source": "group_vars/all.yml"
  },
  "compliance_tier": {
    "type": "string",
    "domain": [
      "pci"
    ],
    "values": [
      "pci"
    ],
    "source": "group_vars/all.yml, inventory.ini"
  },
  "log_retention_days": {
    "type": "integer",
    "domain": null,
    "values": [
      365
    ],
    "source": "group_vars/all.yml"
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "description": "Allow SSH login to bastion from internet for sudo/dba groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "zone": {
        "equals": "mgmt"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        6,
        8
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Allow SSH login to web servers from mgmt subnet for sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers"
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
        11,
        13
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Allow SSH login to app servers for sudo/developers groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      },
      "zone": {
        "equals": "app"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        14,
        17
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow SSH login to db servers for sudo/dba groups",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "zone": {
        "equals": "data"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        17,
        19
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow sudo on bastion for secret-clearance users in sudo group",
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
        "equals": "bastion01.lab.local"
      },
      "zone": {
        "equals": "mgmt"
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
        "type": "authentication",
        "value": "password_required",
        "source": "roles/bastion/tasks/main.yml"
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        10,
        16
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow SSH access to bastion from any source (internet)",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        18,
        23
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow access to app port 8080 from web subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      },
      "port": {
        "equals": 8080
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
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        12,
        18
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Allow HTTP access to web servers from mgmt subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers"
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
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        10,
        15
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Allow PostgreSQL connections from app subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
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
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        12,
        16
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "Grant PostgreSQL superuser privileges to DBA users",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:admin",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        6,
        10
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "PostgreSQL data directory with restricted permissions",
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        3,
        8
      ]
    }
  },
  {
    "rule_id": "rule-012",
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
    "resource_condition": {},
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
      "port": {
        "equals": 8080
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
    "id": "rule-004",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "OpenSSH RCE vulnerability - allows remote code execution",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to version 9.4 or later immediately",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-41617",
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "severity": "high",
    "cvss_score": 7.8,
    "description": "OpenSSH privilege escalation in sshd",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to latest stable version",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 10.0,
    "description": "Log4Shell RCE - remote code execution via JNDI injection",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade Log4j to 2.17.0 or later. Apply WAF rules as temporary mitigation.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 9.0,
    "description": "Log4j DoS and RCE bypass",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade Log4j to 2.17.0 or later",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2023-2454",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "severity": "high",
    "cvss_score": 8.8,
    "description": "PostgreSQL vulnerability allowing privilege escalation",
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to 9.2.3 or later",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "severity": "critical",
    "cvss_score": 9.1,
    "description": "SQL injection vulnerability in PostgreSQL",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade PostgreSQL to latest version immediately",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-44790",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Apache httpd buffer overflow leading to RCE",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade Apache to 2.4.51 or later",
    "source": "group_vars/all.yml"
  }
]
```

## Report

# ABAC Policy Report - ChainCorp Production Environment

## Executive Summary

This report presents an Attribute-Based Access Control (ABAC) policy mined from the ChainCorp Ansible configuration. The policy governs access to 4 production hosts across 4 zones (mgmt, dmz, app, data) for 3 users with varying clearance levels.

**Critical Finding:** The configuration contains 7 known vulnerabilities (CVSS 7.8-10.0) in all pinned software packages, requiring immediate remediation.

---

## Attribute Catalog

### Subject Attributes
| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| name | string | [admin, developer, dba] | group_vars/all.yml |
| uid | integer | [1001, 1002, 1003] | group_vars/all.yml |
| groups | string[] | [sudo, developers, dba] | group_vars/all.yml |
| clearance | string | [secret, confidential] | group_vars/all.yml |
| department | string | [operations, engineering, data] | group_vars/all.yml |

### Resource Attributes
| Attribute | Type | Domain | Source |
|-----------|------|--------|--------|
| hostname | string | [bastion01.lab.local, web01.lab.local, app01.lab.local, db01.lab.local] | inventory.ini |
| inventory_group | string | [bastion, webservers, appservers, dbservers] | inventory.ini |
| zone | string | [mgmt, dmz, app, data] | inventory.ini |
| service | string | [ssh, postgresql, httpd, app] | role task files |
| port | integer | [22, 80, 5432, 8080] | role task files |
| source_network | string | CIDR ranges | role task files |
| path | string | filesystem paths | role task files |
| owner | string | [postgres, root] | role task files |
| group | string | [postgres, root] | role task files |
| mode | string | [0700] | role task files |

### Environment Attributes
| Attribute | Type | Value | Source |
|-----------|------|-------|--------|
| org | string | chaincorp | group_vars/all.yml |
| environment | string | production | inventory.ini |
| compliance_tier | string | pci | group_vars/all.yml |
| log_retention_days | integer | 365 | group_vars/all.yml |

---

## Vulnerability Assessment

### Pinned Software Packages with CVEs

| Product | Pinned Version | CVEs Found | Max CVSS | Severity |
|---------|----------------|------------|----------|----------|
| openssh | 1:9.1p1-1ubuntu1 | 2 | 9.8 | CRITICAL |
| openssh | 1:9.9p1-3ubuntu1 | 2 | 7.8 | HIGH |
| log4j | 2.14.1 | 2 | 10.0 | CRITICAL |
| postgresql | 9.2.3-1.pgdg20.04+1 | 2 | 9.1 | CRITICAL |
| apache | 2.4.49-1 | 1 | 9.8 | CRITICAL |

### Critical Vulnerabilities Requiring Immediate Action

1. **CVE-2021-44228 (Log4Shell)** - CVSS 10.0 - CRITICAL
   - Product: log4j 2.14.1
   - Impact: Remote code execution via JNDI injection
   - Recommendation: URGENT: Upgrade to Log4j 2.17.0+ immediately

2. **CVE-2023-38408** - CVSS 9.8 - CRITICAL
   - Product: openssh 1:9.1p1-1ubuntu1
   - Impact: Remote code execution in sshd
   - Recommendation: Upgrade OpenSSH to 9.4+ immediately

3. **CVE-2021-44790** - CVSS 9.8 - CRITICAL
   - Product: apache 2.4.49-1
   - Impact: Buffer overflow leading to RCE
   - Recommendation: URGENT: Upgrade Apache to 2.4.51+

4. **CVE-2024-1597** - CVSS 9.1 - CRITICAL
   - Product: postgresql 9.2.3
   - Impact: SQL injection vulnerability
   - Recommendation: URGENT: Upgrade PostgreSQL immediately

---

## ABAC Rules

| Rule ID | Subject Condition | Resource | Action | Effect |
|---------|-------------------|----------|--------|--------|
| rule-001 | groups: sudo,dba | bastion01.lab.local | ssh:login | permit |
| rule-002 | groups: sudo | webservers zone:dmz | ssh:login | permit |
| rule-003 | groups: sudo,developers | appservers zone:app | ssh:login | permit |
| rule-004 | groups: sudo,dba | dbservers zone:data | ssh:login | permit |
| rule-005 | groups: sudo, clearance: secret | bastion01.lab.local | sudo:execute | permit |
| rule-006 | source_network: 0.0.0.0/0 | bastion01.lab.local | network:connect | permit |
| rule-007 | source_network: 10.0.1.0/24 | appservers port:8080 | network:connect | permit |
| rule-008 | source_network: 10.0.0.0/24 | webservers port:80 | network:connect | permit |
| rule-009 | source_network: 10.0.2.0/24 | dbservers service:postgresql | db:login | permit |
| rule-010 | groups: dba | dbservers service:postgresql | db:admin | permit |
| rule-011 | applies_to: all | /var/lib/postgresql/data mode:0700 | filesystem:read | permit |
| rule-012 | applies_to: all | applies_to: all | * | deny |

**Total Rules:** 12 (11 permit + 1 default-deny)

---

## Security Analysis

### Strengths
1. **Defense in depth:** Network segmentation with 4 distinct zones
2. **Group-based access control:** SSH access restricted to specific groups per host
3. **Clearance enforcement:** Bastion sudo requires secret clearance
4. **Database isolation:** PostgreSQL accessible only from app subnet
5. **Filesystem hardening:** PostgreSQL data directory mode 0700

### Weaknesses
1. **Bastion exposure:** SSH open to internet (0.0.0.0/0) - high risk
2. **DBA superuser:** All DBAs get PostgreSQL SUPERUSER privileges
3. **Insufficient app protection:** App servers have internet-adjacent exposure
4. **Developer access:** Developers can SSH to app servers (potential lateral movement)

---

## Recommendations

### Immediate (Within 24 Hours)
1. Upgrade Log4j from 2.14.1 to 2.17.0+ to address Log4Shell (CVE-2021-44228)
2. Upgrade OpenSSH to version 9.4+ on bastion host
3. Upgrade Apache httpd to 2.4.51+ on web servers
4. Upgrade PostgreSQL to latest stable version

### Short-term (Within 1 Week)
1. Restrict bastion SSH access to known IP ranges instead of 0.0.0.0/0
2. Implement least-privilege database access - use specific role grants instead of SUPERUSER
3. Add MFA for sudo operations on bastion
4. Implement network monitoring for bastion SSH connections

### Long-term (Within 1 Month)
1. Implement jump server/bastion host monitoring (audit logging)
2. Move app servers behind additional firewall rules
3. Implement credential rotation policy
4. Add intrusion detection system (IDS) on network boundaries

---

## Ambiguities

1. **Credentials:** No SSH keys or passwords are defined in the Ansible configuration. Credential management is external.
2. **Log4j usage:** While Log4j is installed on app servers, the specific services using it are not clearly enumerated.
3. **Audit logging:** No explicit session logging or audit trail configuration found for privileged commands.
4. **Compliance mapping:** PCI-DSS compliance requirements not explicitly mapped to access rules.

---

## Policy Metadata

| Field | Value |
|-------|-------|
| Organization | chaincorp |
| Environment | production |
| Compliance Tier | pci |
| Log Retention | 365 days |
| Policy Version | 1.0 |
| Generated | Automated ABAC Mining |
