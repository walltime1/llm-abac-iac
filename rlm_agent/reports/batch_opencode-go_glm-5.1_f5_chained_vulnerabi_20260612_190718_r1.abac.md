# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 20:18:46_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 15 | Rules: 19_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subject": {
    "user": {
      "type": "string",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "domain": null,
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "string",
      "domain": [
        "confidential",
        "secret"
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
      "source": "group_vars/all.yml"
    },
    "source_ip": {
      "type": "string",
      "domain": null,
      "source": "inferred from firewall rules"
    },
    "source_network": {
      "type": "string",
      "domain": null,
      "source": "inferred from firewall rules"
    },
    "source_zone": {
      "type": "string",
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inferred from inventory zones"
    }
  },
  "resource": {
    "hostname": {
      "type": "string",
      "domain": [
        "bastion01.lab.local",
        "web01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "domain": null,
      "source": "inventory.ini"
    },
    "role": {
      "type": "string",
      "domain": [
        "bastion",
        "frontend",
        "application",
        "primary"
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
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "string",
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "string",
      "domain": [
        "ssh",
        "httpd",
        "app",
        "postgresql",
        "sudo"
      ],
      "source": "roles/*/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "domain": null,
      "source": "group_vars/*.yml"
    },
    "path": {
      "type": "string",
      "domain": null,
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "string",
      "domain": null,
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "string",
      "domain": null,
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "domain": null,
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "string",
      "domain": null,
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "string",
      "domain": [
        "chaincorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "string",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "string",
      "domain": [
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
    "id": "rule-001",
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
      },
      "service": {
        "equals": "ssh"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "8-12"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "ssh"
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
      "lines": "21-25"
    }
  },
  {
    "id": "rule-003",
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
      },
      "service": {
        "equals": "ssh"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "31-35"
    }
  },
  {
    "id": "rule-004",
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
      },
      "service": {
        "equals": "ssh"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "29-33"
    }
  },
  {
    "id": "rule-005",
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
      },
      "service": {
        "equals": "sudo"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "password_required",
        "description": "nopassword=false enforced"
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "22-29"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": "14-20"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "httpd"
      },
      "port": {
        "equals": 80
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
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "13-19"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
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
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": "23-29"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "23-27"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
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
      "task": "Create DB superuser role for DBAs",
      "lines": "16-21"
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      "lines": "8-14"
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      "lines": "8-14"
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
    "effect": "deny"
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
    "id": "rule-015",
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
    "id": "rule-016",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
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
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "httpd"
      },
      "port": {
        "equals": 80
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
    "id": "rule-018",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
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
    "id": "rule-019",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
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
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade Log4j to 2.17.1 or later immediately. This is a critical RCE vulnerability (Log4Shell) actively exploited in the wild. The pinned version 2.14.1 is directly affected.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-41773",
    "product": "apache_httpd",
    "pinned_version": "2.4.49",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade Apache httpd to 2.4.51 or later. Version 2.4.49 is specifically affected by a path traversal vulnerability that can lead to remote code execution.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-42013",
    "product": "apache_httpd",
    "pinned_version": "2.4.49",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade Apache httpd to 2.4.51 or later. This is a follow-up to CVE-2021-41773 with an improved path traversal exploit that also affects 2.4.49.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "9.2.3-1",
    "severity": "critical",
    "cvss_score": 9.1,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to 9.2.4 or later. Version 9.2.3 is affected by a random number generation weakness that can lead to authentication bypass.",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "9.2.3-1",
    "severity": "medium",
    "cvss_score": 5.0,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL to 9.2.4 or later. Version 9.2.3 generates insufficiently random passwords for the pgcrypto extension.",
    "source": "group_vars/all.yml"
  }
]
```

## Report

# ABAC Policy Mining Report — ChainCorp Ansible Infrastructure

## Executive Summary

An Attribute-Based Access Control (ABAC) policy was mined from the ChainCorp Ansible configuration covering 4 host groups (bastion, webservers, appservers, dbservers), 3 defined users (admin, developer, dba), and 4 network zones (mgmt, dmz, app, data). The environment is classified as PCI-compliant production. **5 critical/high vulnerabilities** were identified in pinned software versions, including the infamous Log4Shell (CVE-2021-44228) and Apache path traversal (CVE-2021-41773/42013).

## Infrastructure Overview

| Host Group | Hostname | IP | Role | Zone |
|---|---|---|---|---|
| bastion | bastion01.lab.local | 10.0.0.5 | bastion | mgmt |
| webservers | web01.lab.local | 10.0.1.10 | frontend | dmz |
| appservers | app01.lab.local | 10.0.2.10 | application | app |
| dbservers | db01.lab.local | 10.0.3.10 | primary | data |

### Users

| User | UID | Groups | Department | Clearance |
|---|---|---|---|---|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

### Environment

- **Organization**: chaincorp
- **Environment**: production
- **Compliance Tier**: PCI
- **Default Log Retention**: 365 days

## Extracted ABAC Rules (14 total)

### SSH Access Control (4 rules)

| Rule ID | Groups Allowed | Target Host Group | Source |
|---|---|---|---|
| rule-001 | sudo, dba | bastion | roles/bastion/tasks/main.yml |
| rule-002 | sudo | webservers | roles/web/tasks/main.yml |
| rule-003 | sudo, developers | appservers | roles/app/tasks/main.yml |
| rule-004 | sudo, dba | dbservers | roles/db/tasks/main.yml |

### Sudo Access (1 rule)

| Rule ID | Condition | Target | Notes |
|---|---|---|---|
| rule-005 | groups=sudo AND clearance=secret | bastion | Password required (nopassword=false) |

### Network Firewall Rules (4 rules)

| Rule ID | Source Network | Target | Service | Port |
|---|---|---|---|---|
| rule-006 | 0.0.0.0/0 | bastion | ssh | 22 |
| rule-007 | 10.0.0.0/24 | webservers | httpd | 80 |
| rule-008 | 10.0.1.0/24 | appservers | app | 8080 |
| rule-009 | 10.0.2.0/24 | dbservers | postgresql | 5432 |

### Database Access (1 rule)

| Rule ID | Groups | Target | Privilege |
|---|---|---|---|
| rule-010 | dba | dbservers | SUPERUSER + LOGIN |

### Filesystem Access (2 rules)

| Rule ID | Groups | Path | Mode | Action |
|---|---|---|---|---|
| rule-011 | dba | /var/lib/postgresql/data | 0700 | read |
| rule-012 | dba | /var/lib/postgresql/data | 0700 | write |

### Explicit Deny (1 rule)

| Rule ID | Scope | Action | Effect |
|---|---|---|---|
| rule-013 | Non-app-subnet → dbservers:5432 | network:connect | deny |

### Default Deny (1 rule)

| Rule ID | Scope | Action | Effect |
|---|---|---|---|
| rule-014 | All subjects, all resources | * | deny |

## Vulnerability Assessment

### Critical Findings

| CVE | Product | Pinned Version | Severity | CVSS | Remote | KEV | Affects Version |
|---|---|---|---|---|---|---|---|
| CVE-2021-44228 | Log4j | 2.14.1 | Critical | 10.0 | Yes | Yes | **Yes** |
| CVE-2021-41773 | Apache httpd | 2.4.49 | Critical | 9.8 | Yes | Yes | **Yes** |
| CVE-2021-42013 | Apache httpd | 2.4.49 | Critical | 9.8 | Yes | Yes | **Yes** |
| CVE-2013-1903 | PostgreSQL | 9.2.3 | Critical | 9.1 | Yes | No | **Yes** |
| CVE-2013-1902 | PostgreSQL | 9.2.3 | Medium | 5.0 | Yes | No | **Yes** |

### Recommendations

1. **Log4j (CVE-2021-44228)**: Upgrade to Log4j 2.17.1+. This is the critical Log4Shell RCE vulnerability, actively exploited in the wild with CVSS 10.0. The pinned version 2.14.1 is directly affected.
2. **Apache httpd (CVE-2021-41773/42013)**: Upgrade to 2.4.51+. Both path traversal vulnerabilities lead to remote code execution on version 2.4.49.
3. **PostgreSQL (CVE-2013-1903/1902)**: Upgrade to 9.2.4+. Version 9.2.3 has authentication bypass and weak random number generation vulnerabilities.
4. **OpenSSH on bastion**: Version 9.1p1 is pinned but no critical remote CVEs were found affecting this specific version. Consider upgrading to the latest stable release for defense in depth.

## Security Concerns

### Critical Issues

1. **Bastion SSH open to the internet (rule-006)**: The firewall allows SSH from 0.0.0.0/0, exposing the bastion to brute-force attacks. Combined with the vulnerable OpenSSH version, this is a significant risk.
2. **Log4Shell on appservers**: The app server runs Log4j 2.14.1 which is directly exploitable via CVE-2021-44228. This allows unauthenticated remote code execution.
3. **Apache path traversal on webservers**: Version 2.4.49 is vulnerable to CVE-2021-41773 and CVE-2021-42013, enabling remote code execution.
4. **PostgreSQL 9.2.3 on dbservers**: This ancient version has known authentication bypass vulnerabilities.

### Design Concerns

1. **Sudo restricted to secret clearance on bastion only**: The `when` condition `item.clearance == 'secret'` means the `developer` user (clearance=confidential) cannot sudo on the bastion, even if they could SSH in. However, the developer is not in the allowed SSH groups for bastion anyway.
2. **DBA has SUPERUSER access**: The postgresql_user task grants LOGIN,SUPERUSER to all dba group members without granular privilege separation.
3. **No firewall rules for SSH on web/app/db**: Only bastion has an explicit firewall rule for SSH. The other hosts rely on AllowGroups in sshd_config for access control, but lack network-level filtering for port 22.

## Ambiguities

1. **Credentials**: The Ansible configuration does not define user passwords or SSH keys. Authentication mechanism is assumed but not specified.
2. **pg_hba.conf implicit deny**: The pg_hba rule allows connections from 10.0.2.0/24 with scram-sha-256 authentication. The implicit default deny for all other sources is modeled as rule-013, but the actual pg_hba.conf may have additional entries not shown.
3. **Log4j deployment**: The app server deploys a Log4j JAR via `get_url` but no application configuration is provided. The actual attack surface depends on how the application uses Log4j.
4. **Firewall default policy**: The firewalld rules only define `state: enabled` entries. The default zone policy (drop/reject) is not explicitly configured in Ansible.
5. **OpenSSH version discrepancy**: The bastion uses `ssh_version_bastion: "1:9.1p1-1ubuntu1"` while other hosts use `ssh_version: "1:9.9p1-3ubuntu1"`. The reason for the older version on the bastion (the most exposed host) is unclear and concerning.
