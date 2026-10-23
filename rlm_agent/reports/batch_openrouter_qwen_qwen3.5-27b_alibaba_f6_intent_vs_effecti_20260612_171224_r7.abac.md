# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:30:22_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

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
    "groups": [
      "sudo",
      "developers",
      "dba"
    ],
    "clearance_levels": [
      "secret",
      "confidential"
    ],
    "departments": [
      "operations",
      "engineering",
      "data"
    ]
  },
  "resources": {
    "hosts": [
      {
        "hostname": "proxy01.lab.local",
        "ip": "10.0.1.10",
        "role": "reverse_proxy",
        "zone": "dmz",
        "inventory_group": "dmz",
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
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
      },
      {
        "name": "application",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
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
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "DMZ subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "appservers subnet",
        "source": "group_vars/dbservers.yml"
      }
    ]
  },
  "environment": {
    "org": "segcorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
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
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "25-29"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "21-25"
    }
  },
  {
    "id": "rule-003",
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
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "ssh"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "33-37"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
    "privilege_level": "SUPERUSER",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "17-21"
    }
  },
  {
    "id": "rule-005",
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
    "privilege_level": "NOSUPERUSER",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "23-27"
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
      "hostname": {
        "equals": "app01.lab.local"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "13-18"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "29-32"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "17-22"
    }
  },
  {
    "id": "rule-009",
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "9-15"
    }
  },
  {
    "id": "rule-010",
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "9-15"
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "6-11"
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "9-14"
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
    "action": "*",
    "effect": "deny",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "implicit",
      "task": "default-deny",
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
      "compliance_tier": {
        "equals": "pci"
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
      "compliance_tier": {
        "equals": "pci"
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
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
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
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
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
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "pci"
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Update to nginx 1.9.10 or later versions."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Update to the latest version of njs where the issue is fixed."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when parsing the Content-Length header",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Upgrade to nginx 1.13.6 or later."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.3,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS before 2.8.4, and others contain a vulnerability in the SSL/TLS protocol",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Upgrade affected components to patched versions."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from the DNS server",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Upgrade to nginx 1.20.2, 1.19.10, or 1.21.0."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Upgrade to patched version or disable HTTP/2."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain a buffer overflow in the psql command",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Upgrade to PostgreSQL 7.2.3 or later."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insufficiently random numbers",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Upgrade to patched PostgreSQL version."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to unprivileged users",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Upgrade to patched PostgreSQL version."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 allow privilege escalation",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Upgrade to patched PostgreSQL version."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.8, 42.2.28, and 42.1.4 contain a SQL injection vulnerability",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Upgrade pgjdbc to version 42.7.2 or later."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the pg_read_binary_file function",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Upgrade to PostgreSQL 11.3, 10.8, 9.6.13, 9.5.18, or 9.4.23."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection vulnerability",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "Upgrade pgjdbc to version 42.2.26 or 42.4.1 or later."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a three-tier infrastructure (DMZ, Application, Database) with PCI compliance requirements.

## Infrastructure Overview

### Environment
- **Organization**: segcorp
- **Environment**: production
- **Compliance Tier**: PCI
- **Log Retention**: 365 days

### Hosts (3)
| Hostname | IP | Role | Zone |
|----------|-----|------|------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz |
| app01.lab.local | 10.0.2.10 | application | app |
| db01.lab.local | 10.0.3.10 | primary | data |

### Users (3)
| User | Groups | Department | Clearance |
|------|--------|------------|-----------|
| admin | sudo | operations | secret |
| developer | developers | engineering | confidential |
| dba | dba | data | secret |

## Access Control Rules (13)

### SSH Access Rules
| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-001 | groups: sudo | proxy01.lab.local | ssh:login | permit |
| rule-002 | groups: sudo, developers | app01.lab.local | ssh:login | permit |
| rule-003 | groups: sudo, dba | db01.lab.local | ssh:login | permit |

### Database Access Rules
| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-004 | groups: dba | postgresql | db:login (SUPERUSER) | permit |
| rule-005 | groups: developers | postgresql | db:login (NOSUPERUSER) | permit |

### Network Policy Rules
| Rule | Source | Destination | Port | Effect |
|------|--------|-------------|------|--------|
| rule-006 | 10.0.1.0/24 (DMZ) | app01.lab.local | 8080/tcp | permit |
| rule-007 | 10.0.2.0/24 (app) | db01.lab.local | 5432/tcp | permit |
| rule-008 | 0.0.0.0/0 (internet) | proxy01.lab.local | 443/tcp | permit |

### Filesystem Rules
| Rule | Subject | Path | Action | Effect |
|------|---------|------|--------|--------|
| rule-009 | user: postgres | /var/lib/postgresql/data | filesystem:read | permit |
| rule-010 | user: postgres | /var/lib/postgresql/data | filesystem:write | permit |

### User Provisioning Rules
| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-011 | groups: developers, sudo | app01.lab.local | user:create | permit |
| rule-012 | groups: sudo | proxy01.lab.local | user:create | permit |

### Default Policy
| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-013 | all | all | * | deny |

## Vulnerability Assessment

### Summary
- **Total Vulnerabilities Found**: 13
- **Critical**: 10
- **High**: 3
- **KEV (Known Exploited)**: 5

### Critical Findings by Product

#### nginx (1.20.0-1~focal)
| CVE | Severity | CVSS | Remote | KEV | Recommendation |
|-----|----------|------|--------|-----|----------------|
| CVE-2016-0746 | critical | 9.8 | Yes | No | Update to nginx 1.9.10+ |
| CVE-2021-46461 | critical | 9.8 | Yes | No | Update njs to latest |
| CVE-2017-20005 | critical | 9.8 | Yes | No | Upgrade to 1.13.6+ |
| CVE-2009-3555 | critical | 9.3 | Yes | Yes | Upgrade affected components |
| CVE-2021-23017 | high | 7.5 | Yes | No | Upgrade to 1.20.2+ |
| CVE-2023-44487 | high | 7.5 | Yes | Yes | Patch or disable HTTP/2 |

#### postgresql (16.2-1.pgdg22.04+1)
| CVE | Severity | CVSS | Remote | KEV | Recommendation |
|-----|----------|------|--------|-----|----------------|
| CVE-2002-1399 | critical | 9.8 | Yes | No | Upgrade to 7.2.3+ |
| CVE-2013-1902 | critical | 9.8 | Yes | No | Upgrade to patched version |
| CVE-2007-3279 | critical | 9.8 | Yes | No | Upgrade to patched version |
| CVE-2013-1903 | critical | 9.8 | Yes | No | Upgrade to patched version |
| CVE-2024-1597 | critical | 9.8 | Yes | Yes | Upgrade pgjdbc to 42.7.2+ |
| CVE-2019-9193 | critical | 9.8 | Yes | Yes | Upgrade to 11.3+ |
| CVE-2022-31197 | critical | 9.8 | Yes | Yes | Upgrade pgjdbc to 42.2.26+ |

#### openssh-server (1:9.1p1-1ubuntu1)
- No critical/high remote vulnerabilities found
- No KEV entries found

## Ambiguities and Notes

1. **Package Version Matching**: Some CVEs reference older versions that may not affect the pinned versions (nginx 1.20.0, postgresql 16.2). Manual verification recommended.

2. **Implicit Deny**: The default-deny rule (rule-013) is implicit in the configuration but explicitly documented for completeness.

3. **Network Layer Rules**: Network policies use source_network as the subject attribute, following the namespace discipline for network-layer rules.

4. **Privilege Levels**: Database rules distinguish between SUPERUSER and NOSUPERUSER privilege levels as separate rules.

## Compliance Considerations

- PCI compliance tier requires strict access controls
- Network segmentation enforced (DMZ → app → data)
- SSH access restricted by group membership
- Database access follows least privilege principle

## Recommendations

1. **Immediate**: Address KEV vulnerabilities (CVE-2009-3555, CVE-2023-44487, CVE-2024-1597, CVE-2019-9193, CVE-2022-31197)
2. **Short-term**: Upgrade nginx and postgresql to latest patched versions
3. **Ongoing**: Implement regular vulnerability scanning and patch management
