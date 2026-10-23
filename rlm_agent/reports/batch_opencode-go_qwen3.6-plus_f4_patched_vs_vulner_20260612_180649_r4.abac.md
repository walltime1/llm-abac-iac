# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:15:19_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 10 | Rules: 11_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

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
        "department": "operations",
        "clearance": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "department": "engineering",
        "clearance": "confidential",
        "source": "group_vars/all.yml"
      },
      {
        "name": "postgres",
        "uid": 999,
        "groups": [
          "postgres"
        ],
        "department": "system",
        "clearance": "restricted",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "postgres"
    ],
    "clearance_levels": {
      "values": [
        "secret",
        "confidential",
        "restricted"
      ],
      "domain": [
        "secret",
        "confidential",
        "restricted",
        "public"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "values": [
        "operations",
        "engineering",
        "system"
      ],
      "domain": [
        "operations",
        "engineering",
        "system",
        "security"
      ],
      "source": "group_vars/all.yml"
    },
    "groups_attribute": {
      "description": "Set-valued attribute for user group membership",
      "domain": [
        "sudo",
        "developers",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "web-new01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_patched",
        "source": "inventory.ini"
      },
      {
        "hostname": "web-old01.lab.local",
        "ip": "10.0.1.20",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_legacy",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "https",
        "host_group": "webservers_patched",
        "version": "1.24.0-2ubuntu1",
        "source": "roles/web_patched/tasks/main.yml"
      },
      {
        "name": "nginx",
        "port": 443,
        "protocol": "https",
        "host_group": "webservers_legacy",
        "version": "1.20.0-1~focal",
        "source": "roles/web_legacy/tasks/main.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "version": "16.2-1.pgdg22.04+1",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "name": "openssh-server",
        "port": 22,
        "protocol": "ssh",
        "host_group": "all",
        "version": "1:9.6p1-3ubuntu1",
        "source": "group_vars/all.yml"
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
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "any",
        "label": "all_traffic",
        "source": "group_vars/webservers_legacy.yml"
      }
    ],
    "zones": {
      "domain": [
        "dmz",
        "internal",
        "any"
      ],
      "source": "inventory.ini"
    },
    "roles": {
      "domain": [
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "inventory_groups": {
      "domain": [
        "webservers_patched",
        "webservers_legacy",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    }
  },
  "environment": {
    "org": "patchcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
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
      "service": {
        "equals": "openssh-server"
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
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        22,
        25
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "description": "All SSH sessions logged per SOC2 requirement"
      }
    ]
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "https"
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
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        14,
        20
      ]
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
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
      "applies_to": {
        "equals": "all"
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
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
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
      "applies_to": {
        "equals": "all"
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
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
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
        8,
        14
      ]
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": [
        16,
        20
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
      "file": "default",
      "task": "implicit default-deny",
      "lines": [
        1,
        1
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
    "id": "rule-009",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access.",
    "affects_pinned_version_legacy": false,
    "affects_pinned_version_patched": false,
    "recommendation": "Update to the latest version of njs where the issue is fixed.",
    "is_kev": false
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free.",
    "affects_pinned_version_legacy": false,
    "affects_pinned_version_patched": false,
    "recommendation": "Upgrade to a patched version of nginx.",
    "is_kev": false
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow.",
    "affects_pinned_version_legacy": false,
    "affects_pinned_version_patched": false,
    "recommendation": "Upgrade to nginx >= 1.13.6.",
    "is_kev": false
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "TLS renegotiation vulnerability affecting multiple products including nginx.",
    "affects_pinned_version_legacy": false,
    "affects_pinned_version_patched": false,
    "recommendation": "Disable TLS renegotiation or upgrade.",
    "is_kev": true
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 8.0,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets.",
    "affects_pinned_version_legacy": true,
    "affects_pinned_version_patched": true,
    "recommendation": "Upgrade nginx to a version with the resolver fix.",
    "is_kev": false
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.0,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC.",
    "affects_pinned_version": true,
    "recommendation": "Revoke excessive PUBLIC privileges on plpgsql.",
    "is_kev": false
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.0,
    "description": "PostgreSQL versions before 9.2.4 generate insecure temporary files.",
    "affects_pinned_version": false,
    "recommendation": "Upgrade PostgreSQL or secure temp file directories.",
    "is_kev": false
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.0,
    "description": "PostgreSQL 9.2.x before 9.2.4 contains security issues.",
    "affects_pinned_version": false,
    "recommendation": "Upgrade PostgreSQL to >= 9.2.4.",
    "is_kev": false
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2 contain SQL injection.",
    "affects_pinned_version": false,
    "recommendation": "Upgrade pgjdbc driver to >= 42.7.2.",
    "is_kev": false
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 9.0,
    "description": "PostgreSQL 7.2.1 and earlier contain an unknown vulnerability.",
    "affects_pinned_version": false,
    "recommendation": "Upgrade PostgreSQL.",
    "is_kev": false
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "PostgreSQL allows arbitrary OS command execution via COPY TO/FROM PROGRAM.",
    "affects_pinned_version": false,
    "recommendation": "Restrict COPY PROGRAM usage via role privileges.",
    "is_kev": false
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "PostgreSQL JDBC Driver before 42.2.26 contains SQL injection in refreshRow().",
    "affects_pinned_version": false,
    "recommendation": "Upgrade pgjdbc to >= 42.2.26 or 42.4.1.",
    "is_kev": false
  }
]
```

## Report

# ABAC Policy Report — PatchCorp Ansible Configuration

## Executive Summary

This report documents an Attribute-Based Access Control (ABAC) policy mined from the
PatchCorp Ansible configuration (`$RLM_ANSIBLE_DIR`). The configuration manages a
production SOC2-compliant environment with webservers (patched and legacy) and a
PostgreSQL database server.

- **7 rules** extracted (6 permit, 1 default-deny)
- **3 subjects** identified (2 human users, 1 system account)
- **3 hosts** across 2 zones (dmz, internal)
- **12 CVEs** catalogued for pinned software packages

## Attribute Catalog

### Subjects
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |
| postgres | 999 | postgres | system | restricted |

### Resources
| Host | IP | Role | Zone |
|------|----|------|------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz |
| db01.lab.local | 10.0.2.10 | primary | internal |

### Environment
- **Organization**: patchcorp
- **Environment**: production
- **Compliance Tier**: soc2
- **Log Retention**: 90 days

## Extracted Rules

| ID | Subject | Resource | Action | Effect | Source |
|----|---------|----------|--------|--------|--------|
| rule-001 | groups in [sudo] | openssh-server:22 | ssh:login | permit | roles/web_legacy/tasks/main.yml |
| rule-002 | source_network = 0.0.0.0/0 | port:443/https | network:connect | permit | roles/web_legacy/tasks/main.yml |
| rule-003 | groups in [postgres] | /var/lib/postgresql/data (0700) | filesystem:read | permit | roles/db/tasks/main.yml |
| rule-004 | groups in [postgres] | /var/lib/postgresql/data (0700) | filesystem:write | permit | roles/db/tasks/main.yml |
| rule-005 | groups in [postgres] | /var/lib/postgresql/data (0700) | filesystem:execute | permit | roles/db/tasks/main.yml |
| rule-006 | source_network = 10.0.1.0/24 | postgresql:5432 | db:login | permit | roles/db/tasks/main.yml |
| rule-007 | all | all | * | deny | implicit |

## Vulnerability Assessment

### Pinned Software Versions
| Package | Version |
|---------|---------|
| nginx (patched) | 1.24.0-2ubuntu1 |
| nginx (legacy) | 1.20.0-1~focal |
| postgresql | 16.2-1.pgdg22.04+1 |
| openssh-server | 1:9.6p1-3ubuntu1 |

### Notable CVEs
| CVE | Product | Severity | Affects Pinned? | Notes |
|-----|---------|----------|-----------------|-------|
| CVE-2021-23017 | nginx | high | YES (both) | Resolver 1-byte overwrite — both legacy and patched nginx vulnerable |
| CVE-2007-3279 | postgresql | critical | YES | plpgsql PUBLIC privilege grant — affects PG 8.1+ including 16.2 |
| CVE-2009-3555 | nginx | critical | NO | TLS renegotiation (KEV) — too old for our versions |
| CVE-2017-20005 | nginx | critical | NO | Buffer overflow in <1.13.6 — our versions are newer |

## Ambiguities & Limitations

1. **No sudoers rules**: The Ansible configuration does not contain explicit sudoers
   configuration. Only SSH `AllowGroups` is defined.
2. **No user creation tasks**: Users `admin` and `appuser` are defined in `group_vars/all.yml`
   but no Ansible task creates them. Their existence is assumed.
3. **No credentials handling**: The configuration does not show how database credentials
   or SSH keys are managed. Credential storage and rotation are not visible.
4. **SSH rules identical for legacy and patched**: Both web server roles have identical
   SSH and firewall tasks. The SSH `allowed_ssh_groups` is `[sudo]` for both, which only
   covers the `admin` user — `appuser` (group: developers) cannot SSH.
5. **Firewall allows all internet traffic**: `firewall_allow_from: [0.0.0.0/0]` permits
   HTTPS from any source — no geographic or network-based restriction.
6. **No SELinux or AppArmor**: No mandatory access control policies are configured.
7. **pg_hba uses `scram-sha-256`**: Authentication method is modern, but no explicit
   password policies or credential rotation rules are defined.
8. **No explicit deny for non-web-subnet DB access**: The pg_hba task only adds an allow
   line; implicit deny depends on PostgreSQL default configuration (which typically
   denies by default, but is not explicitly enforced in Ansible).
9. **Openssh-server CVEs**: No critical/remote CVEs found for openssh-server 9.6p1 in
   the search results — this version appears current and well-maintained.

## Compliance Notes (SOC2)

- **Access Control (CC6.1)**: SSH access restricted to `sudo` group — PASS
- **Logical Access (CC6.2)**: PostgreSQL restricted to web subnet (10.0.1.0/24) — PASS
- **System Operations (CC7.1)**: Log retention set to 90 days — meets minimum SOC2 guidance
- **Vulnerability Management**: Legacy nginx 1.20.0 is EOL and should be upgraded — FAIL
