# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:11:23_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 9 | Rules: 14_  
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
      }
    ],
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance_levels": [
      {
        "level": "secret",
        "domain": [
          "secret",
          "confidential",
          "top_secret",
          "unclassified"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "level": "confidential",
        "domain": [
          "secret",
          "confidential",
          "top_secret",
          "unclassified"
        ],
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "name": "operations",
        "domain": [
          "operations",
          "engineering"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "name": "engineering",
        "domain": [
          "operations",
          "engineering"
        ],
        "source": "group_vars/all.yml"
      }
    ]
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
        "protocol": "tcp",
        "host_group": "webservers_patched",
        "source": "group_vars/webservers_patched.yml"
      },
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers_legacy",
        "source": "group_vars/webservers_legacy.yml"
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
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "openssh",
        "source": "roles/web_legacy/tasks/main.yml"
      },
      {
        "path": "/etc/postgresql/pg_hba.conf",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0640",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers_patched.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "patchcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "domain": [
        "production",
        "staging",
        "development"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "domain": [
        "soc2",
        "pci-dss",
        "hipaa",
        "iso27001"
      ],
      "source": "inventory.ini"
    },
    "log_retention_days": {
      "value": 90,
      "source": "group_vars/all.yml"
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
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "host_group": {
        "equals": "webservers_patched"
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        21,
        25
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
      "role": {
        "equals": "frontend"
      },
      "host_group": {
        "equals": "webservers_legacy"
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
        21,
        25
      ]
    },
    "obligations": []
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "webservers_patched"
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        13,
        19
      ]
    },
    "obligations": []
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "webservers_legacy"
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
        13,
        19
      ]
    },
    "obligations": []
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
      },
      "host_group": {
        "equals": "dbservers"
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
      "task": "Allow postgres only from web subnet",
      "lines": [
        16,
        20
      ]
    },
    "obligations": []
  },
  {
    "id": "rule-006",
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
    },
    "obligations": []
  },
  {
    "id": "rule-007",
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
    },
    "obligations": []
  },
  {
    "id": "rule-008",
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
    },
    "obligations": []
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
      "file": "implicit",
      "task": "default-deny",
      "lines": [
        0,
        0
      ]
    },
    "obligations": []
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
    "id": "rule-013",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "webservers_patched"
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
    "id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "webservers_legacy"
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
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "HTTP/2 rapid reset attack enabling denial of service",
    "is_kev": true,
    "is_remote": true,
    "affected_pinned_versions": {
      "webservers_legacy": {
        "version": "1.20.0-1~focal",
        "affects_pinned_version": true
      },
      "webservers_patched": {
        "version": "1.24.0-2ubuntu1",
        "affects_pinned_version": false
      }
    },
    "recommendation": "Update legacy nginx from 1.20.0 to 1.24.0+ to mitigate HTTP/2 rapid reset (CVE-2023-44487). Patched webservers are already on a safe version."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "cvss_score": 7.3,
    "severity": "high",
    "description": "nginx resolver vulnerability with DNS response handling",
    "is_kev": false,
    "is_remote": true,
    "affected_pinned_versions": {
      "webservers_legacy": {
        "version": "1.20.0-1~focal",
        "affects_pinned_version": true
      },
      "webservers_patched": {
        "version": "1.24.0-2ubuntu1",
        "affects_pinned_version": false
      }
    },
    "recommendation": "Update legacy nginx to resolve DNS resolver vulnerability. Patched version already mitigates this."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "PostgreSQL privilege escalation vulnerability",
    "is_kev": true,
    "is_remote": true,
    "affected_pinned_versions": {
      "dbservers": {
        "version": "16.2-1.pgdg22.04+1",
        "affects_pinned_version": true
      }
    },
    "recommendation": "Update PostgreSQL from 16.2 to latest patch release. Critical KEV-listed vulnerability with active exploitation."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "OpenSSH remote code execution via PKCS#11 provider",
    "is_kev": true,
    "is_remote": true,
    "affected_pinned_versions": {
      "all": {
        "version": "1:9.6p1-3ubuntu1",
        "affects_pinned_version": false
      }
    },
    "recommendation": "Current OpenSSH version 9.6p1 is not affected (fix released in 9.3p2). No action required."
  },
  {
    "cve_id": "CVE-2022-41741",
    "product": "nginx",
    "cvss_score": 7.5,
    "severity": "high",
    "description": "nginx SSI include bypass vulnerability",
    "is_kev": false,
    "is_remote": true,
    "affected_pinned_versions": {
      "webservers_legacy": {
        "version": "1.20.0-1~focal",
        "affects_pinned_version": true
      },
      "webservers_patched": {
        "version": "1.24.0-2ubuntu1",
        "affects_pinned_version": false
      }
    },
    "recommendation": "Update legacy nginx to mitigate SSI include bypass."
  }
]
```

## Report

# ABAC Policy Report — patchcorp Production Environment

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration for **patchcorp**'s **production** environment (compliance tier: **SOC2**). The configuration covers 3 hosts across 2 zones (dmz, internal) with 2 defined users and 2 access groups.

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | patchcorp |
| Environment | production |
| Compliance Tier | soc2 |
| Log Retention | 90 days |

## Hosts

| Hostname | IP | Role | Zone | Inventory Group |
|----------|-----|------|------|-----------------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

## Users

| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |

## Rules Summary

| ID | Action | Effect | Subject | Resource |
|----|--------|--------|---------|----------|
| rule-001 | ssh:login | permit | groups: sudo | webservers_patched (frontend) |
| rule-002 | ssh:login | permit | groups: sudo | webservers_legacy (frontend) |
| rule-003 | network:connect | permit | source: 0.0.0.0/0 | port 443/tcp (patched) |
| rule-004 | network:connect | permit | source: 0.0.0.0/0 | port 443/tcp (legacy) |
| rule-005 | db:login | permit | source: 10.0.1.0/24 | postgresql:5432 (primary) |
| rule-006 | filesystem:read | permit | user: postgres | /var/lib/postgresql/data (0700) |
| rule-007 | filesystem:write | permit | user: postgres | /var/lib/postgresql/data (0700) |
| rule-008 | filesystem:execute | permit | user: postgres | /var/lib/postgresql/data (0700) |
| rule-009 | * | deny | all | all (default deny) |

## Vulnerability Assessment

### Critical Findings

| CVE | Product | Severity | Affects Legacy | Affects Patched | KEV |
|-----|---------|----------|----------------|-----------------|-----|
| CVE-2024-1597 | PostgreSQL | Critical (10.0) | N/A | YES (16.2) | Yes |
| CVE-2023-44487 | nginx | High (7.5) | YES (1.20.0) | No (1.24.0) | Yes |
| CVE-2023-38408 | OpenSSH | Critical (9.8) | N/A | No (9.6p1) | Yes |
| CVE-2021-23017 | nginx | High (7.3) | YES (1.20.0) | No (1.24.0) | No |
| CVE-2022-41741 | nginx | High (7.5) | YES (1.20.0) | No (1.24.0) | No |

### Recommendations
1. **URGENT**: Update PostgreSQL 16.2 on dbservers — CVE-2024-1597 is a critical KEV-listed vulnerability (CVSS 10.0)
2. **HIGH**: Update legacy nginx from 1.20.0 to match patched version (1.24.0) — resolves CVE-2023-44487 (KEV) and other vulnerabilities
3. OpenSSH 9.6p1 is current and not affected by known critical CVEs

## Ambiguities and Gaps

1. **No explicit password policy** — Users are defined without password hash or expiration settings in the Ansible configuration.
2. **No sudoers rules** — While the `sudo` group is defined, no explicit sudoers configuration is present in the mined files.
3. **Firewall allows 0.0.0.0/0** — Both web server groups permit HTTPS from any source, which may be overly permissive.
4. **No SELinux policies** — No SELinux boolean or policy configurations found in the Ansible files.
5. **No monitoring rules** — No Nagios or monitoring access configurations found.
6. **Implicit deny for SSH** — The `AllowGroups sudo` configuration implicitly denies SSH for the `developers` group (appuser), but this is not an explicit deny rule in the firewall.
7. **pg_hba.conf uses scram-sha-256** — Authentication method is specified but no explicit database user/privilege mapping is defined in the tasks.

## Compliance Notes

- SOC2 compliance tier requires audit logging — ensure log_retention_days (90) meets organizational requirements.
- The divergent nginx versions (legacy vs patched) create an inconsistent security posture that should be resolved.
