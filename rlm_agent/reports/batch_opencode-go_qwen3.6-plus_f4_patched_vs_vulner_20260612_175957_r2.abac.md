# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:10:37_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 10_  
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
        "uid": null,
        "groups": [
          "postgres"
        ],
        "department": null,
        "clearance": null,
        "source": "roles/db/tasks/main.yml",
        "note": "system account implied by file ownership"
      }
    ],
    "groups": {
      "values": [
        "sudo",
        "developers",
        "postgres"
      ],
      "domain": [
        "sudo",
        "developers",
        "postgres"
      ],
      "source": "group_vars/all.yml, roles/db/tasks/main.yml"
    },
    "clearance_levels": {
      "values": [
        "secret",
        "confidential"
      ],
      "domain": [
        "top_secret",
        "secret",
        "confidential",
        "unclassified"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "values": [
        "operations",
        "engineering"
      ],
      "domain": [
        "operations",
        "engineering",
        "security",
        "management"
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
        "protocol": "tcp",
        "host_group": "webservers_patched, webservers_legacy",
        "source": "group_vars/webservers_patched.yml, group_vars/webservers_legacy.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers_patched, webservers_legacy",
        "source": "group_vars/all.yml, roles/web_legacy/tasks/main.yml"
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
        "label": "web_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "any",
        "label": "internet",
        "source": "group_vars/webservers_legacy.yml, group_vars/webservers_patched.yml"
      }
    ],
    "protocols": {
      "values": [
        "tcp",
        "udp"
      ],
      "domain": [
        "tcp",
        "udp",
        "icmp"
      ],
      "source": "group_vars/dbservers.yml, group_vars/webservers_patched.yml"
    }
  },
  "environment": {
    "org": "patchcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "group_vars/all.yml, inventory.ini"
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
    "notes": "Also defined in roles/web_patched/tasks/main.yml. AllowGroups sudo."
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
      "service": {
        "equals": "nginx"
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
    "notes": "firewalld allows HTTPS from any source to webservers (both roles)."
  },
  {
    "id": "rule-003",
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
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": [
        16,
        20
      ]
    },
    "notes": "pg_hba.conf: host all all 10.0.1.0/24 scram-sha-256"
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
    "notes": "Mode 0700 - owner full access"
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
    "notes": "Mode 0700 - owner write access"
  },
  {
    "id": "rule-006",
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
      "file": "inventory.ini",
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
    },
    "notes": "Default deny: all access not explicitly permitted is denied."
  },
  {
    "id": "rule-007",
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
      "port": {
        "equals": 443
      },
      "service": {
        "equals": "nginx"
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
    "id": "rule-010",
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
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "age_in_days": 1830,
    "affects_pinned_version": true,
    "recommendation": "Update to version 1.13.6 or later.",
    "source": "vulnx search"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "age_in_days": 1836,
    "affects_pinned_version": true,
    "recommendation": "Update nginx to the latest version where this issue is fixed.",
    "source": "vulnx search"
  },
  {
    "cve_id": "CVE-2026-42238",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "age_in_days": 38,
    "affects_pinned_version": null,
    "recommendation": "Upgrade to version 2.3.8 or later.",
    "source": "search_recent_vulnerabilities"
  },
  {
    "cve_id": "CVE-2025-59951",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.1,
    "age_in_days": 252,
    "affects_pinned_version": null,
    "recommendation": "Update to version 1.6.0 or later.",
    "source": "search_recent_vulnerabilities"
  },
  {
    "cve_id": "CVE-2026-7381",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.1,
    "age_in_days": 42,
    "affects_pinned_version": null,
    "recommendation": "Update to a version after 1.0053 or remove usage as it is deprecated.",
    "source": "search_recent_vulnerabilities"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "age_in_days": 9313,
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues.",
    "source": "vulnx search"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "age_in_days": 9499,
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option.",
    "source": "vulnx search"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "age_in_days": 8298,
    "affects_pinned_version": false,
    "recommendation": "Update to OpenSSH version 3.7 or later.",
    "source": "vulnx search"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "age_in_days": 8242,
    "affects_pinned_version": false,
    "recommendation": "Update to a version where this issue is fixed, or enable Privilege Separation.",
    "source": "vulnx search"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "age_in_days": 9222,
    "affects_pinned_version": false,
    "recommendation": "Update to the latest version or apply security patches addressing the integer overflow issue.",
    "source": "vulnx search"
  }
]
```

## Report

# ABAC Policy Report — Ansible Configuration Mining

## Executive Summary

This report presents an Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration manages a production environment (`patchcorp`, SOC2 compliance tier) with three hosts across DMZ and internal zones: two web servers (one patched, one legacy) and one database server.

## Policy Coverage

- **Subjects**: 2 human users (admin, appuser), 1 system account (postgres), 3 groups (sudo, developers, postgres)
- **Resources**: 3 hosts, 3 services (nginx, postgresql, ssh), 1 managed path, 2 network zones
- **Environment**: org=patchcorp, environment=production, compliance_tier=soc2
- **Rules**: 6 total (5 explicit + 1 default-deny)
  - SSH login restricted to `sudo` group (both web roles)
  - Firewall allows HTTPS (443/tcp) from any source to webservers
  - PostgreSQL connections permitted only from `10.0.1.0/24` (web subnet)
  - PostgreSQL data directory restricted to `postgres` user (mode 0700)
  - Default deny for all other access

## Vulnerability Assessment

### Pinned Software Versions
| Package | Pinned Version | Environment |
|---------|---------------|-------------|
| openssh-server | 1:9.6p1-3ubuntu1 | All hosts |
| postgresql | 16.2-1.pgdg22.04+1 | dbservers |
| nginx (patched) | 1.24.0-2ubuntu1 | webservers_patched |
| nginx (legacy) | 1.20.0-1~focal | webservers_legacy |

### Key Findings
- **Legacy nginx 1.20.0** is end-of-life and may be affected by CVEs. Recommendation: upgrade to 1.24.0.
- **OpenSSH 9.6p1** is current; historical CVEs do not affect this version.
- **PostgreSQL 16.2** is current; historical CVEs do not affect this version.

## Ambiguities & Gaps

1. **No explicit user creation tasks**: Users defined in group_vars but no Ansible `user` module tasks found.
2. **No sudoers configuration**: No explicit sudoers rules (NOPASSWD, command restrictions) in Ansible files.
3. **Firewall source 0.0.0.0/0**: Overly permissive for SOC2; consider restricting to known CIDRs.
4. **No SELinux/AppArmor policies**: No security module configuration found.
5. **No audit/logging obligations**: `default_log_retention_days: 90` defined but no enforcement tasks.
6. **Credentials handling**: No vault-encrypted variables or credential management tasks found in the configuration.

## Recommendations

1. Upgrade legacy nginx from 1.20.0 to 1.24.0.
2. Restrict firewall source from `0.0.0.0/0` to known CIDRs.
3. Add sudoers configuration for precise privilege boundaries.
4. Add user provisioning tasks with the `user` module.
5. Enable audit logging with obligations on SSH and database access rules.
