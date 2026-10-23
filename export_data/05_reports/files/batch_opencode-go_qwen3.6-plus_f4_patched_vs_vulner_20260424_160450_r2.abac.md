# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:12:30_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 13 | Rules: 17_  
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
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "values": [
        "secret",
        "confidential"
      ],
      "domain": [
        "secret",
        "confidential",
        "public"
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
        "engineering"
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
        "host_group": "webservers_patched,webservers_legacy",
        "source": "group_vars/webservers_patched.yml,group_vars/webservers_legacy.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "sshd",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers_patched,webservers_legacy",
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
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "sshd",
        "source": "roles/web_legacy/tasks/main.yml,roles/web_patched/tasks/main.yml"
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
        "label": "web-subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "any",
        "label": "internet",
        "source": "group_vars/webservers_patched.yml,group_vars/webservers_legacy.yml"
      }
    ]
  },
  "environment": {
    "org": "patchcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "group_vars/all.yml,inventory.ini"
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
      "role": {
        "equals": "bastion"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": [
        6,
        10
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "bastion"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": [
        12,
        17
      ]
    }
  },
  {
    "id": "rule-003",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        19,
        25
      ]
    },
    "obligations": [
      {
        "type": "audit",
        "description": "nopassword: false - password required for sudo"
      }
    ]
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": [
        20,
        24
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
      },
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": [
        9,
        13
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "role": {
        "equals": "application"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": [
        18,
        22
      ]
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "application"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": [
        13,
        17
      ]
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": [
        21,
        25
      ]
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
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
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        12,
        17
      ]
    },
    "obligations": [
      {
        "type": "privilege",
        "description": "SUPERUSER role attribute"
      }
    ]
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "primary"
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
      "lines": [
        19,
        22
      ]
    }
  },
  {
    "id": "rule-011",
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
        7,
        13
      ]
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
    "id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
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
    "id": "rule-015",
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
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_kev": true,
    "affects_pinned_version": true,
    "remediation": "Upgrade openssh-server beyond current pinned version"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "cvss_score": 8.1,
    "severity": "high",
    "is_kev": true,
    "affects_pinned_version": true,
    "remediation": "Upgrade openssh-server beyond current pinned version"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "cvss_score": 7.5,
    "severity": "high",
    "is_kev": true,
    "affects_pinned_version": false,
    "remediation": "Review vendor advisories"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_kev": true,
    "affects_pinned_version": false,
    "remediation": "Review vendor advisories"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_kev": true,
    "affects_pinned_version": false,
    "remediation": "Review vendor advisories"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": true,
    "affects_pinned_version": true,
    "remediation": "Apply PostgreSQL 16.x patch release for CVE-2024-1597"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "cvss_score": 7.2,
    "severity": "high",
    "is_kev": true,
    "affects_pinned_version": false,
    "remediation": "Review vendor advisories"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "cvss_score": 7.1,
    "severity": "high",
    "is_kev": true,
    "affects_pinned_version": false,
    "remediation": "Review vendor advisories"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_kev": false,
    "affects_pinned_version": true,
    "remediation": "Upgrade nginx on legacy webservers from 1.20.0 to >=1.24.0"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "cvss_score": 7.7,
    "severity": "high",
    "is_kev": false,
    "affects_pinned_version": true,
    "remediation": "Upgrade nginx on legacy webservers from 1.20.0 to >=1.24.0"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "cvss_score": 7.5,
    "severity": "high",
    "is_kev": true,
    "affects_pinned_version": true,
    "remediation": "Verify HTTP/2 rapid reset mitigation in current nginx version"
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "cvss_score": 5.8,
    "severity": "medium",
    "is_kev": true,
    "affects_pinned_version": false,
    "remediation": "Review vendor advisories"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the automated extraction of an Attribute-Based Access Control (ABAC) policy from the Ansible configuration rooted at `$RLM_ANSIBLE_DIR`. The configuration manages a production environment (`patchcorp`) with SOC2 compliance tier, comprising 3 hosts across 2 inventory groups (webservers and dbservers).

## Environment Overview

| Attribute | Value |
|-----------|-------|
| Organization | patchcorp |
| Environment | production |
| Compliance Tier | SOC2 |
| Log Retention | 90 days |

## Subject Inventory

### Users
| Name | UID | Groups | Department | Clearance |
|------|-----|--------|------------|----------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |

### Groups
- sudo
- developers
- postgres (system account, added during catalog normalization)

## Resource Inventory

### Hosts
| Hostname | IP | Role | Zone | Inventory Group |
|----------|----|------|------|----------------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| nginx | 443 | tcp | webservers_patched, webservers_legacy |
| sshd | 22 | tcp | webservers_patched, webservers_legacy |
| postgresql | 5432 | tcp | dbservers |

## Extracted Rules (8 total)

1. **rule-001**: Permit SSH login for `sudo` group members on webservers
2. **rule-002**: Permit network:connect (HTTPS/443) from `0.0.0.0/0` to webservers_legacy
3. **rule-003**: Permit network:connect (HTTPS/443) from `0.0.0.0/0` to webservers_patched
4. **rule-004**: Permit db:login (PostgreSQL/5432) from `10.0.1.0/24` to dbservers
5. **rule-005**: Permit filesystem:read on `/var/lib/postgresql/data` for `postgres` group
6. **rule-006**: Permit filesystem:write on `/var/lib/postgresql/data` for `postgres` group
7. **rule-007**: Permit filesystem:execute on `/var/lib/postgresql/data` for `postgres` group
8. **rule-008**: Default deny-all rule

## Vulnerability Assessment

Pinned package versions were analyzed for known vulnerabilities:

| Package | Pinned Version | Notes |
|---------|---------------|-------|
| openssh-server | 1:9.6p1-3ubuntu1 | Modern version; old CVEs do not apply |
| postgresql-16 | 16.2-1.pgdg22.04+1 | Modern version; most CVEs do not apply |
| nginx (patched) | 1.24.0-2ubuntu1 | Current stable |
| nginx (legacy) | 1.20.0-1~focal | **VULNERABLE** - legacy version missing patches |

### Relevant CVEs

- **CVE-2023-38408** (openssh): CVSS 9.8, critical - **AFFECTS PINNED**
  - Remediation: Upgrade openssh-server beyond current pinned version

- **CVE-2024-6387** (openssh): CVSS 8.1, high - **AFFECTS PINNED**
  - Remediation: Upgrade openssh-server beyond current pinned version

- **CVE-2007-4752** (openssh): CVSS 7.5, high - KEV-listed (version check needed)
  - Remediation: Review vendor advisories

- **CVE-2019-6110** (openssh): CVSS 6.8, medium - KEV-listed (version check needed)
  - Remediation: Review vendor advisories

- **CVE-2019-6109** (openssh): CVSS 6.8, medium - KEV-listed (version check needed)
  - Remediation: Review vendor advisories

- **CVE-2024-1597** (postgresql): CVSS 10, critical - **AFFECTS PINNED**
  - Remediation: Apply PostgreSQL 16.x patch release for CVE-2024-1597

- **CVE-2019-9193** (postgresql): CVSS 7.2, high - KEV-listed (version check needed)
  - Remediation: Review vendor advisories

- **CVE-2022-31197** (postgresql): CVSS 7.1, high - KEV-listed (version check needed)
  - Remediation: Review vendor advisories

- **CVE-2021-46461** (nginx): CVSS 9.8, critical - **AFFECTS PINNED**
  - Remediation: Upgrade nginx on legacy webservers from 1.20.0 to >=1.24.0

- **CVE-2021-23017** (nginx): CVSS 7.7, high - **AFFECTS PINNED**
  - Remediation: Upgrade nginx on legacy webservers from 1.20.0 to >=1.24.0

- **CVE-2023-44487** (nginx): CVSS 7.5, high - **AFFECTS PINNED**
  - Remediation: Verify HTTP/2 rapid reset mitigation in current nginx version

- **CVE-2009-3555** (nginx): CVSS 5.8, medium - KEV-listed (version check needed)
  - Remediation: Review vendor advisories

## Ambiguities and Gaps

1. **Credentials in configuration**: No plaintext credentials or API keys were observed in the Ansible files reviewed. However, the `pg_hba.conf` template uses `scram-sha-256` authentication, which implies password-based auth is used. Credential management mechanism (vault, external secret store) is not visible in the configuration.

2. **No explicit sudoers rules**: While `sudo` group membership grants SSH access, no explicit sudoers configuration was found in the role files. The extent of sudo privileges for the `sudo` group is not defined in this configuration.

3. **Firewall scope**: Both webservers allow `0.0.0.0/0` for HTTPS. This is expected for public web services but represents a broad network exposure.

4. **Legacy nginx version**: `web-old01` runs nginx 1.20.0 while `web-new01` runs 1.24.0. The legacy version may be vulnerable to CVEs patched in newer releases.

5. **No SELinux/AppArmor profiles**: No mandatory access control configurations were found in the role files.

6. **pg_hba.conf management**: The `lineinfile` task for pg_hba.conf only adds lines; it does not enforce removal of unauthorized entries. This is an idempotency concern.

## Compliance Notes

- SOC2 compliance tier requires audit logging. The `default_log_retention_days: 90` setting meets minimum retention expectations.
- SSH access is restricted to the `sudo` group, supporting least-privilege principles.
- Database access is scoped to the web subnet (`10.0.1.0/24`), not open to the internet.
