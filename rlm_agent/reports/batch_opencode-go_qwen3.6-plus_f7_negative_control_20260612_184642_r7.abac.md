# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:55:35_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 12_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

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
        "groups": [],
        "department": null,
        "clearance": null,
        "source": "roles/db/tasks/main.yml",
        "type": "system"
      }
    ],
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
    },
    "source_networks": {
      "domain": [
        "10.0.1.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "source_zones": {
      "domain": [
        "internal",
        "external",
        "dmz"
      ],
      "source": "inventory.ini"
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers",
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
        "host_group": "webservers",
        "source": "group_vars/webservers.yml"
      },
      {
        "name": "openssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
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
        "zone": "internal",
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "labcorp",
      "domain": [
        "labcorp"
      ],
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
        "pci",
        "hipaa"
      ],
      "source": "group_vars/all.yml"
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
      "service": {
        "equals": "postgresql"
      },
      "role": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        16,
        21
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "role": {
        "equals": "NOSUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        23,
        28
      ]
    }
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        30,
        34
      ]
    }
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        31,
        37
      ]
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
        "equals": "openssh"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        39,
        42
      ]
    }
  },
  {
    "id": "rule-006",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "obligations": [
      {
        "nopassword": false
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        22,
        29
      ]
    }
  },
  {
    "id": "rule-007",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        13,
        20
      ]
    }
  },
  {
    "id": "rule-008",
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
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
      "lines": [
        0,
        0
      ]
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
  },
  {
    "id": "rule-012",
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
    "cvss_score": 9.8,
    "is_remote": true,
    "age_in_days": 1577,
    "pinned_version": "1.27.0",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 1.27.0 is not affected. Affects nginx njs module through 0.7.0; nginx 1.27.0 bundles a much newer njs version"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "cvss_score": 9.8,
    "is_remote": true,
    "age_in_days": 3768,
    "pinned_version": "1.27.0",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 1.27.0 is not affected. CVSD predates pinned version 1.27.0 by many years; patched in current release"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "cvss_score": 9.8,
    "is_remote": true,
    "age_in_days": 1830,
    "pinned_version": "1.27.0",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 1.27.0 is not affected. Affects nginx versions before 1.13.6; pinned version 1.27.0 is not affected"
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "cvss_score": 9.8,
    "is_remote": true,
    "age_in_days": 6058,
    "pinned_version": "1.27.0",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 1.27.0 is not affected. CVSD predates pinned version 1.27.0 by many years; patched in current release"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "cvss_score": 7.7,
    "is_remote": true,
    "age_in_days": 1836,
    "pinned_version": "1.27.0",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 1.27.0 is not affected. Affects nginx versions before 1.21.0; pinned version 1.27.0 is not affected"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "cvss_score": 10.0,
    "is_remote": true,
    "age_in_days": 9500,
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 9.9p1 is not affected. CVSD predates pinned version 9.9p1 by many years; patched in current release"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "cvss_score": 10.0,
    "is_remote": true,
    "age_in_days": 9223,
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 9.9p1 is not affected. CVSD predates pinned version 9.9p1 by many years; patched in current release"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "cvss_score": 10.0,
    "is_remote": true,
    "age_in_days": 9314,
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 9.9p1 is not affected. CVSD predates pinned version 9.9p1 by many years; patched in current release"
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "cvss_score": 10.0,
    "is_remote": true,
    "age_in_days": 8745,
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 9.9p1 is not affected. CVSD predates pinned version 9.9p1 by many years; patched in current release"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "cvss_score": 10.0,
    "is_remote": true,
    "age_in_days": 8243,
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 9.9p1 is not affected. CVSD predates pinned version 9.9p1 by many years; patched in current release"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "cvss_score": 10.0,
    "is_remote": true,
    "age_in_days": 8546,
    "pinned_version": "16.4",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 16.4 is not affected. CVSD predates pinned version 16.4 by many years; patched in current release"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "cvss_score": 10.0,
    "is_remote": true,
    "age_in_days": 4815,
    "pinned_version": "16.4",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 16.4 is not affected. CVSD predates pinned version 16.4 by many years; patched in current release"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "cvss_score": 10.0,
    "is_remote": true,
    "age_in_days": 6931,
    "pinned_version": "16.4",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 16.4 is not affected. CVSD predates pinned version 16.4 by many years; patched in current release"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "cvss_score": 10.0,
    "is_remote": true,
    "age_in_days": 4815,
    "pinned_version": "16.4",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 16.4 is not affected. CVSD predates pinned version 16.4 by many years; patched in current release"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10.0,
    "is_remote": true,
    "age_in_days": 843,
    "pinned_version": "16.4",
    "affects_pinned_version": false,
    "recommendation": "No action required. Pinned version 16.4 is not affected. Affects postgresql_jdbc_driver (Java library), not the PostgreSQL server"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

Automated mining of Attribute-Based Access Control (ABAC) policies from the Ansible configuration at `$RLM_ANSIBLE_DIR`. The configuration manages a **production** environment for **labcorp** (compliance tier **soc2**) with two host groups: `webservers` (web01.lab.local, DMZ zone) and `dbservers` (db01.lab.local, internal zone).

## Phase 1: Attribute Catalog

### Subjects
| Name | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |
| postgres | system | — | — | — |

- **Groups**: sudo, developers
- **Clearance Levels**: secret, confidential
- **Departments**: operations, engineering

### Resources
| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| nginx | 443 | tcp | webservers |
| openssh | 22 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |

| Path | Owner | Group | Mode |
|------|-------|-------|------|
| /var/lib/postgresql/data | postgres | postgres | 0700 |

| Network | Zone | Label |
|---------|------|-------|
| 10.0.1.0/24 | internal | webservers_subnet |
| 0.0.0.0/0 | external | internet |

### Environment
- **Organization**: labcorp
- **Environment**: production
- **Compliance Tier**: soc2
- **Log Retention**: 90 days
- **Pinned Software**: nginx 1.27.0, OpenSSH 9.9p1, PostgreSQL 16.4

## Phase 2: Extracted ABAC Rules (9 total)

| ID | Action | Effect | Subject Condition | Resource Condition | Source |
|----|--------|--------|-------------------|-------------------|--------|
| rule-001 | db:login | permit | groups: sudo | postgresql (SUPERUSER) | roles/db/tasks/main.yml |
| rule-002 | db:login | permit | groups: developers | postgresql (NOSUPERUSER) | roles/db/tasks/main.yml |
| rule-003 | network:connect | permit | source_network: 10.0.1.0/24 | postgresql:5432 | roles/db/tasks/main.yml |
| rule-004 | network:connect | permit | source_network: 0.0.0.0/0 | nginx:443 | roles/web/tasks/main.yml |
| rule-005 | ssh:login | permit | groups: sudo | openssh:22 | roles/web/tasks/main.yml |
| rule-006 | sudo:execute | permit | groups: sudo, clearance: secret | all | roles/web/tasks/main.yml |
| rule-007 | user:create | permit | groups: sudo | all | roles/web/tasks/main.yml |
| rule-008 | filesystem:write | permit | groups: postgres | /var/lib/postgresql/data (0700) | roles/db/tasks/main.yml |
| rule-009 | * | deny | all | all | implicit (default-deny) |

## Phase 1.5: Vulnerability Assessment

### Pinned Package Versions
| Package | Pinned Version |
|---------|---------------|
| nginx | 1.27.0-1~noble |
| openssh-server | 1:9.9p1-3ubuntu1 |
| postgresql | 16.4-1.pgdg24.04+1 |

### Critical/Remote CVE Search Results (15 total)
| CVE | Product | CVSS | Age (days) | Affects Pinned? | Reason |
|-----|---------|------|------------|-----------------|--------|
| CVE-2024-1597 | postgresql | 10.0 | 843 | No | Affects postgresql_jdbc_driver (Java lib), not server |
| CVE-2021-46461 | nginx | 9.8 | 1577 | No | Affects njs module ≤ 0.7.0; 1.27.0 bundles newer |
| CVE-2021-23017 | nginx | 7.7 | 1836 | No | Affects nginx < 1.21.0 |
| CVE-2017-20005 | nginx | 9.8 | 1830 | No | Affects nginx < 1.13.6 |
| CVE-2016-0746 | nginx | 9.8 | 3768 | No | Pre-dates pinned version |
| CVE-2009-3555 | nginx | 9.8 | 6058 | No | Pre-dates pinned version |
| CVE-2000-0525 | openssh | 10.0 | 9500 | No | Pre-dates pinned version |
| CVE-2001-0144 | openssh | 10.0 | 9223 | No | Pre-dates pinned version |
| CVE-2000-0999 | openssh | 10.0 | 9314 | No | Pre-dates pinned version |
| CVE-2002-0640 | openssh | 10.0 | 8745 | No | Pre-dates pinned version |
| CVE-2003-0786 | openssh | 10.0 | 8243 | No | Pre-dates pinned version |
| CVE-2002-1399 | postgresql | 10.0 | 8546 | No | Pre-dates pinned version |
| CVE-2013-1902 | postgresql | 10.0 | 4815 | No | Pre-dates pinned version |
| CVE-2007-3279 | postgresql | 10.0 | 6931 | No | Pre-dates pinned version |
| CVE-2013-1903 | postgresql | 10.0 | 4815 | No | Pre-dates pinned version |

### KEV (Known Exploited Vulnerabilities) Summary
- **nginx**: 2 KEV entries found
- **openssh**: 5 KEV entries found
- **postgresql**: 3 KEV entries found

All KEV entries predate the pinned versions and are patched in current releases.

### Conclusion
**No actionable vulnerabilities** — all 15 critical/remote CVEs and all KEV entries affect versions that are significantly older than the pinned releases. The configuration uses up-to-date software.

## Ambiguities and Notes

1. **Credentials**: PostgreSQL authentication uses `scram-sha-256` (explicit in pg_hba task). No plaintext passwords or credential files were found in the configuration.
2. **Implicit Denies**: SSH `AllowGroups sudo` implicitly denies all non-sudo users. PostgreSQL pg_hba uses an explicit allow list with implicit deny for other sources. Both are captured by the default-deny rule (rule-009).
3. **Obligations**: The sudoers configuration includes `nopassword: false`, captured as an obligation on rule-006. No session logging or audit scripts were found.
4. **Network Exposure**: Firewall rule (rule-004) permits HTTPS from 0.0.0.0/0, which is required for the internet-facing webserver but should be monitored.
5. **No Dedicated Security Templates**: No standalone iptables, sshd_config, pg_hba, or selinux template files exist — all security configuration is embedded in role tasks.
6. **Postgres as System Subject**: The `postgres` system user was added to the subject catalog based on its use in filesystem ACLs (roles/db/tasks/main.yml).
