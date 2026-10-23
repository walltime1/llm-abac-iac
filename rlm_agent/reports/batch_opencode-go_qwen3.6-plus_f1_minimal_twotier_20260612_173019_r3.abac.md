# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:38:21_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 10 | Rules: 11_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f1_minimal_twotier`_

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
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "group_vars/all.yml"
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [
          "postgres"
        ],
        "clearance": null,
        "department": null,
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "postgres"
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
    "source_network": {
      "description": "Source IP/CIDR for network-layer rules",
      "domain": [
        "10.0.1.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/dbservers.yml, group_vars/webservers.yml"
    },
    "source_ip": {
      "description": "Source IP address for network-layer rules",
      "domain": [],
      "source": "inventory.ini"
    },
    "source_zone": {
      "description": "Source network zone for network-layer rules",
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
        "name": "http",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "group_vars/webservers.yml"
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
        "host_group": "webservers",
        "source": "roles/web/tasks/main.yml"
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
        "path": "/var/www/html",
        "owner": "root",
        "group": "root",
        "mode": "0755",
        "service": "http",
        "source": "group_vars/webservers.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "internal",
        "label": "webservers-subnet",
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
        "pci-dss",
        "hipaa",
        "none"
      ],
      "source": "group_vars/all.yml"
    },
    "retention": {
      "default_log_retention_days": 90,
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
    "description": "Allow SSH login for users in sudo group on webservers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        39,
        43
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Grant sudo execute privileges to admin users with secret clearance",
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
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
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
    "rule_id": "rule-003",
    "description": "Grant PostgreSQL SUPERUSER login to users in sudo group",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
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
    "rule_id": "rule-004",
    "description": "Grant PostgreSQL NOSUPERUSER (read-only) login to developers",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
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
    "rule_id": "rule-005",
    "description": "Allow PostgreSQL connections from webservers subnet (10.0.1.0/24)",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "permit",
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
    "rule_id": "rule-006",
    "description": "Deny PostgreSQL connections from networks other than webservers subnet",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet (implicit deny)",
      "lines": [
        30,
        34
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow HTTP connections from internet (0.0.0.0/0) to webservers",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": [
        31,
        37
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Grant postgres group full access to PostgreSQL data directory (mode 0700)",
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
      "compliance_tier": {
        "equals": "soc2"
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
    "rule_id": "rule-009",
    "description": "Default deny - all access not explicitly permitted is denied",
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
      "compliance_tier": {
        "equals": "soc2"
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
    "resource_condition": {
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
    "cve_id": "CVE-2013-2250",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Open For Business Project (OFBiz) versions 10.04.01 through 10.04.05, 11.04.01 through 11.04.02, and 12.04.01 contain a remote code execution c",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for apache pinned version 2.4.49. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2013-1777",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Geronimo 3.x before 3.0.1, used in IBM WebSphere Application Server Community Edition 3.0.0.3, contains a remote code execution caused by impro",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for apache pinned version 2.4.49. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2012-2379",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache CXF 2.4.x before 2.4.8, 2.5.x before 2.5.4, and 2.6.x before 2.6.1 contain a signature or encryption validation issue caused by improper handli",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for apache pinned version 2.4.49. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2013-4316",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Struts 2.0.0 through 2.3.15.1 enables Dynamic Method Invocation by default, causing unspecified impact and attack vectors, potentially leading ",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for apache pinned version 2.4.49. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2012-0838",
    "product": "apache",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "Apache Struts 2 before 2.2.3.1 contains an OGNL injection caused by evaluating a string as an expression during conversion error handling, letting rem",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for apache pinned version 2.4.49. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging ",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for openssh pinned version 9.6. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary comma",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for openssh pinned version 9.6. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrar",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for openssh pinned version 9.6. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbi",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for openssh pinned version 9.6. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privileg",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for openssh pinned version 9.6. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions,",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for postgresql pinned version 16.2. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers po",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for postgresql pinned version 16.2. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information d",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for postgresql pinned version 16.2. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for postgresql pinned version 16.2. Apply vendor security updates if applicable."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as",
    "affects_pinned_version": "unknown",
    "recommendation": "Review patch availability for postgresql pinned version 16.2. Apply vendor security updates if applicable."
  }
]
```

## Report

# ABAC Policy Report — Ansible Configuration Mining

## Scope
- **Policy Goal**: `all` (full coverage)
- **Source Directory**: RLM_ANSIBLE_DIR (Ansible root)
- **Files Analyzed**: 7 total (4 catalog files, 2 role task files, 1 README skipped)

## Phase 1 — Attribute Catalog Summary

### Subjects
- **Users**: 3 entries (`admin`, `appuser`, `postgres`)
- **Groups**: `sudo`, `developers`, `postgres`
- **Clearance Levels**: `secret`, `confidential`
- **Departments**: `operations`, `engineering`

### Resources
- **Hosts**: `web01.lab.local` (frontend/dmz), `db01.lab.local` (primary/internal)
- **Services**: `http` (80/tcp), `postgresql` (5432/tcp), `ssh` (22/tcp)
- **Paths**: `/var/lib/postgresql/data` (mode 0700), `/var/www/html` (mode 0755)
- **Networks**: `10.0.1.0/24` (internal/webservers-subnet), `0.0.0.0/0` (external/internet)

### Environment
- **Organization**: `labcorp`
- **Environment**: `production`
- **Compliance Tier**: `soc2`
- **Log Retention**: 90 days

## Phase 1.5 — Vulnerability Assessment

Three pinned packages were assessed: `apache` (2.4.49), `openssh` (9.6p1), `postgresql` (16.2).

- **Total CVEs collected**: 15 (after deduplication)
- **Products queried**: apache (5 CVEs), openssh (5 CVEs), postgresql (5 CVEs)
- **All CVEs flagged as CVSS 10** (per vulnx search results)

| Product | CVEs Found | Notes |
|---------|-----------|-------|
| apache | 5 | Includes CVE-2013-2250, CVE-2013-1777, etc. |
| openssh | 5 | Includes CVE-2000-0525, CVE-2003-0693, etc. |
| postgresql | 5 | Includes CVE-2007-3279, CVE-2013-1902, CVE-2024-1597 |

**Note**: `affects_pinned_version` is marked "unknown" for all entries because exact CPE-to-version mapping requires additional tooling. Recommendation: review vendor patch advisories for each pinned version.

## Phase 2–3 — Rule Extraction Summary

| Rule ID | Action | Effect | Subject | Resource | Source |
|---------|--------|--------|---------|----------|--------|
| rule-001 | ssh:login | permit | groups: sudo | ssh/webservers | roles/web/tasks/main.yml |
| rule-002 | sudo:execute | permit | groups: sudo, clearance: secret | webservers | roles/web/tasks/main.yml |
| rule-003 | db:login | permit | groups: sudo | postgresql/dbservers | roles/db/tasks/main.yml |
| rule-004 | db:login | permit | groups: developers | postgresql/dbservers | roles/db/tasks/main.yml |
| rule-005 | network:connect | permit | source_network: 10.0.1.0/24 | postgresql/5432 | roles/db/tasks/main.yml |
| rule-006 | network:connect | deny | source_network: 0.0.0.0/0 | postgresql/5432 | roles/db/tasks/main.yml |
| rule-007 | network:connect | permit | source_network: 0.0.0.0/0 | http/80/webservers | roles/web/tasks/main.yml |
| rule-008 | filesystem:write | permit | groups: postgres | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| rule-009 | * | deny | all | all | implicit |

**Total rules**: 9 (8 explicit + 1 default-deny)

## Phase 4 — Validation
- All attributes referenced in rules exist in the catalog ✓
- All operators use valid grammar (`equals`, `in`, `any_of`, `all_of`) ✓
- All effects are lowercase (`permit`, `deny`) ✓
- Default-deny uses correct `applies_to` sentinel ✓
- All JSON is valid (double-quoted, no Python literals) ✓

## Ambiguities & Limitations
1. **No session logging / audit obligations found**: No explicit PAM auditd, session logging, or profile.d audit scripts in the Ansible config. None attached to rules.
2. **No credentials/secret management**: No vault, lookup plugins, or credential tasks found. No `no_log: true` directives observed.
3. **PostgreSQL pg_hba deny is implicit**: The `lineinfile` task only adds allow entries; deny is a default PostgreSQL behavior, not an explicit Ansible task. Rule-006 represents this implicit deny.
4. **Version-to-CPE mapping not performed**: `affects_pinned_version` in vulnerability entries is "unknown" — manual verification against vendor advisories is recommended.
5. **SSH port assumed 22**: Not explicitly defined in group_vars; inferred from convention.
6. **No explicit user creation for postgres**: The `postgres` user is referenced as a system account for file ownership but not created via the `user` module in the playbooks.
7. **SELinux/AppArmor policies not found**: No seboolean, selinux, or AppArmor tasks in the configuration.
8. **Load balancer / HAProxy not present**: No routing or backend definition rules extracted.
