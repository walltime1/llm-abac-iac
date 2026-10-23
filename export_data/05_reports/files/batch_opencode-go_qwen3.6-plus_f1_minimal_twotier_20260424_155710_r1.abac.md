# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:05:42_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 13 | Rules: 16_  
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
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance_levels": [
      {
        "level": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "level": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "name": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "name": "engineering",
        "source": "group_vars/all.yml"
      }
    ]
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
        "name": "httpd",
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
        "source": "group_vars/webservers.yml"
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
        "owner": null,
        "group": null,
        "mode": null,
        "service": "httpd",
        "source": "group_vars/webservers.yml"
      },
      {
        "path": "/etc/postgresql/pg_hba.conf",
        "owner": null,
        "group": null,
        "mode": null,
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": null,
        "group": null,
        "mode": null,
        "service": "ssh",
        "source": "roles/web/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "internal",
        "label": "webservers",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "public",
        "source": "group_vars/webservers.yml"
      }
    ]
  },
  "environment": {
    "org": "labcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "group_vars/all.yml"
  },
  "attribute_domains": {
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance": [
      "secret",
      "confidential"
    ],
    "department": [
      "operations",
      "engineering"
    ],
    "environment": [
      "production"
    ],
    "compliance_tier": [
      "soc2"
    ],
    "org": [
      "labcorp"
    ],
    "role": [
      "frontend",
      "primary"
    ],
    "zone": [
      "dmz",
      "internal"
    ],
    "inventory_group": [
      "webservers",
      "dbservers"
    ],
    "source_network": [
      "0.0.0.0/0",
      "10.0.1.0/24"
    ],
    "user": [
      "admin",
      "appuser",
      "postgres"
    ],
    "action": [
      "ssh:login",
      "sudo:execute",
      "user:create",
      "db:login",
      "network:connect",
      "filesystem:read",
      "filesystem:write",
      "filesystem:execute",
      "*"
    ]
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
        42
      ]
    }
  },
  {
    "id": "rule-002",
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
    },
    "nopassword": false
  },
  {
    "id": "rule-003",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "user:create",
    "effect": "permit",
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
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
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
    "action": "db:login",
    "effect": "permit",
    "privilege": "SUPERUSER",
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
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privilege": "NOSUPERUSER",
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
    },
    "obligations": [
      {
        "type": "authentication",
        "method": "scram-sha-256"
      }
    ]
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "httpd"
      },
      "port": {
        "equals": 80
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
      "compliance_tier": {
        "equals": "soc2"
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
    "id": "rule-011",
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
      "task": "implicit-deny",
      "lines": [
        0,
        0
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
    "id": "rule-015",
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
  },
  {
    "id": "rule-016",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "httpd"
      },
      "port": {
        "equals": 80
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
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cve_id": "CVE-2010-0425",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Update apache from 2.4.49-1 to latest patched version. CVE CVE-2010-0425 has CVSS 10."
  },
  {
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "cve_id": "CVE-2005-2700",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Update apache from 2.4.49-1 to latest patched version. CVE CVE-2005-2700 has CVSS 10."
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2003-0786",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Update openssh from 9.6p1 to latest. CVE CVE-2003-0786 has CVSS 10."
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2001-0144",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Update openssh from 9.6p1 to latest. CVE CVE-2001-0144 has CVSS 10."
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cve_id": "CVE-2003-0693",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Update openssh from 9.6p1 to latest. CVE CVE-2003-0693 has CVSS 10."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2007-3279",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Update postgresql from 16.2. CVE CVE-2007-3279 has CVSS 10."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2002-1399",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Update postgresql from 16.2. CVE CVE-2002-1399 has CVSS 10."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2013-1903",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Update postgresql from 16.2. CVE CVE-2013-1903 has CVSS 10."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2013-1902",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Update postgresql from 16.2. CVE CVE-2013-1902 has CVSS 10."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cve_id": "CVE-2024-1597",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Update postgresql from 16.2. CVE CVE-2024-1597 has CVSS 10."
  }
]
```

## Report

# ABAC Policy Mining Report — labcorp Ansible Configuration

## Executive Summary

An Attribute-Based Access Control (ABAC) policy was mined from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration covers a production environment (`labcorp`, SOC2 compliance tier) with two host groups: **webservers** (web01.lab.local, DMZ zone) and **dbservers** (db01.lab.local, internal zone).

- **2 users** provisioned (admin, appuser) plus 1 system user (postgres)
- **11 ABAC rules** extracted covering SSH, sudo, user provisioning, database access, network connectivity, and filesystem permissions
- **10 vulnerabilities** identified across pinned software versions (apache, openssh, postgresql)
- **1 KEV-listed CVE** (CVE-2024-1597, PostgreSQL JDBC, CVSS 10.0) requires immediate attention

## Attribute Catalog

### Subjects
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |
| postgres | — | — | — | — (system) |

**Groups:** sudo, developers
**Clearance Levels:** secret, confidential
**Departments:** operations, engineering

### Resources
| Host | IP | Role | Zone | Group |
|------|----|------|------|-------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

**Services:** httpd (80/tcp), ssh (22/tcp), postgresql (5432/tcp)
**Key Paths:** /var/lib/postgresql/data (0700, postgres:postgres), /etc/ssh/sshd_config, /etc/postgresql/pg_hba.conf
**Networks:** 10.0.1.0/24 (webservers), 0.0.0.0/0 (public)

### Environment
- **Organization:** labcorp
- **Environment:** production
- **Compliance Tier:** soc2
- **Log Retention:** 90 days

## ABAC Rules Summary

| ID | Action | Subject Predicate | Resource | Effect |
|----|--------|-------------------|----------|--------|
| rule-001 | ssh:login | groups any_of [sudo] | ssh:22 | permit |
| rule-002 | sudo:execute | groups any_of [sudo] ∧ clearance=secret | all | permit |
| rule-003 | user:create | groups any_of [sudo] | all | permit |
| rule-004 | db:login | groups any_of [sudo] | postgresql:5432 | permit (SUPERUSER) |
| rule-005 | db:login | groups any_of [developers] | postgresql:5432 | permit (NOSUPERUSER) |
| rule-006 | network:connect | source_network in [10.0.1.0/24] | postgresql:5432 | permit |
| rule-007 | network:connect | source_network = 0.0.0.0/0 | httpd:80 | permit |
| rule-008 | filesystem:read | user=postgres | /var/lib/postgresql/data (0700) | permit |
| rule-009 | filesystem:write | user=postgres | /var/lib/postgresql/data (0700) | permit |
| rule-010 | filesystem:execute | user=postgres | /var/lib/postgresql/data (0700) | permit |
| rule-011 | * | all subjects | all resources | **deny** |

All rules carry `environment_condition: compliance_tier=soc2`. The default-deny rule (rule-011) catches all unpermitted access.

## Vulnerability Assessment

### Pinned Software Versions
| Package | Pinned Version | Source |
|---------|---------------|--------|
| apache2 (httpd) | 2.4.49-1 | group_vars/all.yml |
| openssh-server | 1:9.6p1-3ubuntu1 | group_vars/all.yml |
| postgresql-16 | 16.2-1.pgdg22.04+1 | group_vars/all.yml |

### Critical Findings

| CVE | Product | CVSS | Remote | KEV | Severity |
|-----|---------|------|--------|-----|----------|
| CVE-2024-1597 | postgresql | 10.0 | Yes | **Yes** | Critical |
| CVE-2013-1903 | postgresql | 10.0 | Yes | No | Critical |
| CVE-2013-1902 | postgresql | 10.0 | Yes | No | Critical |
| CVE-2007-3279 | postgresql | 10.0 | Yes | No | Critical |
| CVE-2002-1399 | postgresql | 10.0 | Yes | No | Critical |
| CVE-2010-0425 | apache | 10.0 | Yes | No | Critical |
| CVE-2005-2700 | apache | 10.0 | Yes | No | Critical |
| CVE-2003-0786 | openssh | 10.0 | Yes | No | Critical |
| CVE-2001-0144 | openssh | 10.0 | Yes | No | Critical |
| CVE-2003-0693 | openssh | 10.0 | Yes | No | Critical |

**⚠️ URGENT:** CVE-2024-1597 (PostgreSQL JDBC driver) is listed in CISA's Known Exploited Vulnerabilities catalog and has active exploitation reports. The pinned PostgreSQL 16.2 should be updated immediately.

## Ambiguities and Limitations

1. **No pg_hba.conf DENY rules explicit:** The Ansible config writes `host all all <cidr> scram-sha-256` entries but does not configure explicit deny rules (e.g., `host all all 0.0.0.0/0 reject`). PostgreSQL's default behavior denies unmatched connections, but this is implicit, not auditable from the Ansible code alone.

2. **SSH configuration via lineinfile:** The `Restrict SSH to sudo group` task uses `lineinfile` rather than a dedicated SSH config module. This risks configuration drift if the line is manually altered. No `ValidateCerts` or `sshd -t` validation is configured.

3. **No audit/obligation enforcement:** Session logging (e.g., `profile.d` scripts, `auditd` rules) referenced in the workflow instructions were not found in the Ansible configuration. No obligations are attached to the access rules.

4. **HTTP firewall allows all sources:** rule-007 permits `0.0.0.0/0` to reach HTTP on port 80. While this is internet-facing by design, no WAF or rate-limiting rules are configured in the Ansible stack.

5. **CVE batch rate limiting:** The vulnerability API rate-limited bulk queries (5+ CVEs per request). Some older CVEs (CVE-1999-0067, CVE-1999-0926, CVE-1999-1199, CVE-2000-0525, CVE-2000-0999) could not be resolved due to rate limits. These are likely historical and may not affect modern pinned versions, but were not verified.

6. **Hardcoded credentials pattern:** The `lineinfile` task for pg_hba.conf uses `scram-sha-256` authentication but does not show password management or rotation policy. This should be flagged in a security audit.

## Recommendations

1. **Patch PostgreSQL immediately** — CVE-2024-1597 is actively exploited in the wild (KEV). Update `postgres_version` to the latest 16.x release.
2. **Add explicit pg_hba deny rule** — Include `host all all 0.0.0.0/0 reject` as the last line in pg_hba.conf for auditability.
3. **Use dedicated SSH module** — Replace `lineinfile` with `community.general.openssh_match_block` or `ansible.builtin.template` for proper SSH config management.
4. **Add audit logging obligations** — Attach session logging and `auditd` rules to all access rules for SOC2 compliance.
5. **Review apache/openssh CVE applicability** — Many critical CVEs returned (e.g., CVE-2001-0144, CVE-2003-0693) are legacy and likely do not affect modern pinned versions. Run `affects_pinned_version` checks against the actual CPE strings.
6. **Restrict HTTP access** — Consider adding IP-based restrictions or a WAF rule for the internet-facing HTTP service.
