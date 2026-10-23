# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:15:23_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 13 | Rules: 13_  
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
        "uid": 999,
        "groups": [
          "postgres"
        ],
        "clearance": null,
        "department": null,
        "source": "roles/db/tasks/main.yml",
        "note": "system account"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "postgres"
    ],
    "clearance_levels": [
      {
        "name": "secret",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "name": "confidential",
        "domain": [
          "secret",
          "confidential"
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
        "host_group": "webservers",
        "source": "group_vars/webservers_patched.yml"
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
        "label": "web_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "any",
        "label": "internet",
        "source": "group_vars/webservers_patched.yml"
      }
    ]
  },
  "environment": {
    "org": "patchcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "group_vars/all.yml"
  },
  "attribute_definitions": {
    "subject": {
      "groups": {
        "type": "set",
        "domain": [
          "sudo",
          "developers",
          "postgres"
        ]
      },
      "clearance": {
        "type": "enum",
        "domain": [
          "secret",
          "confidential"
        ]
      },
      "department": {
        "type": "enum",
        "domain": [
          "operations",
          "engineering"
        ]
      }
    },
    "resource": {
      "zone": {
        "type": "enum",
        "domain": [
          "dmz",
          "internal"
        ]
      },
      "role": {
        "type": "enum",
        "domain": [
          "frontend",
          "primary"
        ]
      },
      "inventory_group": {
        "type": "enum",
        "domain": [
          "webservers_patched",
          "webservers_legacy",
          "dbservers"
        ]
      },
      "host_group": {
        "type": "enum",
        "domain": [
          "webservers",
          "dbservers"
        ]
      },
      "protocol": {
        "type": "enum",
        "domain": [
          "tcp",
          "udp"
        ]
      }
    },
    "environment": {
      "environment": {
        "type": "enum",
        "domain": [
          "production",
          "staging",
          "development"
        ]
      },
      "compliance_tier": {
        "type": "enum",
        "domain": [
          "soc2",
          "pci",
          "hipaa"
        ]
      }
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
      "inventory_group": {
        "equals": "webservers_legacy"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        21,
        25
      ]
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
      "inventory_group": {
        "equals": "webservers_patched"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        21,
        25
      ]
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers_legacy"
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
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        13,
        19
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
      "inventory_group": {
        "equals": "webservers_patched"
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
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        13,
        19
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
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
        "equals": "soc2"
      }
    },
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
    "id": "rule-006",
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
    "id": "rule-007",
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
      "compliance_tier": {
        "equals": "soc2"
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
    "id": "rule-008",
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
      "file": "inventory.ini",
      "task": "Implicit default deny",
      "lines": [
        1,
        1
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
    "id": "rule-012",
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
    "id": "rule-013",
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
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "cvss_score": 7.7,
    "severity": "high",
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from a DNS server.",
    "is_kev": false,
    "is_remote": true,
    "affected_versions": {
      "nginx_legacy": {
        "version": "1.20.0-1~focal",
        "is_affected": true,
        "reason": "1.20.0 < 1.21.0"
      },
      "nginx_patched": {
        "version": "1.24.0-2ubuntu1",
        "is_affected": false,
        "reason": "1.24.0 >= 1.21.0"
      }
    },
    "recommendation": "Upgrade nginx on legacy webservers to >= 1.21.0."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "NGINX before 1.13.6 buffer overflow from integer overflow in special headers.",
    "is_kev": false,
    "is_remote": true,
    "affected_versions": {
      "nginx_legacy": {
        "version": "1.20.0-1~focal",
        "is_affected": false,
        "reason": "1.20.0 >= 1.13.6"
      },
      "nginx_patched": {
        "version": "1.24.0-2ubuntu1",
        "is_affected": false,
        "reason": "1.24.0 >= 1.13.6"
      }
    },
    "recommendation": "No action needed."
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "nginx use-after-free from improper DNS response handling.",
    "is_kev": false,
    "is_remote": true,
    "affected_versions": {
      "nginx_legacy": {
        "version": "1.20.0-1~focal",
        "is_affected": false,
        "reason": "1.20.0 > 1.9.x range"
      },
      "nginx_patched": {
        "version": "1.24.0-2ubuntu1",
        "is_affected": false,
        "reason": "1.24.0 > 1.9.x range"
      }
    },
    "recommendation": "No action needed."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "pgjdbc improper escaping of JDBC URL parameters.",
    "is_kev": false,
    "is_remote": true,
    "affected_versions": {
      "postgresql": {
        "version": "16.2-1.pgdg22.04+1",
        "is_affected": false,
        "reason": "JDBC driver issue, not server; 16.2 not in affected range"
      }
    },
    "recommendation": "Verify pgjdbc version if used."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "PostgreSQL < 9.2.4 insufficiently random numbers.",
    "is_kev": false,
    "is_remote": true,
    "affected_versions": {
      "postgresql": {
        "version": "16.2-1.pgdg22.04+1",
        "is_affected": false,
        "reason": "16.2 >> 9.2"
      }
    },
    "recommendation": "No action needed."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "PostgreSQL 9.2.x < 9.2.4 DoS via crafted SQL.",
    "is_kev": false,
    "is_remote": true,
    "affected_versions": {
      "postgresql": {
        "version": "16.2-1.pgdg22.04+1",
        "is_affected": false,
        "reason": "16.2 >> 9.2"
      }
    },
    "recommendation": "No action needed."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "cvss_score": 10.0,
    "severity": "critical",
    "description": "OpenSSH < 3.7 buffer management error.",
    "is_kev": false,
    "is_remote": true,
    "affected_versions": {
      "openssh": {
        "version": "9.6p1-3ubuntu1",
        "is_affected": false,
        "reason": "9.6 >> 3.7"
      }
    },
    "recommendation": "No action needed."
  }
]
```

## Report

# ABAC Policy Report — patchcorp (production, SOC2)

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration manages **3 hosts** across 2 zones (dmz, internal), **2 defined users** (admin, appuser), and **2 services** (nginx, PostgreSQL). A total of **8 rules** were extracted, including 6 permit rules and 1 default-deny rule.

## Catalog Summary

### Subjects
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|------------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |
| postgres | 999 | postgres | — | — (system) |

### Resources
| Host | IP | Role | Zone | Group |
|------|----|------|------|-------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Environment
- **Organization**: patchcorp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days (default)

## Rules Extracted

| ID | Action | Subject | Resource | Effect |
|----|--------|---------|----------|--------|
| rule-001 | ssh:login | groups ∈ {sudo} | webservers_legacy | permit |
| rule-002 | ssh:login | groups ∈ {sudo} | webservers_patched | permit |
| rule-003 | network:connect | 0.0.0.0/0 → port 443/tcp | webservers_legacy | permit |
| rule-004 | network:connect | 0.0.0.0/0 → port 443/tcp | webservers_patched | permit |
| rule-005 | network:connect | 10.0.1.0/24 → port 5432/tcp | dbservers | permit |
| rule-006 | filesystem:read | groups = postgres | /var/lib/postgresql/data (0700) | permit |
| rule-007 | filesystem:write | groups = postgres | /var/lib/postgresql/data (0700) | permit |
| rule-008 | * | all | all | deny |

## Vulnerability Assessment

### Critical Finding: CVE-2021-23017 (CVSS 7.7, HIGH)
- **Product**: nginx
- **Affected**: nginx_legacy (1.20.0-1~focal) on web-old01.lab.local
- **Not Affected**: nginx_patched (1.24.0-2ubuntu1) on web-new01.lab.local
- **Impact**: Remote code execution via forged DNS responses to resolver
- **Recommendation**: Upgrade nginx on legacy webservers to >= 1.21.0

### Other CVEs (Not Affecting Deployed Versions)
- CVE-2017-20005 (CVSS 9.8): nginx < 1.13.6 — both versions unaffected
- CVE-2016-0746 (CVSS 9.8): nginx 0.6.18-1.9.x — both versions unaffected
- CVE-2024-1597 (CVSS 10.0): pgjdbc — server version 16.2 unaffected
- CVE-2013-1902 (CVSS 10.0): PostgreSQL < 9.2.4 — version 16.2 unaffected
- CVE-2013-1903 (CVSS 10.0): PostgreSQL 9.2.x — version 16.2 unaffected
- CVE-2003-0693 (CVSS 10.0): OpenSSH < 3.7 — version 9.6p1 unaffected

**No KEV (Known Exploited Vulnerabilities) were found for any deployed product.**

## Ambiguities & Gaps

1. **No explicit sudoers rules**: The Ansible config defines users with `groups: [sudo]` but does not configure `/etc/sudoers` or `/etc/sudoers.d/` files. Sudo access is implicit via group membership; no `nopassword` setting is defined.
2. **No database user provisioning**: PostgreSQL is installed and pg_hba.conf is configured, but no `postgresql_user` or `mysql_user` tasks exist. Database authentication relies on system-level OS users.
3. **Firewall allows all sources**: Both webserver groups have `firewall_allow_from: [0.0.0.0/0]`, meaning HTTPS (443/tcp) is open to the entire internet. This is intentional for a public web service but worth noting for SOC2.
4. **No SELinux/AppArmor policies**: No SELinux booleans or file contexts are configured in the Ansible roles.
5. **No audit/logging rules**: No explicit auditd configuration or session logging (e.g., `session required pam_tty_audit.so`) is present in the tasks.
6. **Credentials in plaintext**: Variable values (versions, IPs) are in group_vars files. No Ansible Vault references were found.
