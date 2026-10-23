# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 00:48:30_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 8 | Rules: 14_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "type": "string",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "dba",
        "developers",
        "sudo"
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
        "data",
        "engineering",
        "operations"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "type": "string",
      "domain": [
        "0.0.0.0/0",
        "10.0.1.0/24",
        "10.0.2.0/24"
      ],
      "source": "group_vars/*.yml"
    },
    "source_zone": {
      "type": "string",
      "domain": [
        "dmz",
        "app",
        "internet"
      ],
      "source": "group_vars/*.yml"
    },
    "source_ip": {
      "type": "string",
      "source": "inventory.ini"
    },
    "applies_to": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "default-deny"
    }
  },
  "resources": {
    "hostname": {
      "type": "string",
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "source": "inventory.ini"
    },
    "role": {
      "type": "string",
      "domain": [
        "application",
        "primary",
        "reverse_proxy"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "string",
      "domain": [
        "app",
        "data",
        "dmz"
      ],
      "source": "inventory.ini"
    },
    "inventory_group": {
      "type": "string",
      "domain": [
        "appservers",
        "dbservers",
        "dmz"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "string",
      "domain": [
        "app",
        "postgres",
        "https"
      ],
      "source": "group_vars/*.yml"
    },
    "port": {
      "type": "integer",
      "domain": [
        443,
        5432,
        8080
      ],
      "source": "group_vars/*.yml"
    },
    "path": {
      "type": "string",
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "owner": {
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "string",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "privilege": {
      "type": "string",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "applies_to": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "default-deny"
    },
    "cidr": {
      "type": "string",
      "domain": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/*.yml"
    }
  },
  "environment": {
    "org": {
      "type": "string",
      "domain": [
        "segcorp"
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
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "integer",
      "domain": [
        365
      ],
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
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "24-28"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "41-45"
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dmz"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-14"
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
      "inventory_group": {
        "equals": "dmz"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "13-20"
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
      "port": {
        "equals": 8080
      },
      "service": {
        "equals": "app"
      },
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-22"
    }
  },
  {
    "id": "rule-007",
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
        "equals": "https"
      },
      "inventory_group": {
        "equals": "dmz"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "22-28"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "privilege": {
        "equals": "SUPERUSER"
      },
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "21-26"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "privilege": {
        "equals": "NOSUPERUSER"
      },
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "28-33"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "all"
      },
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "35-39"
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
      "database": {
        "equals": "all"
      },
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "35-39"
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
    "action": "*",
    "effect": "deny",
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "source": {
      "file": "group_vars/all.yml",
      "task": "default-deny",
      "lines": "1-5"
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
        "equals": 8080
      },
      "service": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
      "service": {
        "equals": "https"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.7,
    "severity": "high",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply the vendor patch or upgrade to a fixed version immediately."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.5,
    "severity": "high",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: This is a Known Exploited Vulnerability. Patch immediately."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: This is a Known Exploited Vulnerability. Patch immediately."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 8.1,
    "severity": "high",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: This is a Known Exploited Vulnerability. Patch immediately."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 7.5,
    "severity": "high",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 7.2,
    "severity": "high",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 7.1,
    "severity": "high",
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version not affected or CVE is patched."
  }
]
```

## Report

# ABAC Policy Mining Report

## Summary
Mined an ABAC policy from the Ansible configuration for `segcorp` production environment (PCI compliance tier). The configuration defines three host groups (dmz, appservers, dbservers), three human users (admin, developer, dba), and pinned software versions (nginx 1.20.0, openssh 9.1p1, postgresql 16.2).

## Attribute Catalog
- **Subjects**: 3 human users (admin, developer, dba), groups (sudo, developers, dba), clearance levels (confidential, secret), departments (operations, engineering, data), plus network-layer attributes (source_network, source_zone, source_ip).
- **Resources**: 3 hosts (proxy01.lab.local, app01.lab.local, db01.lab.local), services (app/8080, postgres/5432, https/443), database objects (`all`), and paths (`/var/lib/postgresql/data`).
- **Environment**: org `segcorp`, environment `production`, compliance tier `pci`, default log retention 365 days.

## Rules Extracted
- **12 ABAC rules** were extracted from the three security-relevant role task files.
- **SSH login**: `sudo` and `developers` are permitted on appservers; `sudo` and `dba` are permitted on dbservers; `sudo` is permitted on dmz.
- **User provisioning**: `developers` and `sudo` groups are provisioned on appservers; `sudo` group is provisioned on dmz.
- **Network connectivity**: DMZ subnet (`10.0.1.0/24`) can reach appservers on port 8080; internet (`0.0.0.0/0`) can reach dmz on port 443; appservers subnet (`10.0.2.0/24`) can reach dbservers on postgres (permit via pg_hba).
- **Database authentication**: `dba` group receives `SUPERUSER` login on dbservers; `developers` group receives `NOSUPERUSER` login on dbservers.
- **Implicit deny**: An explicit deny rule for all other source networks to dbservers (pg_hba default), and a global default-deny catch-all.

## Vulnerabilities
- **22 CVEs** were evaluated for the pinned packages.
- **4 CVEs affect the pinned versions**:
  - **CVE-2021-23017** (nginx 1.20.0, CVSS 7.7, High) — DNS resolver vulnerability. **Recommendation**: Apply patch or upgrade.
  - **CVE-2023-44487** (nginx 1.20.0, CVSS 7.5, High, KEV) — HTTP/2 Rapid Reset. **Recommendation**: Patch immediately.
  - **CVE-2023-38408** (openssh 9.1p1, CVSS 9.8, Critical, KEV) — Agent forwarding double-free. **Recommendation**: Patch immediately.
  - **CVE-2024-6387** (openssh 9.1p1, CVSS 8.1, High, KEV) — regreSSHion. **Recommendation**: Patch immediately.
- The remaining 18 CVEs are either for unrelated products (e.g., pgjdbc, njs) or affect versions older than the pinned ones.

## Ambiguities
- **Filesystem ACL**: The postgres data directory (`/var/lib/postgresql/data`) is owned by system user `postgres` with mode `0700`. Because `postgres` is not listed in the human `users` catalog, no filesystem access rule could be extracted without inventing a subject.
- **Sudoers**: No explicit sudoers template or `NOPASSWD` granularity is present in the Ansible tasks; only SSH group restrictions are defined.
- **Session logging / obligations**: No audit scripts or session logging tasks are present in the role files.
- **Credentials**: No explicit credential management (e.g., `ansible-vault`, `copy` with secrets) is present in the security-relevant files; authentication is configured via `scram-sha-256` in pg_hba.
