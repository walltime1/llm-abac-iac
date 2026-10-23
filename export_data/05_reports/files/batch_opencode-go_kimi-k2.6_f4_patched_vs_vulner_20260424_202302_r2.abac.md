# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 20:56:30_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 11 | Rules: 9_  
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
    "source_network": {
      "domain": [
        "0.0.0.0/0",
        "10.0.1.0/24"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "applies_to": {
      "domain": [
        "all"
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
        "host_group": "webservers_patched",
        "source": "inventory.ini"
      },
      {
        "hostname": "web-old01.lab.local",
        "ip": "10.0.1.20",
        "role": "frontend",
        "zone": "dmz",
        "host_group": "webservers_legacy",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "host_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "https",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers_patched",
        "source": "group_vars/webservers_patched.yml"
      },
      {
        "name": "https",
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
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "internal",
        "label": "web subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet",
        "source": "group_vars/webservers_patched.yml"
      }
    ],
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "environment": {
    "org": {
      "value": "patchcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "domain": [
        "soc2"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "value": 90,
      "source": "group_vars/all.yml"
    },
    "applies_to": {
      "domain": [
        "all"
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
    "rule_id": "rule-001",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers_patched"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "21-25"
    }
  },
  {
    "rule_id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers_legacy"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "21-25"
    }
  },
  {
    "rule_id": "rule-003",
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
        "equals": "tcp"
      },
      "host_group": {
        "equals": "webservers_patched"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "13-20"
    }
  },
  {
    "rule_id": "rule-004",
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
        "equals": "tcp"
      },
      "host_group": {
        "equals": "webservers_legacy"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "13-20"
    }
  },
  {
    "rule_id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": "16-20"
    }
  },
  {
    "rule_id": "rule-006",
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
      "task": "default-deny",
      "lines": "0"
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
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "webservers_patched"
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
    "id": "rule-002",
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
    "id": "rule-003",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "host_group": {
        "equals": "dbservers"
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
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned OpenSSH 9.6p1 is not affected.",
    "cvss_score": 10,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned OpenSSH 9.6p1 is not affected.",
    "cvss_score": 10,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned OpenSSH 9.6p1 is not affected.",
    "cvss_score": 10,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned OpenSSH 9.6p1 is not affected.",
    "cvss_score": 10,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned OpenSSH 9.6p1 is not affected.",
    "cvss_score": 10,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned OpenSSH 9.6p1 is not affected.",
    "cvss_score": 9.8,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade OpenSSH to 9.8p1 or later, or apply vendor patch for regreSSHion (CVE-2024-6387).",
    "cvss_score": 8.1,
    "severity": "high"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned OpenSSH 9.6p1 is not affected.",
    "cvss_score": 7.5,
    "severity": "high"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned OpenSSH 9.6p1 is not affected.",
    "cvss_score": 6.8,
    "severity": "medium"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "9.6p1",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned OpenSSH 9.6p1 is not affected.",
    "cvss_score": 6.8,
    "severity": "medium"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned PostgreSQL 16.2 is not affected by this CVE.",
    "cvss_score": 10,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned PostgreSQL 16.2 is not affected by this CVE.",
    "cvss_score": 10,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned PostgreSQL 16.2 is not affected by this CVE.",
    "cvss_score": 10,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned PostgreSQL 16.2 is not affected by this CVE.",
    "cvss_score": 10,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned PostgreSQL 16.2 is not affected by this CVE.",
    "cvss_score": 7.2,
    "severity": "high"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.24.0",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned nginx 1.24.0 is not affected.",
    "cvss_score": 9.8,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned nginx 1.20.0 is not affected.",
    "cvss_score": 9.8,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.24.0",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned nginx 1.24.0 is not affected.",
    "cvss_score": 9.8,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned nginx 1.20.0 is not affected.",
    "cvss_score": 9.8,
    "severity": "critical"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.24.0",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned nginx 1.24.0 is not affected.",
    "cvss_score": 7.7,
    "severity": "high"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx to 1.20.1 or later to mitigate DNS resolver vulnerability (CVE-2021-23017).",
    "cvss_score": 7.7,
    "severity": "high"
  },
  {
    "cve_id": "CVE-2016-0742",
    "product": "nginx",
    "pinned_version": "1.24.0",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned nginx 1.24.0 is not affected.",
    "cvss_score": 7.5,
    "severity": "high"
  },
  {
    "cve_id": "CVE-2016-0742",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned nginx 1.20.0 is not affected.",
    "cvss_score": 7.5,
    "severity": "high"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.24.0",
    "affects_pinned_version": true,
    "recommendation": "Apply HTTP/2 rapid reset patch or disable HTTP/2 on nginx 1.24.0 (CVE-2023-44487).",
    "cvss_score": 7.5,
    "severity": "high"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": true,
    "recommendation": "Apply HTTP/2 rapid reset patch or disable HTTP/2 on nginx 1.20.0 (CVE-2023-44487).",
    "cvss_score": 7.5,
    "severity": "high"
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.24.0",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned nginx 1.24.0 is not affected.",
    "cvss_score": 5.8,
    "severity": "medium"
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned nginx 1.20.0 is not affected.",
    "cvss_score": 5.8,
    "severity": "medium"
  }
]
```

## Report

# ABAC Policy Mining Report — PatchCorp Production

## 1. Scope & Methodology
Mined from Ansible configuration rooted at `RLM_ANSIBLE_DIR`.
Policy slice: `all` (SSH, firewall, database access, filesystem).

## 2. Attribute Catalog Summary
| Category | Count | Key Values |
|----------|-------|------------|
| **Subjects** | 2 users | admin (sudo, operations, secret), appuser (developers, engineering, confidential) |
| **Groups** | 2 | sudo, developers |
| **Hosts** | 3 | web-new01.lab.local (webservers_patched), web-old01.lab.local (webservers_legacy), db01.lab.local (dbservers) |
| **Services** | 3 | HTTPS/443 (webservers), PostgreSQL/5432 (dbservers) |
| **Networks** | 2 | 0.0.0.0/0 (internet), 10.0.1.0/24 (web subnet) |
| **Environment** | — | org=patchcorp, environment=production, compliance_tier=soc2 |

## 3. Rules Extracted
- **rule-001**: Permit `ssh:login` for `sudo` group on **webservers_patched**.
- **rule-002**: Permit `ssh:login` for `sudo` group on **webservers_legacy**.
- **rule-003**: Permit `network:connect` from `0.0.0.0/0` to TCP/443 on **webservers_patched**.
- **rule-004**: Permit `network:connect` from `0.0.0.0/0` to TCP/443 on **webservers_legacy**.
- **rule-005**: Permit `network:connect` from `10.0.1.0/24` to TCP/5432 on **dbservers**.
- **rule-006**: Default deny all.

## 4. Vulnerability Assessment
| Product | Pinned Version | Affecting CVE | Recommendation |
|---------|----------------|---------------|----------------|
| OpenSSH | 9.6p1 | **CVE-2024-6387** (regreSSHion) | Upgrade to 9.8p1+ or apply vendor patch. |
| nginx (legacy) | 1.20.0 | **CVE-2021-23017**, **CVE-2023-44487** | Upgrade to 1.20.1+; apply HTTP/2 rapid-reset patch or disable HTTP/2. |
| nginx (patched) | 1.24.0 | **CVE-2023-44487** | Apply HTTP/2 rapid-reset patch or disable HTTP/2. |
| PostgreSQL | 16.2 | None affecting pinned server version | No action required. |

## 5. Ambiguities & Gaps
- **Sudo privileges**: The `sudo` group is declared, but no `sudoers` configuration is present in the mined Ansible tasks.
- **Filesystem ACLs**: `/var/lib/postgresql/data` is created with owner `postgres` and mode `0700`, but explicit access rights for catalog users (`admin`, `appuser`) are not defined.
- **Database authorization**: `pg_hba.conf` allows all database users from the web subnet; no distinction between privilege levels (e.g., SUPERUSER vs read-only) is configured.
- **Credentials management**: Passwords, keys, or other secrets are not managed in the committed Ansible files inspected.
- **Session logging / audit**: No `profile.d` audit scripts or session-logging tasks were found in the role tasks.
- **Implicit denies**: No explicit `reject` firewall or `pg_hba` deny rules are present; default deny is modeled as a policy-level catch-all.
