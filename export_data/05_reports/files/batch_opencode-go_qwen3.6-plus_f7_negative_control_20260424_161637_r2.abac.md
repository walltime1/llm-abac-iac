# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:22:45_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 9 | Rules: 12_  
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
        "source": "labcorp"
      },
      {
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "department": "engineering",
        "clearance": "confidential",
        "source": "labcorp"
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
          "confidential"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "level": "confidential",
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
        "service": "nginx",
        "source": "group_vars/webservers.yml"
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
    "org": "labcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90
  },
  "attribute_definitions": {
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers"
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
    },
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
        "webservers",
        "dbservers"
      ]
    },
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
        "pci-dss",
        "hipaa"
      ]
    },
    "org": {
      "type": "string",
      "domain": []
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp",
        "udp"
      ]
    },
    "mode": {
      "type": "string",
      "domain": []
    },
    "source_network": {
      "type": "string",
      "domain": []
    },
    "database": {
      "type": "string",
      "domain": []
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "postgresql",
        "sshd"
      ]
    },
    "port": {
      "type": "integer",
      "domain": []
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
      "hostname": {
        "equals": "web01.lab.local"
      },
      "service": {
        "equals": "sshd"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        24,
        27
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "clearance": {
        "equals": "secret"
      },
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "obligations": [
      {
        "type": "audit",
        "description": "nopassword: false - requires password for sudo"
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        17,
        23
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
      "hostname": {
        "equals": "web01.lab.local"
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        24,
        29
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
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        13,
        17
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
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        18,
        22
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
      "hostname": {
        "equals": "db01.lab.local"
      },
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        23,
        26
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        12,
        16
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
      "file": "policy",
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
      "environment": {
        "equals": "production"
      },
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
      "environment": {
        "equals": "production"
      },
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
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if nginx 1.27.0 includes backported patches for CVE-2016-0746; upgrade if not"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if nginx 1.27.0 includes backported patches for CVE-2021-46461; upgrade if not"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if nginx 1.27.0 includes backported patches for CVE-2017-20005; upgrade if not"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cvss_score": 7.7,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if nginx 1.27.0 includes backported patches for CVE-2021-23017; upgrade if not"
  },
  {
    "cve_id": "CVE-2013-4547",
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cvss_score": 7.5,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if nginx 1.27.0 includes backported patches for CVE-2013-4547; upgrade if not"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cvss_score": 7.5,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if nginx 1.27.0 includes backported patches for CVE-2023-44487; upgrade if not"
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cvss_score": 5.8,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if nginx 1.27.0 includes backported patches for CVE-2009-3555; upgrade if not"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if PostgreSQL 16.4 includes backported patches for CVE-2007-3279; upgrade if not"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if PostgreSQL 16.4 includes backported patches for CVE-2002-1399; upgrade if not"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if PostgreSQL 16.4 includes backported patches for CVE-2013-1903; upgrade if not"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if PostgreSQL 16.4 includes backported patches for CVE-2013-1902; upgrade if not"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if PostgreSQL 16.4 includes backported patches for CVE-2024-1597; upgrade if not"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cvss_score": 7.2,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if PostgreSQL 16.4 includes backported patches for CVE-2019-9193; upgrade if not"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cvss_score": 7.1,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Verify if PostgreSQL 16.4 includes backported patches for CVE-2022-31197; upgrade if not"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

Mined an Attribute-Based Access Control (ABAC) policy from an Ansible configuration for **labcorp** in a **production** environment with **soc2** compliance tier. The infrastructure consists of 2 hosts (web01 in DMZ, db01 internal) running nginx, openssh, and postgresql.

## Coverage Summary

| Domain | Rules Extracted | Source Files |
|--------|----------------|--------------|
| SSH Access | 1 (rule-001) | roles/web/tasks/main.yml |
| Sudo Privileges | 1 (rule-002) | roles/web/tasks/main.yml |
| Network/Firewall | 2 (rule-003, rule-006) | roles/web/tasks/main.yml, roles/db/tasks/main.yml |
| Database Access | 2 (rule-004, rule-005) | roles/db/tasks/main.yml |
| Filesystem | 1 (rule-007) | roles/db/tasks/main.yml |
| Identity Management | 1 (rule-008) | roles/web/tasks/main.yml |
| Default Deny | 1 (rule-009) | policy |
| **Total** | **9** | |

## Subject Catalog

- **admin** (uid:1001, groups: sudo, dept: operations, clearance: secret)
- **appuser** (uid:1002, groups: developers, dept: engineering, clearance: confidential)

## Resource Catalog

- **web01.lab.local** (10.0.1.10, frontend, dmz, webservers)
- **db01.lab.local** (10.0.2.10, primary, internal, dbservers)

## Vulnerability Assessment

Identified **14 CVEs** across 2 pinned products:

- **nginx** (1.27.0-1~noble): 7 critical/remote CVEs (CVSS 5.8–9.8)
- **postgresql** (16.4-1.pgdg24.04+1): 7 critical/remote CVEs (CVSS 7.1–10.0)
- **openssh-server** (1:9.9p1-3ubuntu1): No critical/remote CVEs or KEV entries found

All pinned packages note in group_vars/all.yml that they are "ALL PATCHED", so many historical CVEs are likely already mitigated via backported patches.

## Ambiguities and Gaps

1. **Pinned version vs CVE age**: group_vars/all.yml states "ALL PATCHED, no applicable CVEs." Many returned CVEs (e.g., CVE-2002-1399, CVE-2007-3279) are decades old and almost certainly fixed in PostgreSQL 16.4. The vulnerability tools returned historical CVEs without version-range validation. Manual version-range verification is recommended.

2. **No explicit filesystem rules for /var/www/html**: group_vars/webservers.yml defines `document_root: /var/www/html` but no Ansible task sets its mode/owner/group. Rule coverage for this path is incomplete.

3. **No pg_hba.conf deny rules**: The Ansible config adds `host all all 10.0.1.0/24` lines to pg_hba.conf but does not configure explicit deny entries (e.g., `host all all 0.0.0.0/0 reject`). PostgreSQL's default implicit deny applies, but no explicit rule was mined.

4. **No SELinux or audit logging tasks**: No session logging, auditd configuration, or SELinux boolean tasks were found in the Ansible roles. Obligations for audit trails are missing from the mined policy.

5. **Firewall allow 0.0.0.0/0**: Rule-003 permits HTTPS from any source to web01. This is consistent with an internet-facing frontend but is a broad network rule.

6. **Credentials handling**: No vault-encrypted variables or credential management tasks were found in the scanned files. This is noted as a potential gap for SOC2 compliance.

7. **Openssh version string**: `1:9.9p1-3ubuntu1` includes epoch prefix (`1:`). This is correct Debian/Ubuntu packaging format but should be noted for vulnerability matching.

## Default-Deny

A default-deny rule (rule-009) has been included as a catch-all for any subject-resource-action combination not explicitly permitted.

## Conclusion

The mined policy covers SSH, sudo, network, database, filesystem, and identity management access controls. The configuration is reasonably structured for a SOC2-compliant production environment, though audit logging and credential management are not explicitly configured in the scanned Ansible files.
