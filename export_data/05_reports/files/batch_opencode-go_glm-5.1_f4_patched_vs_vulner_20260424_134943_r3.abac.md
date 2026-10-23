# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 14:35:08_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 11 | Rules: 11_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "type": "enum",
      "domain": [
        "admin",
        "appuser"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "enum",
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "type": "cidr",
      "source": "group_vars/dbservers.yml"
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal",
        "internet"
      ],
      "source": "inventory.ini"
    }
  },
  "resources": {
    "hostname": {
      "type": "enum",
      "domain": [
        "web-new01.lab.local",
        "web-old01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "ip",
      "source": "inventory.ini"
    },
    "role": {
      "type": "enum",
      "domain": [
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "webservers_patched",
        "webservers_legacy",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "postgresql",
        "ssh"
      ],
      "source": "roles/web_legacy/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "source": "group_vars/dbservers.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp",
        "udp"
      ],
      "source": "roles/web_legacy/tasks/main.yml"
    },
    "path": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "enum",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "enum",
      "domain": [
        "patchcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "enum",
      "domain": [
        "soc2"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "integer",
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
        "equals": "ssh"
      },
      "host_group": {
        "in": [
          "webservers_patched",
          "webservers_legacy"
        ]
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
      "lines": "21-25"
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
      "protocol": {
        "equals": "tcp"
      },
      "service": {
        "equals": "nginx"
      },
      "host_group": {
        "in": [
          "webservers_patched",
          "webservers_legacy"
        ]
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
      "lines": "13-19"
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
      },
      "host_group": {
        "equals": "dbservers"
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
      "lines": "16-20"
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
      "lines": "8-14"
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
      "lines": "8-14"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
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
      "lines": "8-14"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "*",
    "effect": "deny"
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
      },
      "host_group": {
        "equals": "dbservers"
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
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affected_host_group": "webservers_legacy",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "nginx resolver 1-byte memory overwrite via forged UDP packets from DNS server, causing worker process crash or other impacts",
    "recommendation": "Upgrade legacy webservers to nginx 1.24.0 (already used by webservers_patched) or later to remediate this vulnerability"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx-njs",
    "pinned_version": "N/A",
    "affected_host_group": "webservers_legacy",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access in njs_vmcode_typeof, potentially enabling arbitrary code execution",
    "recommendation": "Only relevant if the njs module is compiled into nginx; verify njs is not loaded and consider removing it if present"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql-jdbc-driver",
    "pinned_version": "N/A",
    "affected_host_group": "dbservers",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "SQL injection in pgjdbc when PreferQueryMode=SIMPLE is used, allowing attackers to inject arbitrary SQL",
    "recommendation": "Not applicable to server-side PostgreSQL 16.2; only relevant if Java applications use the JDBC driver with SIMPLE query mode"
  }
]
```

## Report

# ABAC Policy Mining Report — PatchCorp Ansible Infrastructure

## Executive Summary

An Attribute-Based Access Control (ABAC) policy was mined from the PatchCorp Ansible configuration. The infrastructure comprises 3 hosts across 2 zones (DMZ and internal), running nginx (web serving), PostgreSQL (database), and OpenSSH (remote access). The policy defines **7 rules** covering SSH access, firewall/network connectivity, filesystem permissions, and a default-deny catch-all.

## Infrastructure Overview

| Host | IP | Role | Zone | Group |
|------|-----|------|------|-------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

## Subjects

| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |

## Extracted Rules

### Rule-001: SSH Login (sudo group only)
- **Effect**: PERMIT
- **Subject**: groups any_of [sudo]
- **Resource**: service=ssh on webservers_patched and webservers_legacy
- **Source**: `roles/web_legacy/tasks/main.yml` and `roles/web_patched/tasks/main.yml`

### Rule-002: HTTPS from Internet
- **Effect**: PERMIT
- **Subject**: all (0.0.0.0/0)
- **Resource**: port=443/tcp, service=nginx on webservers
- **Source**: `roles/web_legacy/tasks/main.yml` and `roles/web_patched/tasks/main.yml`

### Rule-003: PostgreSQL from Web Subnet
- **Effect**: PERMIT
- **Subject**: source_network=10.0.1.0/24
- **Resource**: service=postgresql, port=5432 on dbservers
- **Source**: `roles/db/tasks/main.yml`

### Rule-004/005/006: PostgreSQL Data Directory
- **Effect**: PERMIT
- **Subject**: groups any_of [sudo]
- **Resource**: path=/var/lib/postgresql/data, owner=postgres, mode=0700
- **Actions**: filesystem:read, filesystem:write, filesystem:execute
- **Source**: `roles/db/tasks/main.yml`

### Rule-007: Default Deny
- **Effect**: DENY
- **Subject/Resource**: all

## Vulnerability Assessment

### CVE-2021-23017 (HIGH — Affects nginx 1.20.0 on legacy webservers)
The nginx resolver contains a 1-byte memory overwrite vulnerability exploitable via forged UDP packets. The legacy web servers (webservers_legacy) running nginx 1.20.0 are **affected**. The patched servers running nginx 1.24.0 are not affected. **Recommendation**: Prioritize migrating legacy webservers to the patched nginx version (1.24.0).

### CVE-2021-46461 (CRITICAL — njs module, unlikely deployed)
Affects NGINX njs module through 0.7.0. Not relevant unless the njs module is explicitly loaded. **Recommendation**: Verify njs is not in use.

### CVE-2024-1597 (CRITICAL — pgjdbc, not PostgreSQL server)
Affects the PostgreSQL JDBC driver, not the server itself. **Recommendation**: Only relevant if Java applications connect using the JDBC driver with PreferQueryMode=SIMPLE.

## Ambiguities

1. **No explicit sudoers rules**: The `sudo` group is referenced for SSH access, but no sudoers configuration was found in the Ansible roles. Actual sudo privileges are assumed from the group name convention.
2. **No database user grants**: The pg_hba.conf entry uses `host all all 10.0.1.0/24 scram-sha-256`, meaning all users can connect to all databases from the web subnet. No specific PostgreSQL user accounts or privilege levels are defined in the Ansible configuration.
3. **No credential management**: No vault files or credential management tasks were found. Database credentials and SSH keys are managed outside this Ansible configuration.
4. **No monitoring/logging configuration**: No audit, logging, or monitoring tasks were found in the role files.
5. **appuser lacks explicit permissions**: The appuser (developers group) has no directly assigned access rules in the configuration beyond what may be inherited through group membership on the hosts.
6. **Firewall allows 0.0.0.0/0**: Both webservers_legacy and webservers_patched allow HTTPS from all IPs (0.0.0.0/0), which is appropriate for public-facing web servers but should be documented.

## Policy Coverage

| Slice | Rules | Status |
|-------|-------|--------|
| SSH | rule-001 | Complete |
| Firewall/Network | rule-002, rule-003 | Complete |
| Database | rule-003 | Complete (network-layer only) |
| Filesystem | rule-004, rule-005, rule-006 | Complete |
| Default Deny | rule-007 | Complete |
