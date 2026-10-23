# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 13:53:52_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 12 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f1_minimal_twotier`_

## Attributes

```json
{
  "subject": {
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
      "domain": null,
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
    "source_ip": {
      "type": "string",
      "domain": null,
      "source": "roles/db/tasks/main.yml"
    },
    "source_network": {
      "type": "string",
      "domain": null,
      "source": "roles/db/tasks/main.yml"
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
  "resource": {
    "hostname": {
      "type": "enum",
      "domain": [
        "web01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "string",
      "domain": null,
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
        "webservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "postgresql",
        "httpd",
        "ssh"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "port": {
      "type": "integer",
      "domain": null,
      "source": "group_vars/dbservers.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "path": {
      "type": "string",
      "domain": null,
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
      "domain": null,
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "enum",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "privilege_level": {
      "type": "enum",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "enum",
      "domain": [
        "labcorp"
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
      "domain": null,
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
      "privilege_level": {
        "equals": "SUPERUSER"
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
      "task": "Create DB superuser role",
      "lines": "13-17"
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
      "privilege_level": {
        "equals": "NOSUPERUSER"
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
      "task": "Create DB read-only role",
      "lines": "19-23"
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
      "task": "Allow postgres only from webservers subnet",
      "lines": "25-28"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet (implicit deny)",
      "lines": "25-28"
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
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-12"
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
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-12"
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
      "lines": "8-12"
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
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "webservers"
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
      "lines": "28-31"
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
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "ssh:login",
    "effect": "deny",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group (implicit deny)",
      "lines": "28-31"
    }
  },
  {
    "id": "rule-010",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "password_required",
        "nopassword": false
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "20-25"
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "source_zone": {
        "equals": "internet"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "httpd"
      },
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "webservers"
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
      "task": "Firewall — allow HTTP from internet",
      "lines": "26-27"
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "14-18"
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
    "effect": "deny"
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
    "id": "rule-015",
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
    "id": "rule-016",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2021-41773",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": true,
    "kev": true,
    "known_ransomware_campaign_use": true,
    "description": "Apache HTTP Server 2.4.49 path traversal flaw allows mapping URLs outside document root, potentially accessing sensitive files or leaking source code",
    "recommendation": "Upgrade httpd to 2.4.51 or later immediately. This version is directly affected and the CVE is actively exploited in the wild with ransomware campaigns."
  },
  {
    "cve_id": "CVE-2021-42013",
    "product": "httpd",
    "pinned_version": "2.4.49-1",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": true,
    "kev": true,
    "known_ransomware_campaign_use": true,
    "description": "Apache HTTP Server 2.4.49 and 2.4.50 path traversal allows accessing files outside document root and potentially executing remote code if mod_cgi enabled",
    "recommendation": "Upgrade httpd to 2.4.51 or later immediately. The fix in 2.4.50 was incomplete; 2.4.51 fully addresses both CVE-2021-41773 and CVE-2021-42013."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "kev": false,
    "known_ransomware_campaign_use": false,
    "description": "pgjdbc PostgreSQL JDBC Driver SQL injection via PreferQueryMode=SIMPLE, allowing attackers to execute arbitrary SQL",
    "recommendation": "This affects the JDBC driver, not the PostgreSQL server itself. If JDBC clients connect to this server, ensure pgjdbc is updated to 42.7.2+."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "kev": false,
    "known_ransomware_campaign_use": false,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 privilege escalation via not checking the return value of setuid",
    "recommendation": "Does not affect OpenSSH 9.6p1. No action required for the pinned version."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "kev": false,
    "known_ransomware_campaign_use": false,
    "description": "OpenSSH before 3.7 buffer management error in buffer_append_space causing privilege escalation",
    "recommendation": "Does not affect OpenSSH 9.6p1. No action required for the pinned version."
  }
]
```

## Report

# ABAC Policy Mining Report — Ansible Configuration

## Overview

This report documents the ABAC policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a two-tier infrastructure with web servers (DMZ) and database servers (internal zone), running under the `labcorp` organization with SOC2 compliance requirements.

## Infrastructure Summary

| Component | Details |
|-----------|--------|
| **Organization** | labcorp |
| **Environment** | production |
| **Compliance Tier** | soc2 |
| **Web Server** | web01.lab.local (10.0.1.10, DMZ, frontend) |
| **DB Server** | db01.lab.local (10.0.2.10, internal, primary) |

## Subjects

| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|----------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |

## Policy Rules Extracted

### Database Access (roles/db/tasks/main.yml)

1. **DB Superuser Login** (rule-001): Users in `sudo` group may login to PostgreSQL with SUPERUSER privileges.
2. **DB Read-Only Login** (rule-002): Users in `developers` group may login to PostgreSQL with NOSUPERUSER (read-only) privileges.
3. **PostgreSQL Network Allow** (rule-003): Connections from 10.0.1.0/24 (webservers subnet) may connect to PostgreSQL.
4. **PostgreSQL Network Deny** (rule-004): All other sources are denied PostgreSQL connections (implicit deny from pg_hba default).
5. **Postgres Data Dir Read** (rule-005): Users in `sudo` group may read /var/lib/postgresql/data (owner=postgres, mode=0700).
6. **Postgres Data Dir Write** (rule-006): Users in `sudo` group may write to /var/lib/postgresql/data.
7. **Postgres Data Dir Execute** (rule-007): Users in `sudo` group may execute/traverse /var/lib/postgresql/data.

### Web Server Access (roles/web/tasks/main.yml)

8. **SSH Login** (rule-008): Users in `sudo` group may SSH into webservers (AllowGroups sudo).
9. **SSH Deny** (rule-009): All other users are denied SSH access to webservers (implicit deny from sshd_config).
10. **Sudo Execute** (rule-010): Users in `sudo` group with `secret` clearance may execute sudo commands on webservers (password required, nopassword=false).
11. **HTTP Firewall Allow** (rule-011): Internet-facing traffic (0.0.0.0/0) may connect to HTTP (port 80/tcp) on webservers.
12. **User Provisioning** (rule-012): Users in `sudo` group are provisioned shell accounts on webservers.
13. **Default Deny** (rule-013): All access not explicitly permitted is denied.

## Vulnerability Assessment

### Critical: Apache HTTP Server (httpd 2.4.49-1)

| CVE | CVSS | KEV | Ransomware | Affects Pinned Version |
|-----|------|-----|------------|----------------------|
| CVE-2021-41773 | 9.8 | Yes | Yes | **Yes** |
| CVE-2021-42013 | 9.8 | Yes | Yes | **Yes** |

**httpd 2.4.49 is directly affected by both path traversal CVEs.** These are actively exploited in the wild with known ransomware campaigns. **Immediate upgrade to 2.4.51+ is required.**

### Informational: PostgreSQL (16.2-1.pgdg22.04+1)

| CVE | CVSS | Affects Pinned Version |
|-----|------|----------------------|
| CVE-2024-1597 | 10.0 | No (JDBC driver, not server) |

The pinned PostgreSQL 16.2 server version is not directly affected by recent critical CVEs. CVE-2024-1597 affects the JDBC driver, not the server.

### Informational: OpenSSH (1:9.6p1-3ubuntu1)

| CVE | CVSS | Affects Pinned Version |
|-----|------|----------------------|
| CVE-2003-0786 | 10.0 | No (affects 3.7.x) |
| CVE-2003-0693 | 10.0 | No (affects pre-3.7) |

The pinned OpenSSH 9.6p1 is not affected by any known critical remote CVEs.

## Ambiguities and Open Questions

1. **Firewall scope for HTTP**: The `firewall_allow_from` is set to `0.0.0.0/0` (internet-facing), which is appropriate for a public web server but may need refinement for compliance.
2. **pg_hba authentication method**: The `scram-sha-256` method is configured but no explicit deny rule for non-matching sources is written in the file — the implicit deny is assumed from PostgreSQL's default behavior.
3. **Sudoers scope**: The sudoers rule applies only to users with `clearance=secret` in the `sudo` group on webservers. No sudoers configuration was found for dbservers.
4. **SSH access to dbservers**: No SSH AllowGroups configuration was found for database servers. This may be an oversight or may rely on a different mechanism.
5. **appuser shell access**: The `appuser` (developers group) is not provisioned a shell account on webservers (only sudo group users are), but does get a PostgreSQL NOSUPERUSER login. This is consistent but worth noting.
6. **Credentials**: No explicit credential management (vault passwords, API keys) was found in the Ansible configuration. If credentials are managed elsewhere, this should be documented.
