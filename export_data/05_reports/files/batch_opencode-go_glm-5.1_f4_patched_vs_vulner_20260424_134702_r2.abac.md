# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 14:12:54_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 18 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

## Attributes

```json
{
  "subject": {
    "user": {
      "type": "enum",
      "domain": [
        "admin",
        "appuser",
        "postgres"
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
        "developers",
        "postgres"
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
      "type": "cidr",
      "source": "group_vars/dbservers.yml"
    },
    "source_network": {
      "type": "cidr",
      "source": "group_vars/webservers_legacy.yml"
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "internet"
      ],
      "source": "roles/web_legacy/tasks/main.yml"
    }
  },
  "resource": {
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
      "type": "string",
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
    "inventory_group": {
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
        "openssh-server",
        "postgresql"
      ],
      "source": "group_vars/all.yml"
    },
    "port": {
      "type": "integer",
      "source": "group_vars/dbservers.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp"
      ],
      "source": "group_vars/webservers_legacy.yml"
    },
    "path": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "string",
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
    "description": "Allow SSH login for sudo group on legacy web servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "openssh-server"
      },
      "inventory_group": {
        "equals": "webservers_legacy"
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
    "action": "ssh:login",
    "effect": "permit",
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
    "description": "Allow SSH login for sudo group on patched web servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "openssh-server"
      },
      "inventory_group": {
        "equals": "webservers_patched"
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
    "action": "ssh:login",
    "effect": "permit",
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
    "description": "Allow HTTPS connections from any source to legacy web servers",
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
      },
      "protocol": {
        "equals": "tcp"
      },
      "inventory_group": {
        "equals": "webservers_legacy"
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
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall allow HTTPS from internet",
      "lines": [
        13,
        19
      ]
    }
  },
  {
    "id": "rule-004",
    "description": "Allow HTTPS connections from any source to patched web servers",
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
      },
      "protocol": {
        "equals": "tcp"
      },
      "inventory_group": {
        "equals": "webservers_patched"
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
    "effect": "permit",
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall allow HTTPS from internet",
      "lines": [
        13,
        19
      ]
    }
  },
  {
    "id": "rule-005",
    "description": "Allow PostgreSQL connections from web subnet 10.0.1.0/24",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "hostname": {
        "equals": "db01.lab.local"
      },
      "port": {
        "equals": 5432
      },
      "database": {
        "equals": "all"
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
    "action": "db:connect",
    "effect": "permit",
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
    "description": "Deny PostgreSQL connections from sources not in 10.0.1.0/24 (pg_hba implicit deny)",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "hostname": {
        "equals": "db01.lab.local"
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
    "action": "db:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet (implicit deny)",
      "lines": [
        16,
        20
      ]
    }
  },
  {
    "id": "rule-007",
    "description": "Allow postgres group read access to PostgreSQL data directory",
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
      "environment": {
        "equals": "production"
      },
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
    "id": "rule-008",
    "description": "Allow postgres group write access to PostgreSQL data directory",
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
      "environment": {
        "equals": "production"
      },
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
    "id": "rule-009",
    "description": "Allow postgres group execute access to PostgreSQL data directory",
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
      "environment": {
        "equals": "production"
      },
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
    "id": "rule-010",
    "description": "Default deny all access",
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
      "file": "inventory.ini",
      "task": "implicit default",
      "lines": [
        1,
        30
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
    "id": "rule-014",
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
    "id": "rule-015",
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
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "reason": "OpenSSH 9.6p1 is far beyond the affected versions for this 2003 vulnerability",
    "recommendation": "No action needed; pinned version 9.6p1 is not affected"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "reason": "OpenSSH 9.6p1 is far beyond the affected versions for this 2000 vulnerability",
    "recommendation": "No action needed; pinned version 9.6p1 is not affected"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "reason": "OpenSSH 9.6p1 is far beyond the affected versions for this 2000 vulnerability",
    "recommendation": "No action needed; pinned version 9.6p1 is not affected"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "reason": "OpenSSH 9.6p1 is far beyond the affected versions for this 2001 vulnerability",
    "recommendation": "No action needed; pinned version 9.6p1 is not affected"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "reason": "OpenSSH 9.6p1 is far beyond the affected versions for this 2003 vulnerability",
    "recommendation": "No action needed; pinned version 9.6p1 is not affected"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "reason": "Affects nginx before 1.9.10; both pinned versions (1.20.0 and 1.24.0) are past the fix",
    "recommendation": "No action needed; pinned versions are beyond the fix"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": true,
    "reason": "Affects nginx through 1.20.0; legacy host uses exactly nginx 1.20.0-1~focal which is likely vulnerable",
    "recommendation": "Upgrade nginx on webservers_legacy from 1.20.0 to 1.24.0+ to remediate this vulnerability"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": true,
    "reason": "May affect nginx 1.20.0; needs verification against specific version ranges",
    "recommendation": "Upgrade nginx on webservers_legacy from 1.20.0 to 1.24.0+ and verify patch status"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": true,
    "reason": "DNS resolver vulnerability affects nginx before 1.21.0; legacy 1.20.0 is vulnerable",
    "recommendation": "Upgrade nginx on webservers_legacy from 1.20.0 to at least 1.21.0 to fix DNS resolver issue"
  },
  {
    "cve_id": "CVE-2013-4547",
    "product": "nginx",
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "reason": "Affects nginx before 1.4.4 and 1.5.7; both 1.20.0 and 1.24.0 are beyond the fix",
    "recommendation": "No action needed; pinned versions are beyond the fix"
  }
]
```

## Report

# ABAC Policy Mining Report — PatchCorp Ansible Configuration

## 1. Overview

This report presents an Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The infrastructure consists of three hosts in a production environment under SOC 2 compliance: two web servers (one legacy, one patched) in the DMZ and one database server in the internal zone.

## 2. Infrastructure Summary

### Hosts
| Hostname | IP | Role | Zone | Inventory Group |
|----------|-----|------|------|----------------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Users
| Name | UID | Groups | Department | Clearance |
|------|-----|--------|------------|----------|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |

### Environment
- **Org**: patchcorp
- **Environment**: production
- **Compliance Tier**: soc2
- **Log Retention**: 90 days

## 3. Pinned Software Versions
| Package | Version | Host Group |
|---------|---------|-----------|
| openssh-server | 1:9.6p1-3ubuntu1 | webservers_legacy, webservers_patched |
| nginx (patched) | 1.24.0-2ubuntu1 | webservers_patched |
| nginx (legacy) | 1.20.0-1~focal | webservers_legacy |
| postgresql | 16.2-1.pgdg22.04+1 | dbservers |

## 4. Access Control Rules Extracted

### SSH Access (rules 001–002)
SSH login is restricted to the **sudo** group on both web server groups via `AllowGroups sudo` in `/etc/ssh/sshd_config`. Only the `admin` user (member of sudo) can SSH into web servers.

### Network Firewall (rules 003–004)
Firewalld permits HTTPS (port 443/tcp) from **0.0.0.0/0** (any source) to both web server groups. This is an open ingress policy for public-facing web services.

### Database Access (rules 005–006)
PostgreSQL on db01 accepts connections only from the **10.0.1.0/24** subnet (the web server DMZ) via `pg_hba.conf` with SCRAM-SHA-256 authentication. All other sources are implicitly denied.

### Filesystem (rules 007–009)
The PostgreSQL data directory `/var/lib/postgresql/data` is owned by `postgres:postgres` with mode `0700`, granting read/write/execute exclusively to the postgres group.

### Default Deny (rule 010)
A catch-all deny rule applies to all unspecified access requests.

## 5. Vulnerability Assessment

### Critical Findings Affecting Pinned Versions
| CVE | Product | Severity | Affects Pinned | Recommendation |
|-----|---------|----------|---------------|----------------|
| CVE-2021-46461 | nginx | critical | YES (legacy 1.20.0) | Upgrade to 1.24.0+ |
| CVE-2021-23017 | nginx | critical | YES (legacy 1.20.0) | Upgrade to 1.21.0+ |
| CVE-2017-20005 | nginx | critical | LIKELY (legacy 1.20.0) | Upgrade to 1.24.0+ |

### Non-Affected Critical CVEs
The following critical remote CVEs were found but do **not** affect the pinned versions:
- **OpenSSH**: CVE-2003-0786, CVE-2000-0999, CVE-2000-0525, CVE-2001-0144, CVE-2003-0693 — all from 2000–2003, resolved long before version 9.6p1.
- **nginx**: CVE-2016-0746, CVE-2013-4547 — fixed before version 1.20.0.

### PostgreSQL
No critical remote vulnerabilities were found for the pinned PostgreSQL 16.2 version.

## 6. Ambiguities and Gaps

1. **Firewall allow-from 0.0.0.0/0**: Both web server groups allow HTTPS from any source. For a production SOC 2 environment, this may be overly permissive. Consider restricting to known client CIDRs.
2. **postgres user not defined in users list**: The `postgres` system user (owner of the data directory) is referenced in role tasks but not declared in the `users` list in `group_vars/all.yml`. It is assumed to be a system account created by the PostgreSQL package.
3. **No explicit sudoers rules**: While the `sudo` group exists and has SSH access, no sudoers configuration file was found in the Ansible roles. The scope of sudo privileges is therefore undefined.
4. **No credentials or secrets management**: No Ansible Vault or secrets configuration was found. Database passwords and SSH keys are not managed through this configuration.
5. **Legacy nginx version**: The webservers_legacy group runs nginx 1.20.0, which is affected by at least 2 critical CVEs. The divergence from the patched version (1.24.0) creates an inconsistent security posture.
6. **No session logging or audit obligations observed**: While log retention is defined (90 days), no audit logging or session recording (e.g., auditd, profile.d scripts) is configured in the Ansible roles.

## 7. Recommendations

1. **Migrate legacy web servers** to nginx 1.24.0+ to eliminate 3 critical CVEs (CVE-2021-46461, CVE-2021-23017, CVE-2017-20005).
2. **Restrict firewall allow-from** on web servers from 0.0.0.0/0 to specific client CIDRs where possible.
3. **Add sudoers management** to Ansible roles to explicitly define sudo scope.
4. **Add secrets management** via Ansible Vault for database credentials.
5. **Implement audit logging** obligations (auditd, session recording) to support SOC 2 compliance.
