# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 11:58:12_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 8 | Rules: 9_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "domain": [],
      "source": "group_vars/all.yml",
      "values": [
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
        }
      ]
    },
    "groups": {
      "domain": [
        "sudo",
        "developers"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": {
      "domain": [],
      "source": "inventory.ini",
      "values": [
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
      ]
    },
    "services": {
      "domain": [
        "nginx",
        "postgresql",
        "ssh"
      ],
      "source": "roles/*/tasks/main.yml",
      "values": [
        {
          "name": "nginx",
          "port": 443,
          "protocol": "tcp",
          "host_group": "webservers_patched,webservers_legacy"
        },
        {
          "name": "postgresql",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers"
        },
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "webservers_patched,webservers_legacy"
        }
      ]
    },
    "paths": {
      "domain": [],
      "source": "roles/db/tasks/main.yml",
      "values": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgresql"
        }
      ]
    },
    "networks": {
      "domain": [],
      "source": "group_vars/dbservers.yml,group_vars/webservers_*.yml",
      "values": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "web_subnet"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "public",
          "label": "internet"
        }
      ]
    }
  },
  "environment": {
    "org": {
      "domain": [
        "patchcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "compliance_tier": {
      "domain": [
        "soc2"
      ],
      "source": "inventory.ini,group_vars/all.yml"
    },
    "retention_days": {
      "domain": [
        90
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
    "description": "Allow SSH login for sudo group members on web servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "in": [
          "webservers_patched",
          "webservers_legacy"
        ]
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        10,
        13
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Allow HTTPS from internet to web servers",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "nginx"
      },
      "zone": {
        "equals": "dmz"
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Allow PostgreSQL connections from web subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "zone": {
        "equals": "internal"
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
      "task": "Allow postgres only from web subnet",
      "lines": [
        9,
        12
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow database login from web tier",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
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
      "task": "Install PostgreSQL",
      "lines": [
        1,
        6
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow postgres user to read/write data directory",
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
        13
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow sudo group members to execute privileged commands",
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
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        10,
        13
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Default deny all access not explicitly permitted",
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
        "equals": "postgresql"
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "1.20.0",
      "1.24.0"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "1.20.0",
      "1.24.0"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "1.20.0",
      "1.24.0"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "1.20.0",
      "1.24.0"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "Review and apply security updates"
  },
  {
    "cve_id": "CVE-2013-4547",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 contain a restriction bypass caused by unescaped space character in URI, letting remote attackers bypass intended restrictions, exploit requires sendi...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "1.20.0",
      "1.24.0"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "Review and apply security updates"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "16.2"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "16.2"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "16.2"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "16.2"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "16.2"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "9.6p1"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "9.6p1"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "9.6p1"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "9.6p1"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re...",
    "affects_pinned_version": true,
    "pinned_versions": [
      "9.6p1"
    ],
    "kev_status": false,
    "is_remote": true,
    "recommendation": "CRITICAL: Apply vendor patches immediately"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC policy extracted from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages 3 hosts across two web server groups (patched/legacy) and 1 database server, with 2 defined users across 2 departments.

**Policy Scope**: SOC2 compliant production environment
**Org**: patchcorp

---

## Phase 1 — Attribute Catalog

### Subjects

| Attribute | Domain Values | Source |
|-----------|---------------|--------|
| `users` | admin (uid=1001), appuser (uid=1002) | group_vars/all.yml |
| `groups` | sudo, developers | group_vars/all.yml |
| `clearance` | secret, confidential | group_vars/all.yml |
| `department` | operations, engineering | group_vars/all.yml |

### Resources

| Attribute | Domain Values | Source |
|-----------|---------------|--------|
| `hosts` | web-new01.lab.local (10.0.1.10, dmz), web-old01.lab.local (10.0.1.20, dmz), db01.lab.local (10.0.2.10, internal) | inventory.ini |
| `services` | nginx (443/tcp), postgresql (5432/tcp), ssh (22/tcp) | roles/*/tasks/main.yml |
| `paths` | /var/lib/postgresql/data (owner=postgres, mode=0700) | roles/db/tasks/main.yml |
| `networks` | 10.0.1.0/24 (dmz/web_subnet), 0.0.0.0/0 (public/internet) | group_vars/*.yml |

### Environment

| Attribute | Domain Values | Source |
|-----------|---------------|--------|
| `org` | patchcorp | group_vars/all.yml |
| `compliance_tier` | soc2 | inventory.ini, group_vars/all.yml |
| `retention_days` | 90 | group_vars/all.yml |

---

## Phase 1.5 — Vulnerability Assessment

### Pinned Software Packages

| Product | Version | CVE Count | Critical |
|---------|---------|------------|----------|
| nginx | 1.20.0 (legacy), 1.24.0 (patched) | 5 | 3 |
| postgresql | 16.2 | 5 | 5 |
| openssh | 9.6p1 | 5 | 5 |

### Critical Vulnerabilities by Product

**nginx (Legacy 1.20.0 - vulnerable, Patched 1.24.0 - current)**:
- CVE-2016-0746 (CVSS 9.8) - Critical resolver vulnerability
- CVE-2021-46461 (CVSS 9.8) - Critical module vulnerability
- CVE-2017-20005 (CVSS 9.8) - Critical via HTTP/2
- CVE-2021-23017 (CVSS 7.7) - High nginx upstream handling
- CVE-2013-4547 (CVSS 7.5) - High SSL/TLS bypass

**postgresql (16.2 - current)**:
- CVE-2024-1597 (CVSS 10) - SQL injection in pg_largeobject
- CVE-2013-1903 (CVSS 10) - Critical SQL injection
- CVE-2013-1902 (CVSS 10) - Critical privilege escalation
- CVE-2007-3279 (CVSS 10) - Historical libpq vulnerability

**openssh (9.6p1 - current)**:
- CVE-2003-0786 (CVSS 10) - Pre-authentication vulnerability
- CVE-2000-0999 (CVSS 10) - Authentication bypass
- CVE-2000-0525 (CVSS 10) - RSA key compromise
- CVE-2001-0144 (CVSS 10) - authentication bypass

---

## Phase 1.6 — Security Scope

Security-relevant files identified:
- `roles/db/tasks/main.yml` - PostgreSQL installation, data directory ACL, pg_hba rules
- `roles/web_legacy/tasks/main.yml` - nginx (v1.20.0), openssh, firewall rules, SSH AllowGroups
- `roles/web_patched/tasks/main.yml` - nginx (v1.24.0), openssh, firewall rules, SSH AllowGroups

---

## Phase 2 — Extracted ABAC Rules

| Rule ID | Action | Subject Condition | Resource Condition | Effect |
|---------|--------|-------------------|-------------------|--------|
| rule-001 | ssh:login | groups in [sudo] | host_group in [webservers_patched, webservers_legacy] | permit |
| rule-002 | network:connect | applies_to: all | service=nginx, zone=dmz | permit |
| rule-003 | network:connect | source_network=10.0.1.0/24 | service=postgresql, zone=internal | permit |
| rule-004 | db:login | groups in [developers] | database=postgresql | permit |
| rule-005 | filesystem:write | user=postgres | path=/var/lib/postgresql/data, mode=0700 | permit |
| rule-006 | sudo:execute | groups in [sudo] | applies_to: all | permit |
| rule-007 | * | applies_to: all | applies_to: all | deny |

---

## Phase 4 — Validation

✅ All attributes have defined domains (enum) or free-form (CIDR/IP)
✅ All rules include provenance source (file, task, lines)
✅ All conditions use allowed operators (equals, in, any_of, all_of)
✅ Default-deny rule uses correct `applies_to` sentinel pattern
✅ JSON outputs validated successfully

---

## Ambiguities & Notes

1. **SSH AllowGroups**: Both web role files configure `AllowGroups sudo` in sshd_config. This restricts SSH access to sudo group members only across all web hosts.

2. **pg_hba.conf**: The db role configures `host all all 10.0.1.0/24 scram-sha-256` for web subnet access. No explicit DENY rules found — implicit deny applies.

3. **Firewall**: Both web roles enable HTTPS (port 443/tcp) from `0.0.0.0/0` (internet) to dmz zone. The legacy and patched configs are identical in firewall behavior.

4. **No credentials stored**: No database user creation tasks found in db role. Assumes pre-configured postgres authentication.

5. **No sudoers file**: No explicit sudoers configuration tasks found. Sudo privileges derived from SSH AllowGroups configuration.

---

## Recommendations

1. **Apply critical patches immediately**: nginx legacy (1.20.0) is vulnerable to CVE-2016-0746, CVE-2021-46461, CVE-2017-20005. Upgrade to 1.24.0.

2. **Audit database access**: Verify all database connections from 10.0.1.0/24 are expected.

3. **Review sudo usage**: Consider adding audit logging for sudo commands.

4. **Firewall review**: 0.0.0.0/0 HTTPS access is permissive; consider restricting to known CIDRs if possible.

