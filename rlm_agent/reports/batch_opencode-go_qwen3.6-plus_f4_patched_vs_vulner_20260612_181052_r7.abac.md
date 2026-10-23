# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:16:07_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 15_  
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
        "uid": null,
        "groups": [],
        "clearance": null,
        "department": null,
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance_levels": [
      {
        "value": "secret",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "confidential",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "value": "operations",
        "domain": [
          "operations",
          "engineering"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "engineering",
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
        "host_group": "webservers_patched",
        "source": "group_vars/webservers_patched.yml"
      },
      {
        "name": "nginx",
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
      },
      {
        "name": "openssh-server",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers_patched",
        "source": "group_vars/all.yml"
      },
      {
        "name": "openssh-server",
        "port": 22,
        "protocol": "tcp",
        "host_group": "webservers_legacy",
        "source": "group_vars/all.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "roles/db/tasks/main.yml"
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
        "path": "/etc/postgresql/pg_hba.conf",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "openssh-server",
        "source": "roles/web_legacy/tasks/main.yml"
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
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers_legacy.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "patchcorp",
      "domain": [
        "patchcorp"
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
        "hipaa",
        "pci-dss",
        "iso27001"
      ],
      "source": "inventory.ini"
    },
    "log_retention_days": {
      "value": 90,
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
    "rule_id": "rule-001",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "openssh-server"
      },
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "webservers_legacy"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
    "rule_id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "openssh-server"
      },
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "webservers_patched"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
        "equals": "webservers_legacy"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
        "equals": "webservers_patched"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
    "rule_id": "rule-005",
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
    "rule_id": "rule-006",
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
    "rule_id": "rule-007",
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
    "rule_id": "rule-008",
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
    "action": "filesystem:execute",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
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
    "rule_id": "rule-009",
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
      "file": "policy-default",
      "task": "default-deny",
      "lines": [
        1,
        1
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
    "id": "rule-002",
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
    "id": "rule-003",
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
    "id": "rule-004",
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
  },
  {
    "id": "rule-005",
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
  },
  {
    "id": "rule-006",
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via "
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia"
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of "
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "cvss_score": 7.7,
    "severity": "high",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit "
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Not applicable to 9.6p1",
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "affects_pinned_version": false,
    "recommendation": "Review and update if affected",
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requir"
  }
]
```

## Report

# ABAC Policy Report: Ansible Configuration Mining

## Overview
Mined ABAC policy from Ansible configuration rooted at `RLM_ANSIBLE_DIR`.
Policy goal: `all` (full coverage).

## Catalog Summary

### Subjects
- **Users**: 3 (admin, appuser, postgres)
- **Groups**: 2 (sudo, developers)
- **Clearance levels**: secret, confidential
- **Departments**: operations, engineering

### Resources
- **Hosts**: 3 (web-new01, web-old01, db01)
- **Services**: nginx (443/tcp), postgresql (5432/tcp), openssh-server (22/tcp)
- **Paths**: /var/lib/postgresql/data, /etc/postgresql/pg_hba.conf, /etc/ssh/sshd_config
- **Networks**: 10.0.1.0/24 (web_subnet), 0.0.0.0/0 (internet)

### Environment
- **Org**: patchcorp
- **Environment**: production
- **Compliance tier**: soc2
- **Log retention**: 90 days

## Rules Extracted (9 total)

| ID | Action | Effect | Scope |
|----|--------|--------|-------|
| rule-001 | ssh:login | permit | sudo group → webservers_legacy |
| rule-002 | ssh:login | permit | sudo group → webservers_patched |
| rule-003 | network:connect | permit | 0.0.0.0/0 → port 443/tcp webservers_legacy |
| rule-004 | network:connect | permit | 0.0.0.0/0 → port 443/tcp webservers_patched |
| rule-005 | network:connect | permit | 10.0.1.0/24 → postgresql:5432 dbservers |
| rule-006 | filesystem:read | permit | postgres → /var/lib/postgresql/data |
| rule-007 | filesystem:write | permit | postgres → /var/lib/postgresql/data |
| rule-008 | filesystem:execute | permit | postgres → /var/lib/postgresql/data |
| rule-009 | * | deny | default-deny (all) |

## Vulnerability Assessment

### Pinned Software
| Package | Version | Host Group |
|---------|---------|------------|
| nginx | 1.24.0-2ubuntu1 (patched) / 1.20.0-1~focal (legacy) | webservers |
| postgresql | 16.2-1.pgdg22.04+1 | dbservers |
| openssh | 1:9.6p1-3ubuntu1 | webservers |

### Critical/Remote Vulnerabilities Found
- **nginx**: 4 CVEs evaluated. None directly affect the pinned versions (CVE-2016-0746 requires <1.9.10; others target njs module or older versions).
- **postgresql**: 5 CVEs evaluated. All target versions older than 16.x; current 16.2 appears unaffected.
- **openssh**: 5 CVEs evaluated. All target versions 7.x/8.x or earlier; current 9.6p1 is not affected.

### Known Exploited Vulnerabilities (KEV)
No actively exploited vulnerabilities (KEV) were found for the pinned product versions in the queried results.

### Risk Summary
The legacy nginx version (1.20.0) is older than the patched version (1.24.0) and may be vulnerable to CVEs fixed between those releases. Recommend prioritizing the legacy web server upgrade.

## Ambiguities

1. **Filesystem rules convention**: The postgres user has no explicit group membership in the Ansible catalog. Filesystem rules for `/var/lib/postgresql/data` use `user` predicate instead of `groups` due to lack of group data. A `postgres` system group could be inferred but was not explicitly defined.

2. **pg_hba.conf implicit deny**: The `pg_hba.conf` configuration only contains an allow rule for `10.0.1.0/24`. PostgreSQL's default-deny behavior (reject all other connections) is implicit but not explicitly configured as a task.

3. **No sudoers file**: No sudoers configuration was found in the Ansible roles. The `sudo` group existence is defined in `group_vars/all.yml` but no sudo privilege delegation rules were extracted.

4. **No SELinux policy**: No SELinux boolean or policy tasks were found in any role.

5. **No session logging/audit obligations**: No audit logging, profile.d scripts, or session recording configurations were found in the extracted tasks.

6. **No credentials exposure detected**: No hardcoded passwords, API keys, or secrets were found in the scanned files.

## Methodology
- Phase 1: Cataloged inventory, group_vars for subjects/resources/environment
- Phase 1.5: Queried vulnx for critical/remote and KEV vulnerabilities
- Phase 1.6: Classified files by path pattern for security relevance
- Phase 2: Extracted rules from 3 role task files
- Phase 3: Normalized attribute references and assigned stable IDs
- Phase 4: Validated JSON serialization
