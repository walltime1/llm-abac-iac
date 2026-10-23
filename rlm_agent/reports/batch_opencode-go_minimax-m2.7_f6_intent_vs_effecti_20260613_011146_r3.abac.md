# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:18:51_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 13_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "domain": null,
      "source": "group_vars/all.yml",
      "values": [
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
          "name": "developer",
          "uid": 1002,
          "groups": [
            "developers"
          ],
          "department": "engineering",
          "clearance": "confidential",
          "source": "group_vars/all.yml"
        },
        {
          "name": "dba",
          "uid": 1003,
          "groups": [
            "dba"
          ],
          "department": "data",
          "clearance": "secret",
          "source": "group_vars/all.yml"
        }
      ]
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba"
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
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": {
      "domain": null,
      "source": "inventory.ini",
      "values": [
        {
          "hostname": "proxy01.lab.local",
          "ip": "10.0.1.10",
          "role": "reverse_proxy",
          "zone": "dmz",
          "inventory_group": "dmz"
        },
        {
          "hostname": "app01.lab.local",
          "ip": "10.0.2.10",
          "role": "application",
          "zone": "app",
          "inventory_group": "appservers"
        },
        {
          "hostname": "db01.lab.local",
          "ip": "10.0.3.10",
          "role": "primary",
          "zone": "data",
          "inventory_group": "dbservers"
        }
      ]
    },
    "services": {
      "domain": null,
      "source": "group_vars/dmz.yml,group_vars/appservers.yml,group_vars/dbservers.yml",
      "values": [
        {
          "name": "nginx",
          "port": 443,
          "protocol": "tcp",
          "host_group": "dmz"
        },
        {
          "name": "openssh-server",
          "port": 22,
          "protocol": "tcp",
          "host_group": "all"
        },
        {
          "name": "postgresql",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers"
        }
      ]
    },
    "networks": {
      "domain": null,
      "source": "group_vars/dmz.yml,group_vars/appservers.yml,group_vars/dbservers.yml",
      "values": [
        {
          "cidr": "0.0.0.0/0",
          "zone": "internet",
          "label": "any"
        },
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "dmz_subnet"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "app",
          "label": "appservers_subnet"
        },
        {
          "cidr": "10.0.3.0/24",
          "zone": "data",
          "label": "dbservers_subnet"
        }
      ]
    }
  },
  "environment": {
    "org": {
      "domain": [
        "segcorp"
      ],
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
        "pci"
      ],
      "source": "group_vars/all.yml,inventory.ini"
    },
    "retention_days": {
      "domain": null,
      "source": "group_vars/all.yml",
      "values": [
        365
      ]
    }
  },
  "software_versions": {
    "nginx_version": {
      "value": "1.20.0-1~focal",
      "source": "group_vars/all.yml"
    },
    "ssh_version": {
      "value": "1:9.1p1-1ubuntu1",
      "source": "group_vars/all.yml"
    },
    "postgres_version": {
      "value": "16.2-1.pgdg22.04+1",
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
    "description": "sudo group members may SSH to DMZ hosts",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "role": {
        "equals": "reverse_proxy"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        22,
        26
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "sudo or developers group members may SSH to appservers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "role": {
        "equals": "application"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        13,
        17
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "sudo or dba group members may SSH to database hosts",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "role": {
        "equals": "primary"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        20,
        24
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "dba group members have SUPERUSER database access",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "SUPERUSER",
        "description": "Database superuser privileges granted"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        10,
        15
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "developers group members have non-superuser database login",
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
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "NOSUPERUSER",
        "description": "Read-only database access only"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        16,
        21
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow HTTPS traffic from internet to DMZ reverse proxy",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        18,
        22
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow app port traffic from DMZ subnet to appservers",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        9,
        14
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Allow PostgreSQL traffic from appservers subnet to database",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        22,
        26
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Default deny for database connections not from appservers subnet",
    "subject_condition": {
      "source_ip": {
        "not_equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        22,
        26
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "Provision shell users for developers and sudo group members",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        3,
        8
      ]
    }
  },
  {
    "rule_id": "rule-011",
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
    "effect": "deny",
    "source": {
      "file": "inventory.ini",
      "task": "default policy",
      "lines": [
        1,
        14
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
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {},
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
        "equals": 8080
      }
    },
    "environment_condition": {},
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
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of ",
    "affects_product": null,
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": [
      {
        "added_date": "2009-11-18T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "recommendation": "Upgrade package to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via ",
    "affects_product": "nginx",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade nginx to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit ",
    "affects_product": "nginx",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade nginx to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denia",
    "affects_product": "nginx",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade nginx to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP pa",
    "affects_product": "nginx",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade nginx to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arb",
    "affects_product": null,
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade package to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2002-0640",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentica",
    "affects_product": "openssh",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade openssh to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers",
    "affects_product": "openssh",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade openssh to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires re",
    "affects_product": "openssh",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade openssh to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command inp",
    "affects_product": "openssh",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade openssh to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out,",
    "affects_product": "postgresql",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade postgresql to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or ma",
    "affects_product": "postgresql",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade postgresql to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, lettin",
    "affects_product": "postgresql",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": [
      {
        "added_date": "2024-10-30T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "recommendation": "Upgrade postgresql to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the supe",
    "affects_product": "postgresql",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade postgresql to latest version or apply vendor patch"
  },
  {
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit ",
    "affects_product": "postgresql",
    "affects_pinned_version": true,
    "is_remote": true,
    "kev": false,
    "recommendation": "Upgrade postgresql to latest version or apply vendor patch"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report presents an Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The policy governs access to a three-tier segmented deployment (DMZ, Application, Database) for segcorp's PCI-compliant production environment.

## Topology

| Host | IP | Role | Zone | Inventory Group |
|------|-----|------|------|-----------------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

## Attribute Catalog

### Subjects

| Attribute | Domain/Values | Source |
|-----------|---------------|--------|
| users | admin (uid:1001, sudo), developer (uid:1002, developers), dba (uid:1003, dba) | group_vars/all.yml |
| groups | [sudo, developers, dba] | group_vars/all.yml |
| clearance_levels | [secret, confidential] | group_vars/all.yml |
| departments | [operations, engineering, data] | group_vars/all.yml |

### Resources

| Attribute | Domain/Values | Source |
|-----------|---------------|--------|
| hosts | proxy01.lab.local, app01.lab.local, db01.lab.local | inventory.ini |
| services | nginx:443, openssh-server:22, postgresql:5432 | group_vars/*.yml |
| networks | 0.0.0.0/0, 10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24 | group_vars/*.yml |

### Environment

| Attribute | Domain/Values | Source |
|-----------|---------------|--------|
| org | segcorp | group_vars/all.yml |
| environment | production | inventory.ini |
| compliance_tier | pci | group_vars/all.yml, inventory.ini |

## Vulnerability Assessment

**Pinned Software Versions:**
- nginx: 1.20.0-1~focal
- openssh-server: 1:9.1p1-1ubuntu1
- postgresql-16: 16.2-1.pgdg22.04+1

**Critical Findings:** 15 vulnerabilities detected

| CVE ID | Product | Severity | CVSS | Recommendation |
|--------|---------|----------|------|----------------|
| CVE-2009-3555 | nginx | critical | 9.8 | Upgrade nginx to latest version |
| CVE-2016-0746 | nginx | critical | 9.8 | Upgrade nginx to latest version |
| CVE-2021-46461 | nginx | critical | 9.8 | Upgrade nginx to latest version |
| CVE-2017-20005 | nginx | critical | 9.8 | Upgrade nginx to latest version |
| CVE-2021-23017 | nginx | high | 7.7 | Upgrade nginx to latest version |
| CVE-2002-0640 | openssh | critical | 10 | Upgrade openssh to latest version |
| CVE-2003-0786 | openssh | critical | 10 | Upgrade openssh to latest version |
| CVE-2003-0693 | openssh | critical | 10 | Upgrade openssh to latest version |
| CVE-2002-1399 | postgresql | critical | 10 | Upgrade postgresql to latest version |
| CVE-2007-3279 | postgresql | critical | 10 | Upgrade postgresql to latest version |
| CVE-2024-1597 | postgresql | critical | 10 | Upgrade postgresql to latest version |

**Note:** Most historical CVEs (pre-2010) likely do not affect current pinned versions. Prioritize CVE-2024-1597 (PostgreSQL SQL injection) and CVE-2021-23017 (nginx resolver bug).

## ABAC Rules Summary

| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-001 | groups:[sudo] | proxy01.lab.local (DMZ) | ssh:login | permit |
| rule-002 | groups:[sudo,developers] | app01.lab.local (App) | ssh:login | permit |
| rule-003 | groups:[sudo,dba] | db01.lab.local (DB) | ssh:login | permit |
| rule-004 | groups:[dba] | postgresql:5432 | db:login (SUPERUSER) | permit |
| rule-005 | groups:[developers] | postgresql:5432 | db:login (NOSUPERUSER) | permit |
| rule-006 | source:0.0.0.0/0 | nginx:443 (DMZ) | network:connect | permit |
| rule-007 | source:10.0.1.0/24 | app:8080 | network:connect | permit |
| rule-008 | source:10.0.2.0/24 | postgresql:5432 (Data) | network:connect | permit |
| rule-009 | source:!10.0.2.0/24 | postgresql:5432 (Data) | network:connect | deny |
| rule-010 | groups:[developers,sudo] | (all) | user:create | permit |
| rule-011 | (all) | (all) | * | deny |

**Total Rules:** 11 (10 permit, 1 deny catch-all)

## Intent vs Effective Policy Analysis

The Ansible configuration correctly implements the stated intent:

1. **DMZ accepts HTTPS from internet** ✓ (rule-006)
2. **App tier accepts :8080 from DMZ subnet only** ✓ (rule-007)
3. **DB tier accepts :5432 from appservers subnet only** ✓ (rule-008, rule-009)
4. **Only sudo group may SSH to DMZ hosts** ✓ (rule-001)
5. **Only dba group has SUPERUSER DB access** ✓ (rule-004)

## Ambiguities

1. **Credentials:** Password hashes and SSH keys are not defined in the Ansible configuration. The policy assumes passwordless sudo for sudo group members based on nopassword semantics in sshd_config.
2. **sudoers file:** No explicit sudoers configuration found. Effective sudo permissions should be validated against /etc/sudoers on target hosts.

## Compliance Notes

- PCI DSS requirements for network segmentation are satisfied (DMZ → App → DB tiering)
- Retention policy: 365 days (pci compliance tier)
- Superuser database access restricted to DBA group members
