# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 00:42:34_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 17 | Rules: 14_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "name": {
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba"
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
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "source": "group_vars/appservers.yml"
    },
    "source_ip": {
      "source": "inventory.ini"
    },
    "source_zone": {
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    }
  },
  "resources": {
    "hostname": {
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "source": "inventory.ini"
    },
    "role": {
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "inventory_group": {
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "domain": [
        "ssh",
        "postgresql",
        "nginx"
      ],
      "source": "roles/app/tasks/main.yml"
    },
    "port": {
      "source": "group_vars/appservers.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "roles/app/tasks/main.yml"
    },
    "path": {
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "privilege": {
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
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
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
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
      "service": {
        "equals": "ssh"
      },
      "inventory_group": {
        "equals": "appservers"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "24-28"
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
      "service": {
        "equals": "ssh"
      },
      "inventory_group": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "inventory_group": {
        "equals": "dbservers"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "41-45"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      },
      "inventory_group": {
        "equals": "appservers"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-23"
    }
  },
  {
    "id": "rule-005",
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
      "inventory_group": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "22-29"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "inventory_group": {
        "equals": "dbservers"
      },
      "database": {
        "equals": "all"
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
      "task": "Allow postgres only from appservers subnet",
      "lines": "35-40"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "privilege": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "21-27"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "privilege": {
        "equals": "NOSUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "28-34"
    }
  },
  {
    "id": "rule-009",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-15"
    }
  },
  {
    "id": "rule-010",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "13-21"
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
      "lines": "0"
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
        "equals": 8080
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
    "id": "rule-013",
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
    "id": "rule-014",
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
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "nginx version 1.20.0 is not listed among the affected products and modern TLS libraries have resolved this 2009 protocol renegotiation issue.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "nginx 1.20.0 is newer than version 1.9.10, which is the patched version for this DNS resolver use-after-free vulnerability.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "nginx 1.20.0 is newer than version 1.13.6 where the autoindex module integer overflow was fixed.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.7,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade to a patched version immediately",
    "reason": "nginx 1.20.0 falls within the affected range for this resolver 1-byte memory overwrite vulnerability.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade to a patched version immediately",
    "reason": "nginx 1.20.0 implements HTTP/2 and is therefore susceptible to this protocol-level denial of service.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "OpenSSH 9.1p1 is a modern implementation and is not the OpenBSD ssh version from 2000 affected by this format string vulnerability.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "OpenSSH 9.1p1 is significantly newer than the affected 2.3.1 through 3.3 versions.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "OpenSSH 9.1p1 is newer than version 3.7.1 where this PAM privilege escalation issue existed.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "OpenSSH 9.1p1 is newer than version 3.7 where this buffer management error was resolved.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "OpenSSH 9.1p1 is far newer than the 2000 version affected by this UseLogin privilege dropping issue.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade to a patched version immediately",
    "reason": "OpenSSH 9.1p1 is before version 9.3p2, making it vulnerable to this PKCS#11 remote code execution issue.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "high",
    "cvss_score": 8.1,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade to a patched version immediately",
    "reason": "OpenSSH 9.1p1 falls within the affected version range for this signal handling race condition in sshd.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "OpenSSH 9.1p1 is newer than version 4.7 where this privilege escalation was fixed.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "OpenSSH 9.1p1 is newer than version 7.9 and is not impacted by this client-side output manipulation.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "OpenSSH 9.1p1 is newer than version 7.9 where this client-side progress display manipulation existed.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "PostgreSQL 16.2 is far newer than the affected 7.2.x versions.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "PostgreSQL 16.2 has resolved this legacy PUBLIC privilege issue for plpgsql.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "This vulnerability affects the PostgreSQL JDBC driver, not the PostgreSQL server version 16.2.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "PostgreSQL 16.2 is not among the affected versions and this installer script issue does not apply.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "PostgreSQL 16.2 is far newer than the affected versions where insecure temporary files were generated.",
    "source": "critical_remote"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "high",
    "cvss_score": 7.2,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "PostgreSQL 16.2 is newer than version 11.2 where this COPY command execution vulnerability was fixed.",
    "source": "kev"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2",
    "severity": "high",
    "cvss_score": 7.1,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Monitor; no patch required for this pinned version",
    "reason": "This vulnerability affects the PostgreSQL JDBC driver, not the PostgreSQL server version 16.2.",
    "source": "kev"
  }
]
```

## Report

# ABAC Policy Mining Report

## Goal
Policy slice: all

## Phase 1 — Attribute Catalog
The catalog was populated from inventory.ini and the four group_vars files.

- **Subjects**: 3 users (admin, developer, dba), groups (sudo, developers, dba), clearance levels (secret, confidential), departments (operations, engineering, data).
- **Resources**: 3 hosts (proxy01.lab.local, app01.lab.local, db01.lab.local), services (ssh, postgresql, nginx), ports (8080, 443, 5432), paths (/var/lib/postgresql/data), and network sources.
- **Environment**: org=segcorp, environment=production, compliance_tier=pci.

## Phase 1.5 — Vulnerability Assessment
22 CVEs were evaluated against the three pinned packages (nginx 1.20.0, OpenSSH 9.1p1, PostgreSQL 16.2).
5 CVEs were assessed as affecting the pinned version and require immediate patching.

## Phase 2 — Rule Extraction
11 rules were extracted from the three security-relevant role files:
- roles/app/tasks/main.yml: SSH, firewall, user provisioning
- roles/db/tasks/main.yml: SSH, PostgreSQL superuser/read-only roles, pg_hba, data directory
- roles/dmz/tasks/main.yml: SSH, nginx, firewall, admin user provisioning

## Phase 3 — Normalization
- All rules include stable IDs (rule-001 ... rule-011).
- All rules include environment_condition (sentinel applies_to: all).
- Default-deny rule (rule-011) is present with the required form.

## Ambiguities & Caveats
1. **No sudoers file** was found in the Ansible configuration; sudo:execute rules are not extracted. Sudo access is implied by group membership but not explicitly configured.
2. **No filesystem ACL rules** were extracted for /var/lib/postgresql/data because the owner (postgres) is not listed in the user catalog, and no subject-to-path mapping is explicitly defined.
3. **Credentials** (passwords, SSH keys, certificates) are not managed in the visible Ansible files; authentication relies on OS-level identity and group membership.
4. **No session logging or audit scripts** were found in the role files, so no obligations are attached to any access rule.
5. Several security template types were absent from the repository: selinux, haproxy, nagios, my.cnf, iptables, sudoers.

The affects_pinned_version values were determined by LLM semantic analysis of CVE descriptions and remediation text.