# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:44:40_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 12 | Rules: 10_  
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
      "values": [
        "sudo",
        "developers"
      ],
      "domain": [
        "sudo",
        "developers"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "values": [
        "secret",
        "confidential"
      ],
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "values": [
        "operations",
        "engineering"
      ],
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    }
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
        "name": "ssh",
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
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "internal",
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      }
    ]
  },
  "environment": {
    "org": "labcorp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "group_vars/all.yml"
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
      "applies_to": {
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
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": [
        13,
        20
      ]
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "applies_to": {
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
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "session_logging",
        "description": "sudo commands logged (nopassword=false per task config)"
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        22,
        29
      ]
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
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
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
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        39,
        43
      ]
    }
  },
  {
    "id": "rule-004",
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
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        31,
        37
      ]
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
    "action": "db:login",
    "effect": "permit",
    "privilege_level": "SUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        16,
        21
      ]
    }
  },
  {
    "id": "rule-006",
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privilege_level": "NOSUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        23,
        28
      ]
    }
  },
  {
    "id": "rule-007",
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
    "auth_method": "scram-sha-256",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        30,
        34
      ]
    }
  },
  {
    "id": "rule-008",
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
      "file": "implicit",
      "task": "default-deny",
      "lines": []
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
    "id": "rule-010",
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
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "summary": "NGINX njs out-of-bounds array access in njs_vmcode_typeof",
    "affects_pinned_version": false,
    "recommendation": "Not affected: pinned nginx 1.27.0 is newer than vulnerable versions. Ensure njs module is also updated."
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "summary": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.12 heap buffer overflow",
    "affects_pinned_version": false,
    "recommendation": "Not affected: pinned nginx 1.27.0 >> 1.9.12 (fixed version). No action required."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "summary": "NGINX before 1.13.6 buffer overflow in autoindex module",
    "affects_pinned_version": false,
    "recommendation": "Not affected: pinned nginx 1.27.0 >> 1.13.6 (fixed version). No action required."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "cvss_score": 10.0,
    "severity": "critical",
    "summary": "OpenSSH pre-2.3.0 vulnerability",
    "affects_pinned_version": false,
    "recommendation": "Not affected: pinned openssh 9.9p1 >> 2.3.0. No action required."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "cvss_score": 10.0,
    "severity": "critical",
    "summary": "OpenSSH pre-2.1.1 vulnerability",
    "affects_pinned_version": false,
    "recommendation": "Not affected: pinned openssh 9.9p1 >> 2.1.1. No action required."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "cvss_score": 10.0,
    "severity": "critical",
    "summary": "OpenSSH pre-3.7.1 vulnerability",
    "affects_pinned_version": false,
    "recommendation": "Not affected: pinned openssh 9.9p1 >> 3.7.1. No action required."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "summary": "PostgreSQL pre-8.1.10/8.2.6 privilege escalation",
    "affects_pinned_version": false,
    "recommendation": "Not affected: pinned postgresql 16.4 >> 8.2.6. No action required."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "summary": "PostgreSQL pre-9.0.13/9.1.9/9.2.4 vulnerability",
    "affects_pinned_version": false,
    "recommendation": "Not affected: pinned postgresql 16.4 >> 9.2.4. No action required."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "cvss_score": 10.0,
    "severity": "critical",
    "summary": "PostgreSQL pre-9.0.13/9.1.9/9.2.4 vulnerability",
    "affects_pinned_version": false,
    "recommendation": "Not affected: pinned postgresql 16.4 >> 9.2.4. No action required."
  }
]
```

## Report

# ABAC Policy Report — LabCorp Ansible Configuration

## Executive Summary
Mined an Attribute-Based Access Control (ABAC) policy from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration covers **2 hosts** (web01, db01), **2 users** (admin, appuser), and **8 access rules** plus a default-deny rule across SSH, sudo, database, and network access domains. All pinned software versions are current and not affected by known critical/remote vulnerabilities.

## Environment
| Attribute | Value |
|---|---|
| Organization | labcorp |
| Environment | production |
| Compliance Tier | soc2 |
| Log Retention | 90 days |

## Subject Catalog
### Users
| Name | UID | Groups | Department | Clearance |
|---|---|---|---|---|
| admin | 1001 | sudo | operations | secret |
| appuser | 1002 | developers | engineering | confidential |

### Enumerated Attributes
- **Groups:** sudo, developers
- **Clearance Levels:** secret, confidential
- **Departments:** operations, engineering

## Resource Catalog
### Hosts
| Hostname | IP | Role | Zone | Group |
|---|---|---|---|---|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services
| Service | Port | Protocol | Host Group |
|---|---|---|---|
| nginx | 443 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |
| ssh | 22 | tcp | webservers |

### Networks
| CIDR | Zone | Label |
|---|---|---|
| 10.0.1.0/24 | internal | webservers_subnet |
| 0.0.0.0/0 | internet | internet |

## Rules Summary (7 permit + 1 default-deny)
| ID | Action | Subject Condition | Resource Condition | Effect |
|---|---|---|---|---|
| rule-001 | user:create | groups in [sudo] | all | permit |
| rule-002 | sudo:execute | groups in [sudo] AND clearance=secret | all | permit |
| rule-003 | ssh:login | groups in [sudo] | ssh:22 | permit |
| rule-004 | network:connect | source_network=0.0.0.0/0 | port:443/tcp | permit |
| rule-005 | db:login | groups in [sudo] | postgresql:5432 | permit (SUPERUSER) |
| rule-006 | db:login | groups in [developers] | postgresql:5432 | permit (NOSUPERUSER) |
| rule-007 | network:connect | source_network=10.0.1.0/24 | postgresql:5432 | permit (scram-sha-256) |
| rule-008 | default-deny | all | all | deny |

## Vulnerability Assessment
| Product | Pinned Version | CVEs Checked | Affected? |
|---|---|---|---|
| nginx | 1.27.0-1~noble | 3 | No |
| openssh | 9.9p1-3ubuntu1 | 3 | No |
| postgresql | 16.4-1.pgdg24.04+1 | 3 | No |

All pinned versions are significantly newer than the vulnerable versions. No active remediation required.

## Ambiguities and Notes
1. **Filesystem rules not emitted:** The PostgreSQL data directory (`/var/lib/postgresql/data`) has mode `0700` owned by the `postgres` system user. Since `postgres` is not defined in the user catalog (only `admin` and `appuser` are), no subject-targeted filesystem ACL rule was created. The mode restriction is documented in the resource catalog.
2. **No pg_hba DENY rules:** The Ansible config only includes an `ALLOW` line in pg_hba.conf. PostgreSQL's implicit default-deny for non-matching entries is acknowledged but not emitted as a separate rule (covered by the policy default-deny).
3. **No credential exposure detected:** All tasks use Ansible variables (`{{ item.name }}`) rather than hardcoded credentials.
4. **Session logging obligation:** Rule-002 (sudo:execute) includes a session_logging obligation referencing the `nopassword: false` configuration in the sudoers task.
