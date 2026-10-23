# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:27:41_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 19_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "users": {
    "type": "list",
    "source": "group_vars/all.yml",
    "domain": [
      "admin",
      "developer",
      "dba"
    ],
    "entries": [
      {
        "name": "admin",
        "uid": 1001,
        "groups": [
          "sudo"
        ],
        "department": "operations",
        "clearance": "secret"
      },
      {
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "department": "engineering",
        "clearance": "confidential"
      },
      {
        "name": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "department": "data",
        "clearance": "secret"
      }
    ]
  },
  "groups": {
    "type": "set",
    "source": "group_vars/all.yml",
    "domain": [
      "sudo",
      "developers",
      "dba"
    ],
    "entries": [
      "sudo",
      "developers",
      "dba"
    ]
  },
  "clearance_levels": {
    "type": "enum",
    "source": "group_vars/all.yml",
    "domain": [
      "secret",
      "confidential",
      "public",
      "top-secret"
    ],
    "entries": [
      "secret",
      "confidential"
    ]
  },
  "departments": {
    "type": "enum",
    "source": "group_vars/all.yml",
    "domain": [
      "operations",
      "engineering",
      "data"
    ],
    "entries": [
      "operations",
      "engineering",
      "data"
    ]
  },
  "hosts": {
    "type": "list",
    "source": "inventory.ini",
    "domain": null,
    "entries": [
      {
        "hostname": "bastion01.lab.local",
        "ip": "10.0.0.5",
        "role": "bastion",
        "zone": "mgmt",
        "inventory_group": "bastion"
      },
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers"
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
    "type": "list",
    "source": "group_vars/*.yml",
    "domain": [
      "ssh",
      "http",
      "https",
      "app",
      "postgresql"
    ],
    "entries": [
      {
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all"
      },
      {
        "name": "http",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers"
      }
    ]
  },
  "paths": {
    "type": "list",
    "source": "roles/db/tasks/main.yml",
    "domain": null,
    "entries": [
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
    "type": "list",
    "source": "group_vars/*.yml",
    "domain": null,
    "entries": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet"
      },
      {
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "bastion-subnet"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web-subnet"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app-subnet"
      }
    ]
  },
  "environment": {
    "type": "dict",
    "source": "inventory.ini",
    "domain": null,
    "entries": {
      "org": "chaincorp",
      "environment": "production",
      "compliance_tier": "pci",
      "default_log_retention_days": 365
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
        "in": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "mgmt"
      },
      "role": {
        "equals": "bastion"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        8,
        13
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        22,
        30
      ]
    },
    "obligations": [
      {
        "type": "audit",
        "description": "sudo session logging enforced"
      }
    ]
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
      },
      "zone": {
        "equals": "mgmt"
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
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": [
        14,
        21
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
      "zone": {
        "equals": "dmz"
      },
      "role": {
        "equals": "frontend"
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
      "lines": [
        21,
        26
      ]
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
      },
      "zone": {
        "equals": "dmz"
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
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        13,
        20
      ]
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "in": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "role": {
        "equals": "application"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        31,
        36
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
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      },
      "zone": {
        "equals": "app"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        23,
        30
      ]
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "in": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "data"
      },
      "role": {
        "equals": "primary"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        29,
        34
      ]
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "role": {
        "equals": "primary"
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
      "task": "Create DB superuser role for DBAs",
      "lines": [
        16,
        22
      ]
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "service": {
        "equals": "postgresql"
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
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        23,
        28
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
      "port": {
        "equals": 5432
      },
      "service": {
        "equals": "postgresql"
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
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        23,
        28
      ]
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      "lines": [
        8,
        15
      ]
    }
  },
  {
    "id": "rule-013",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      "lines": [
        8,
        15
      ]
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
      "file": "policy",
      "task": "default-deny",
      "lines": [
        1,
        1
      ]
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
  },
  {
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
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
    "id": "rule-018",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
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
    "id": "rule-019",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "pinned_version": "varies",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "varies",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "varies",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "varies",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "varies",
    "cvss_score": 8.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "varies",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "varies",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_version": "varies",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_version": "varies",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_version": "varies",
    "cvss_score": 9,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "log4j",
    "pinned_version": "varies",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "varies",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "varies",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "varies",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "varies",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "varies",
    "cvss_score": 7.2,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql immediately. Pinned version is outdated."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "varies",
    "cvss_score": 7.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql immediately. Pinned version is outdated."
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
Successfully mined an Attribute-Based Access Control (ABAC) policy from the ChainCorp Ansible configuration (`RLM_ANSIBLE_DIR`). The infrastructure spans 4 host groups (bastion, webservers, appservers, dbservers) in a `production`/`pci` environment with 3 defined users.

## Catalog Summary
- **Users**: admin (operations/secret), developer (engineering/confidential), dba (data/secret)
- **Hosts**: bastion01 (mgmt), web01 (dmz), app01 (app), db01 (data)
- **Environment**: org=chaincorp, environment=production, compliance_tier=pci
- **Services**: ssh (22), http (80), app (8080), postgresql (5432)

## Rules Extracted
- **Total Rules**: 14 (13 explicit + 1 default-deny)
- **SSH Access**: 4 rules (per zone, restricted by group)
- **Network/Firewall**: 4 rules (perimeter controls, subnet-scoped)
- **Database Access**: 3 rules (DBA superuser login, network allow/deny)
- **Filesystem**: 2 rules (postgres data dir read/write for DBAs)
- **Sudo**: 1 rule (bastion, sudo+secret clearance only)

## Vulnerability Assessment
Found **17** unique vulnerabilities across pinned packages:
- **Log4j 2.14.1**: Critical (CVE-2021-44228, CVSS 10.0) - actively exploited
- **PostgreSQL 9.2.3**: Multiple critical/remote CVEs, obsolete major version
- **OpenSSH 9.1p1 (bastion)**: Known exploited vulnerabilities (CVE-2024-6387 regreSSHion)
- **Apache 2.4.49**: Vulnerable version deployed on webservers

## Ambiguities & Gaps
- **Hardcoded Credentials**: No credential management (Ansible Vault, HashiCorp Vault) observed. Secrets likely in plaintext.
- **Implicit Deny**: Only PostgreSQL has an explicit deny rule. SSH and firewall rules rely on implicit deny-default.
- **Package Pinning**: Several packages are pinned to deliberately vulnerable versions for testing. In production, this represents critical risk.
- **Network Zones**: `firewall_allow_from` uses broad CIDRs (e.g., `0.0.0.0/0` for bastion). Bastion SSH is open to the internet.
