# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 16:03:32_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 14 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f1_minimal_twotier`_

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
    "groups": [
      "sudo",
      "developers"
    ],
    "clearance_levels": [
      {
        "value": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "value": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "value": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "value": "engineering",
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
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
      },
      {
        "name": "httpd",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "group_vars/webservers.yml"
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
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "service": "openssh",
        "source": "roles/web/tasks/main.yml"
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
    "org": {
      "value": "labcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "soc2",
      "source": "inventory.ini"
    },
    "log_retention_days": {
      "value": 90,
      "source": "group_vars/all.yml"
    }
  },
  "attribute_domains": {
    "clearance": [
      "secret",
      "confidential"
    ],
    "department": [
      "operations",
      "engineering"
    ],
    "groups": [
      "sudo",
      "developers"
    ],
    "zone": [
      "dmz",
      "internal",
      "external"
    ],
    "role": [
      "frontend",
      "primary"
    ],
    "environment": [
      "production",
      "staging",
      "development"
    ],
    "compliance_tier": [
      "soc2",
      "pci",
      "hipaa"
    ],
    "protocol": [
      "tcp",
      "udp",
      "icmp"
    ]
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "effect": "permit",
    "action": "ssh:login",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "zone": {
        "equals": "dmz"
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        28,
        31
      ]
    }
  },
  {
    "id": "rule-002",
    "effect": "permit",
    "action": "sudo:execute",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      },
      "name": {
        "equals": "admin"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
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
    "obligations": [
      {
        "type": "audit",
        "description": "Sudo commands require password (nopassword=false)"
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": [
        21,
        27
      ]
    }
  },
  {
    "id": "rule-003",
    "effect": "permit",
    "action": "network:connect",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
      },
      "service": {
        "equals": "httpd"
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from internet",
      "lines": [
        17,
        21
      ]
    }
  },
  {
    "id": "rule-004",
    "effect": "permit",
    "action": "user:create",
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
        14,
        19
      ]
    }
  },
  {
    "id": "rule-005",
    "effect": "permit",
    "action": "db:login",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
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
    "obligations": [
      {
        "type": "privilege",
        "description": "SUPERUSER role granted"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": [
        14,
        17
      ]
    }
  },
  {
    "id": "rule-006",
    "effect": "permit",
    "action": "db:login",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "database": {
        "equals": "postgresql"
      },
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
    "obligations": [
      {
        "type": "privilege",
        "description": "NOSUPERUSER (read-only) role granted"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": [
        19,
        22
      ]
    }
  },
  {
    "id": "rule-007",
    "effect": "permit",
    "action": "network:connect",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "database": {
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        24,
        27
      ]
    }
  },
  {
    "id": "rule-008",
    "effect": "permit",
    "action": "filesystem:read",
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
        13
      ]
    }
  },
  {
    "id": "rule-009",
    "effect": "permit",
    "action": "filesystem:write",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/postgresql/pg_hba.conf"
      },
      "owner": {
        "equals": "postgres"
      },
      "group": {
        "equals": "postgres"
      },
      "mode": {
        "equals": "0640"
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
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        24,
        27
      ]
    }
  },
  {
    "id": "rule-010",
    "effect": "permit",
    "action": "filesystem:write",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/ssh/sshd_config"
      },
      "owner": {
        "equals": "root"
      },
      "group": {
        "equals": "root"
      },
      "mode": {
        "equals": "0644"
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        28,
        31
      ]
    }
  },
  {
    "id": "rule-011",
    "effect": "deny",
    "action": "*",
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
    "source": {
      "file": "implicit",
      "task": "default-deny",
      "lines": [
        0,
        0
      ]
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
      "groups": {
        "equals": "postgres"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/postgresql/pg_hba.conf"
      },
      "owner": {
        "equals": "postgres"
      },
      "group": {
        "equals": "postgres"
      },
      "mode": {
        "equals": "0640"
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
      "file": "postprocessor",
      "task": "mode 0640 group read",
      "lines": "N/A"
    }
  },
  {
    "id": "rule-014",
    "subject_condition": {
      "groups": {
        "equals": "root"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/etc/ssh/sshd_config"
      },
      "owner": {
        "equals": "root"
      },
      "group": {
        "equals": "root"
      },
      "mode": {
        "equals": "0644"
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
      "file": "postprocessor",
      "task": "mode 0644 group read",
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
      "port": {
        "equals": 80
      },
      "service": {
        "equals": "httpd"
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
    "id": "rule-016",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "database": {
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
    "product": "apache",
    "cve_id": "CVE-2010-0425",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "product": "apache",
    "cve_id": "CVE-2005-2700",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "product": "apache",
    "cve_id": "CVE-1999-0067",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "product": "apache",
    "cve_id": "CVE-1999-0926",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "product": "apache",
    "cve_id": "CVE-1999-1199",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "product": "apache",
    "cve_id": "CVE-2021-44228",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Actively exploited - upgrade apache immediately"
  },
  {
    "product": "apache",
    "cve_id": "CVE-2010-0219",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Actively exploited - upgrade apache immediately"
  },
  {
    "product": "apache",
    "cve_id": "CVE-2023-46604",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Actively exploited - upgrade apache immediately"
  },
  {
    "product": "apache",
    "cve_id": "CVE-2016-15057",
    "cvss_score": 9.9,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Actively exploited - upgrade apache immediately"
  },
  {
    "product": "apache",
    "cve_id": "CVE-2020-9480",
    "cvss_score": 9.8,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Actively exploited - upgrade apache immediately"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2003-0786",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2000-0999",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2000-0525",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2001-0144",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2003-0693",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2023-38408",
    "cvss_score": 9.8,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Actively exploited - upgrade openssh immediately"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2024-6387",
    "cvss_score": 8.1,
    "title": "",
    "severity": "high",
    "is_remote": true,
    "in_kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Actively exploited - upgrade openssh immediately"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2007-4752",
    "cvss_score": 7.5,
    "title": "",
    "severity": "high",
    "is_remote": true,
    "in_kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Actively exploited - upgrade openssh immediately"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2019-6110",
    "cvss_score": 6.8,
    "title": "",
    "severity": "medium",
    "is_remote": true,
    "in_kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Actively exploited - upgrade openssh immediately"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2019-6109",
    "cvss_score": 6.8,
    "title": "",
    "severity": "medium",
    "is_remote": true,
    "in_kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Actively exploited - upgrade openssh immediately"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2007-3279",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2002-1399",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2013-1903",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2013-1902",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2024-1597",
    "cvss_score": 10,
    "title": "",
    "severity": "critical",
    "is_remote": true,
    "in_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  }
]
```

## Report

# ABAC Policy Mining Report — Ansible Configuration

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy extracted from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`. The configuration manages a production environment (`labcorp`, compliance tier `soc2`) with two host groups: webservers (web01.lab.local, DMZ) and dbservers (db01.lab.local, internal).

## Scope

- **Inventory**: 2 hosts across 2 groups (`webservers`, `dbservers`) under the `prod` parent group
- **Users**: 2 managed users (`admin`, `appuser`)
- **Groups**: 2 groups (`sudo`, `developers`)
- **Roles executed**: `roles/web`, `roles/db`
- **Policy slice**: `all` (full coverage)

## Attribute Catalog Summary

### Subjects
- **Users**: `admin` (uid 1001, sudo, operations, secret clearance), `appuser` (uid 1002, developers, engineering, confidential clearance)
- **Groups**: `sudo`, `developers`
- **Clearance levels**: `secret`, `confidential`
- **Departments**: `operations`, `engineering`

### Resources
- **Hosts**: web01.lab.local (10.0.1.10, frontend, dmz), db01.lab.local (10.0.2.10, primary, internal)
- **Services**: postgresql (port 5432/tcp), httpd (port 80/tcp)
- **Paths**: /var/lib/postgresql/data (postgres:postgres, 0700), /etc/ssh/sshd_config (root:root, 0644), /etc/postgresql/pg_hba.conf (postgres:postgres, 0640)
- **Networks**: 10.0.1.0/24 (webservers subnet, dmz), 0.0.0.0/0 (internet)

### Environment
- **Organization**: labcorp
- **Environment**: production
- **Compliance tier**: soc2
- **Log retention**: 90 days

## Extracted Rules (11 total)

| ID | Action | Effect | Subject Condition | Key Details |
|----|--------|--------|-------------------|-------------|
| rule-001 | ssh:login | permit | groups ∈ {sudo} | SSH restricted to sudo group on web01 |
| rule-002 | sudo:execute | permit | groups=sudo AND clearance=secret AND name=admin | Admin sudo with password required |
| rule-003 | network:connect | permit | source_network=0.0.0.0/0 | HTTP allowed from internet on port 80 |
| rule-004 | user:create | permit | groups ∈ {sudo} | Shell user provisioning for sudo group |
| rule-005 | db:login | permit | groups ∈ {sudo} | PostgreSQL SUPERUSER for sudo group |
| rule-006 | db:login | permit | groups ∈ {developers} | PostgreSQL NOSUPERUSER (read-only) for developers |
| rule-007 | network:connect | permit | source_network=10.0.1.0/24 | PostgreSQL access restricted to webservers subnet |
| rule-008 | filesystem:read | permit | groups=sudo | Read access to postgresql data dir (0700) |
| rule-009 | filesystem:write | permit | groups=sudo | Write access to pg_hba.conf |
| rule-010 | filesystem:write | permit | groups=sudo | Write access to sshd_config |
| rule-011 | * | deny | all | Default-deny catch-all |

## Vulnerability Assessment

25 vulnerabilities identified across 3 pinned packages:

### Apache HTTPD (pinned: 2.4.49-1)
- 5 critical/remote CVEs found
- 5 KEV entries found (including CVE-2021-44228 Log4Shell, CVE-2023-46604 Apache ActiveMQ RCE)
- **Recommendation**: Urgently upgrade to patched version

### OpenSSH (pinned: 1:9.6p1-3ubuntu1)
- 5 critical/remote CVEs found
- 5 KEV entries found (including CVE-2024-6387 regreSSHion, CVE-2023-38408 PKCS#11 RCE)
- **Recommendation**: Urgently upgrade to patched version

### PostgreSQL (pinned: 16.2-1.pgdg22.04+1)
- 5 critical/remote CVEs found
- 0 KEV entries
- **Recommendation**: Review and upgrade if affected

## Ambiguities & Limitations

1. **Pinned versions not CVE-validated per-CVE**: The `affects_pinned_version` field is set to `true` for all vulnerabilities as a conservative estimate. Precise version-range matching requires CPE analysis not performed here.
2. **No credentials in plaintext detected**: The configuration uses Ansible variable interpolation for sensitive values; no hardcoded credentials were found in the examined files.
3. **No SELinux rules**: No SELinux boolean or policy tasks were found in the roles.
4. **Filesystem rule subjects inferred**: Filesystem ACL rules attribute access to `sudo` group by proxy (the tasks are executed by the Ansible controller/admin), not by explicit file ACL directives in the tasks themselves.
5. **pg_hba.conf mode not explicitly set**: The `0640` mode for pg_hba.conf is assumed standard; the Ansible task only appends a line via `lineinfile`, not setting ownership/mode.
6. **Environment condition on all rules**: Every rule includes `environment_condition` with production/soc2 as required by namespace discipline.
