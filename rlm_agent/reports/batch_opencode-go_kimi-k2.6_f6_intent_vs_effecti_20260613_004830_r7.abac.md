# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 00:59:05_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 15 | Rules: 20_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

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
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [
          "postgres"
        ],
        "department": null,
        "clearance": null,
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba",
        "postgres"
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
    },
    "source_network": {
      "domain": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/appservers.yml / group_vars/dbservers.yml / group_vars/dmz.yml"
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "proxy01.lab.local",
        "ip": "10.0.1.10",
        "role": "reverse_proxy",
        "zone": "dmz",
        "inventory_group": "dmz",
        "source": "inventory.ini"
      },
      {
        "hostname": "app01.lab.local",
        "ip": "10.0.2.10",
        "role": "application",
        "zone": "app",
        "inventory_group": "appservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.3.10",
        "role": "primary",
        "zone": "data",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
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
        "zone": "dmz",
        "label": "DMZ subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "appservers subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet",
        "source": "group_vars/dmz.yml"
      }
    ],
    "database_privilege": {
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "value": "segcorp",
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
      "value": 365,
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
      "hostname": {
        "equals": "app01.lab.local"
      },
      "role": {
        "equals": "application"
      },
      "zone": {
        "equals": "app"
      },
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
      },
      "zone": {
        "equals": "data"
      },
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "41-45"
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
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "role": {
        "equals": "reverse_proxy"
      },
      "zone": {
        "equals": "dmz"
      },
      "inventory_group": {
        "equals": "dmz"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-004",
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
      },
      "zone": {
        "equals": "app"
      },
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-15"
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
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "role": {
        "equals": "reverse_proxy"
      },
      "zone": {
        "equals": "dmz"
      },
      "inventory_group": {
        "equals": "dmz"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "13-21"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "role": {
        "equals": "primary"
      },
      "zone": {
        "equals": "data"
      },
      "inventory_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "database_privilege": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "21-27"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "role": {
        "equals": "primary"
      },
      "zone": {
        "equals": "data"
      },
      "inventory_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "database_privilege": {
        "equals": "NOSUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "28-34"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "role": {
        "equals": "primary"
      },
      "zone": {
        "equals": "data"
      },
      "inventory_group": {
        "equals": "dbservers"
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "35-40"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "role": {
        "equals": "application"
      },
      "zone": {
        "equals": "app"
      },
      "inventory_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-23"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "role": {
        "equals": "reverse_proxy"
      },
      "zone": {
        "equals": "dmz"
      },
      "inventory_group": {
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "22-29"
    }
  },
  {
    "id": "rule-011",
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
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "13-20"
    }
  },
  {
    "id": "rule-012",
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
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "13-20"
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "13-20"
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
    "action": "*",
    "effect": "deny",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "source": {
      "file": "implicit",
      "task": "default-deny",
      "lines": "0-0"
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
        "equals": "pci"
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
    "id": "rule-018",
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
        "equals": "pci"
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
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
    "id": "rule-020",
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
        "equals": "pci"
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
    "products": [
      "nginx"
    ],
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "is_remote": true,
    "is_poc": true,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Actively exploited (KEV). Critical severity."
  },
  {
    "cve_id": "CVE-2016-0746",
    "products": [
      "nginx"
    ],
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Critical severity."
  },
  {
    "cve_id": "CVE-2021-46461",
    "products": [
      "nginx"
    ],
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "is_remote": true,
    "is_poc": true,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Critical severity."
  },
  {
    "cve_id": "CVE-2017-20005",
    "products": [
      "nginx"
    ],
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": false,
    "is_remote": true,
    "is_poc": true,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Critical severity."
  },
  {
    "cve_id": "CVE-2021-23017",
    "products": [
      "nginx"
    ],
    "severity": "high",
    "cvss_score": 7.7,
    "is_kev": false,
    "is_remote": true,
    "is_poc": true,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. High severity."
  },
  {
    "cve_id": "CVE-2023-44487",
    "products": [
      "nginx"
    ],
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "is_remote": true,
    "is_poc": true,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Actively exploited (KEV). High severity."
  },
  {
    "cve_id": "CVE-2000-0999",
    "products": [
      "openssh"
    ],
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Critical severity."
  },
  {
    "cve_id": "CVE-2002-0640",
    "products": [
      "openssh"
    ],
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Critical severity."
  },
  {
    "cve_id": "CVE-2003-0786",
    "products": [
      "openssh"
    ],
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Critical severity."
  },
  {
    "cve_id": "CVE-2003-0693",
    "products": [
      "openssh"
    ],
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Critical severity."
  },
  {
    "cve_id": "CVE-2000-0525",
    "products": [
      "openssh"
    ],
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Critical severity."
  },
  {
    "cve_id": "CVE-2023-38408",
    "products": [
      "openssh"
    ],
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "is_remote": true,
    "is_poc": true,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Actively exploited (KEV). Critical severity."
  },
  {
    "cve_id": "CVE-2024-6387",
    "products": [
      "openssh"
    ],
    "severity": "high",
    "cvss_score": 8.1,
    "is_kev": true,
    "is_remote": true,
    "is_poc": true,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Actively exploited (KEV). High severity."
  },
  {
    "cve_id": "CVE-2007-4752",
    "products": [
      "openssh"
    ],
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Actively exploited (KEV). High severity."
  },
  {
    "cve_id": "CVE-2019-6110",
    "products": [
      "openssh"
    ],
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "is_remote": true,
    "is_poc": true,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Actively exploited (KEV)."
  },
  {
    "cve_id": "CVE-2019-6109",
    "products": [
      "openssh"
    ],
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Actively exploited (KEV)."
  },
  {
    "cve_id": "CVE-2002-1399",
    "products": [
      "postgresql"
    ],
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Critical severity."
  },
  {
    "cve_id": "CVE-2007-3279",
    "products": [
      "postgresql"
    ],
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Critical severity."
  },
  {
    "cve_id": "CVE-2024-1597",
    "products": [
      "postgresql"
    ],
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Actively exploited (KEV). Critical severity."
  },
  {
    "cve_id": "CVE-2013-1903",
    "products": [
      "postgresql"
    ],
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Critical severity."
  },
  {
    "cve_id": "CVE-2013-1902",
    "products": [
      "postgresql"
    ],
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "is_poc": false,
    "affects_pinned_version": false,
    "recommendation": "Critical severity."
  },
  {
    "cve_id": "CVE-2019-9193",
    "products": [
      "postgresql"
    ],
    "severity": "high",
    "cvss_score": 7.2,
    "is_kev": true,
    "is_remote": true,
    "is_poc": true,
    "affects_pinned_version": false,
    "recommendation": "Actively exploited (KEV). High severity."
  },
  {
    "cve_id": "CVE-2022-31197",
    "products": [
      "postgresql"
    ],
    "severity": "high",
    "cvss_score": 7.1,
    "is_kev": true,
    "is_remote": true,
    "is_poc": true,
    "affects_pinned_version": false,
    "recommendation": "Apply vendor patch. Actively exploited (KEV). High severity."
  }
]
```

## Report

# ABAC Policy Mining Report

## Summary
Mined ABAC policy from the Ansible configuration rooted at `RLM_ANSIBLE_DIR`.
The deployment is a PCI-compliant production environment (`segcorp`) with three hosts: **proxy01** (DMZ reverse proxy), **app01** (application server), and **db01** (primary database).
Three human users are defined—**admin**, **developer**, and **dba**—plus the **postgres** system user.
Pinned packages: nginx `1.20.0`, openssh `9.1p1`, postgresql `16.2`.

## Attribute Catalog
### Subjects
- **Users**: 4 entries (admin, developer, dba, postgres).
- **Groups**: sudo, developers, dba, postgres.
- **Clearance levels**: secret, confidential.
- **Departments**: operations, engineering, data.
- **Source networks**: `10.0.1.0/24` (DMZ), `10.0.2.0/24` (appservers), `0.0.0.0/0` (internet).

### Resources
- **Hosts**: 3 hosts with role, zone, and inventory group.
- **Services**: 3 services (nginx/443, app/8080, postgresql/5432).
- **Paths**: 1 path (`/var/lib/postgresql/data`, owner postgres, mode 0700).
- **Networks**: 3 CIDR ranges.

### Environment
- org: `segcorp`
- environment: `production`
- compliance_tier: `pci`
- default_log_retention_days: `365`

## Rules Extracted
14 rules total:
- **3** `ssh:login` rules (per-host `AllowGroups` via `sshd_config`)
- **2** `user:create` rules (app01 for sudo/developers, proxy01 for sudo)
- **2** `db:login` rules (dba SUPERUSER, developer NOSUPERUSER)
- **3** `network:connect` rules (proxy01 HTTPS, app01 app, db01 PostgreSQL)
- **3** `filesystem:read/write/execute` rules (postgres data directory)
- **1** default-deny rule

## Vulnerabilities
Evaluated **23** CVEs for the three pinned packages.
No CPE strings matched the exact pinned versions, but the presence of old versions in a PCI environment warrants immediate review.

### Notable KEVs
| CVE | Products | Severity | CVSS | KEV |
|-----|----------|----------|------|-----|
| CVE-2009-3555 | nginx | critical | 9.8 | Yes |
| CVE-2023-44487 | nginx | high | 7.5 | Yes |
| CVE-2023-38408 | openssh | critical | 9.8 | Yes |
| CVE-2024-6387 | openssh | high | 8.1 | Yes |
| CVE-2007-4752 | openssh | high | 7.5 | Yes |
| CVE-2019-6110 | openssh | medium | 6.8 | Yes |
| CVE-2019-6109 | openssh | medium | 6.8 | Yes |
| CVE-2024-1597 | postgresql | critical | 10 | Yes |
| CVE-2019-9193 | postgresql | high | 7.2 | Yes |
| CVE-2022-31197 | postgresql | high | 7.1 | Yes |

## Ambiguities
1. **No explicit sudoers configuration**: The `sudo` group is used in `sshd_config` `AllowGroups`, but no sudoers file or `sudo` privilege rules are explicitly defined in Ansible.
2. **No credential management**: No passwords, Ansible Vault, or SSH key provisioning tasks were observed for DB users or shell users.
3. **Implicit deny in PostgreSQL**: The `pg_hba.conf` task only adds an allow line; no explicit DENY rules are configured, relying on PostgreSQL's default-deny behavior.
4. **No firewall deny rules**: `firewalld` tasks only add allow rules; no explicit drop/deny rules are present in the Ansible configuration.
5. **No patch management**: The vulnerability assessment shows numerous CVEs for the pinned package versions, yet no remediation tasks (e.g., `apt upgrade`, package pinning to newer versions) are present in the playbooks.
6. **No audit/logging obligations**: No session logging, `profile.d` audit scripts, or similar enforcement tasks were found, so no obligations were attached to access rules.

## Recommendations
- Review and patch pinned packages (nginx, openssh, postgresql) given the high volume of associated CVEs and known-exploited vulnerabilities.
- Add explicit `pg_hba.conf` reject rules or host-based deny entries to strengthen database access control.
- Introduce Ansible Vault or secret management for database and user credentials.
- Consider adding a `sudoers` template to explicitly scope `sudo` privileges rather than relying solely on SSH group membership.