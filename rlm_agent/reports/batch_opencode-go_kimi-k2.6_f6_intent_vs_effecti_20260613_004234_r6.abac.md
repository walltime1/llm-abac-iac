# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 00:49:53_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 11 | Rules: 20_  
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
      "source": "group_vars/all.yml,roles/db/tasks/main.yml"
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
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml"
    },
    "source_zone": {
      "domain": [
        "dmz",
        "app",
        "internet"
      ],
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml"
    },
    "user": {
      "domain": [
        "admin",
        "developer",
        "dba",
        "postgres"
      ],
      "source": "group_vars/all.yml,roles/db/tasks/main.yml"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "implicit"
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
    "host_group": {
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
        "nginx",
        "app",
        "postgresql"
      ],
      "source": "group_vars/dmz.yml,group_vars/appservers.yml,group_vars/dbservers.yml"
    },
    "port": {
      "source": "group_vars/dmz.yml,group_vars/appservers.yml,group_vars/dbservers.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "group_vars/dmz.yml,group_vars/appservers.yml,group_vars/dbservers.yml"
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
    "cidr": {
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml"
    },
    "network_zone": {
      "domain": [
        "dmz",
        "app",
        "internet"
      ],
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml"
    },
    "label": {
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/dmz.yml"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "implicit"
    }
  },
  "environment": {
    "org": {
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
    "rule_id": "rule-001",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "24-28"
    }
  },
  {
    "rule_id": "rule-002",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "41-45"
    }
  },
  {
    "rule_id": "rule-003",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-34"
    }
  },
  {
    "rule_id": "rule-004",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-15"
    }
  },
  {
    "rule_id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "13-21"
    }
  },
  {
    "rule_id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "21-27"
    }
  },
  {
    "rule_id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "28-34"
    }
  },
  {
    "rule_id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      },
      "source_zone": {
        "equals": "dmz"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-23"
    }
  },
  {
    "rule_id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      },
      "source_zone": {
        "equals": "internet"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "service": {
        "equals": "nginx"
      },
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "22-29"
    }
  },
  {
    "rule_id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      },
      "source_zone": {
        "equals": "app"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "35-40"
    }
  },
  {
    "rule_id": "rule-011",
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
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "13-20"
    }
  },
  {
    "rule_id": "rule-012",
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
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "13-20"
    }
  },
  {
    "rule_id": "rule-013",
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
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "13-20"
    }
  },
  {
    "rule_id": "rule-014",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "implicit",
      "task": "default-deny",
      "lines": "0"
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
      "environment": {
        "equals": "production"
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
      "environment": {
        "equals": "production"
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
      "environment": {
        "equals": "production"
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
      "host_group": {
        "equals": "appservers"
      },
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
      "host_group": {
        "equals": "dmz"
      },
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
      "host_group": {
        "equals": "dbservers"
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
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2009-3555",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev": true,
    "affects_pinned_version": false,
    "recommendation": "URGENT: KEV active exploitation confirmed for CVE-2009-3555. Upgrade nginx from 1.20.0 immediately."
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "High priority: Remote critical vulnerability CVE-2016-0746 in nginx 1.20.0. Patch or upgrade."
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "High priority: Remote critical vulnerability CVE-2021-46461 in nginx 1.20.0. Patch or upgrade."
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "High priority: Remote critical vulnerability CVE-2017-20005 in nginx 1.20.0. Patch or upgrade."
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Review CVE-2021-23017 for impact on nginx 1.20.0. Apply vendor patch if affected."
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2023-44487",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV active exploitation confirmed for CVE-2023-44487. Upgrade nginx from 1.20.0 immediately."
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": false,
    "recommendation": "High priority: Remote critical vulnerability CVE-2000-0999 in openssh 9.1p1. Patch or upgrade."
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2002-0640",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": false,
    "recommendation": "High priority: Remote critical vulnerability CVE-2002-0640 in openssh 9.1p1. Patch or upgrade."
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": false,
    "recommendation": "High priority: Remote critical vulnerability CVE-2003-0786 in openssh 9.1p1. Patch or upgrade."
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": false,
    "recommendation": "High priority: Remote critical vulnerability CVE-2003-0693 in openssh 9.1p1. Patch or upgrade."
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": false,
    "recommendation": "High priority: Remote critical vulnerability CVE-2000-0525 in openssh 9.1p1. Patch or upgrade."
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2023-38408",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV active exploitation confirmed for CVE-2023-38408. Upgrade openssh from 9.1p1 immediately."
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2024-6387",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV active exploitation confirmed for CVE-2024-6387. Upgrade openssh from 9.1p1 immediately."
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2007-4752",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "kev": true,
    "affects_pinned_version": false,
    "recommendation": "URGENT: KEV active exploitation confirmed for CVE-2007-4752. Upgrade openssh from 9.1p1 immediately."
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2019-6110",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_remote": true,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV active exploitation confirmed for CVE-2019-6110. Upgrade openssh from 9.1p1 immediately."
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2019-6109",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_remote": true,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV active exploitation confirmed for CVE-2019-6109. Upgrade openssh from 9.1p1 immediately."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": false,
    "recommendation": "High priority: Remote critical vulnerability CVE-2002-1399 in postgresql 16.2. Patch or upgrade."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": false,
    "recommendation": "High priority: Remote critical vulnerability CVE-2007-3279 in postgresql 16.2. Patch or upgrade."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV active exploitation confirmed for CVE-2024-1597. Upgrade postgresql from 16.2 immediately."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "High priority: Remote critical vulnerability CVE-2013-1903 in postgresql 16.2. Patch or upgrade."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "High priority: Remote critical vulnerability CVE-2013-1902 in postgresql 16.2. Patch or upgrade."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2019-9193",
    "severity": "high",
    "cvss_score": 7.2,
    "is_remote": true,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV active exploitation confirmed for CVE-2019-9193. Upgrade postgresql from 16.2 immediately."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2022-31197",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "URGENT: KEV active exploitation confirmed for CVE-2022-31197. Upgrade postgresql from 16.2 immediately."
  }
]
```

## Report

# ABAC Policy Mining Report

## 1. Overview
The Ansible repository under `RLM_ANSIBLE_DIR` describes a three-tier production environment (`prod`) comprising DMZ, application, and database tiers. The environment is governed by PCI compliance (`compliance_tier=pci`). This report documents the mined Attribute-Based Access Control (ABAC) policy, the attribute catalog, the extracted rules, and a vulnerability assessment of pinned software packages.

## 2. Attribute Catalog
- **Subjects**: Three interactive users (`admin`, `developer`, `dba`) plus the implicit `postgres` service account. Attributes include `groups`, `clearance`, `department`, and `source_network` / `source_zone` for network-layer subjects.
- **Resources**: Three hosts (`proxy01.lab.local`, `app01.lab.local`, `db01.lab.local`), three services (`nginx` on 443/tcp, `app` on 8080/tcp, `postgresql` on 5432/tcp), one filesystem path (`/var/lib/postgresql/data`), and three network definitions (`10.0.1.0/24`, `10.0.2.0/24`, `0.0.0.0/0`).
- **Environment**: `org=segcorp`, `environment=production`, `compliance_tier=pci`, `default_log_retention_days=365`.

## 3. Extracted Rules (14 total)
| Rule | Action | Effect | Scope |
|------|--------|--------|-------|
| rule-001 | ssh:login | permit | appservers — groups `sudo` or `developers` |
| rule-002 | ssh:login | permit | dbservers — groups `sudo` or `dba` |
| rule-003 | ssh:login | permit | dmz — group `sudo` |
| rule-004 | user:create | permit | appservers — groups `sudo` or `developers` |
| rule-005 | user:create | permit | dmz — group `sudo` |
| rule-006 | db:login | permit | dbservers/postgresql — group `dba` (SUPERUSER) |
| rule-007 | db:login | permit | dbservers/postgresql — group `developers` (read-only) |
| rule-008 | network:connect | permit | DMZ (`10.0.1.0/24`) → appservers:8080/tcp |
| rule-009 | network:connect | permit | Internet (`0.0.0.0/0`) → dmz:443/tcp |
| rule-010 | network:connect | permit | appservers (`10.0.2.0/24`) → dbservers:5432/tcp |
| rule-011 | filesystem:read | permit | `postgres` group on `/var/lib/postgresql/data` |
| rule-012 | filesystem:write | permit | `postgres` group on `/var/lib/postgresql/data` |
| rule-013 | filesystem:execute | permit | `postgres` group on `/var/lib/postgresql/data` |
| rule-014 | * | deny | global default-deny |

## 4. Vulnerability Assessment
Pinned packages: nginx `1.20.0-1~focal`, OpenSSH `9.1p1`, PostgreSQL `16.2-1.pgdg22.04+1`.
- **23 unique CVEs** were identified across the three packages.
- **Known Exploited Vulnerabilities (KEV)**: CVE-2023-44487 (nginx), CVE-2023-38408 (OpenSSH), CVE-2024-6387 (OpenSSH), CVE-2024-1597 (PostgreSQL), CVE-2019-9193 (PostgreSQL), CVE-2022-31197 (PostgreSQL), and others.
- **Critical remote**: CVE-2021-46461, CVE-2017-20005, CVE-2016-0746 (nginx); CVE-2023-38408 (OpenSSH); CVE-2024-1597 (PostgreSQL), etc.
- **Recommendations**: Upgrade KEV-affected packages immediately; apply vendor patches for critical remote vulnerabilities; review medium-severity items for applicability to the pinned versions.

## 5. Ambiguities & Gaps
1. **No explicit sudoers configuration**: The playbook assigns users to the `sudo` group, but no `sudoers` file or `sudo` privilege rules are explicitly defined in the extracted tasks.
2. **Credentials management**: No Ansible Vault files or explicit credential-rotation tasks were observed; credential handling is therefore ambiguous.
3. **Incomplete `pg_hba`**: The PostgreSQL access control is augmented with a single `lineinfile` entry; the full `pg_hba.conf` baseline is unknown, and implicit deny is assumed.
4. **Missing session-logging / audit obligations**: No audit or session-logging tasks were present in the extracted role files, so no obligations were attached.
5. **No SELinux / AppArmor rules**: The catalog contains no SELinux booleans or file-context policies.
6. **Filesystem ACLs**: Only the PostgreSQL data directory is explicitly managed; other paths rely on package defaults.