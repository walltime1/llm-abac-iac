# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 21:45:51_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 15 | Rules: 20_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "domain": [
        "admin",
        "developer",
        "dba",
        "postgres"
      ],
      "source": "group_vars/all.yml,roles/db/tasks/main.yml"
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
      "domain": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
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
    "users": {
      "entries": [
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
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": {
      "entries": [
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
      "source": "inventory.ini"
    },
    "services": {
      "entries": [
        {
          "name": "app",
          "port": 8080,
          "protocol": "tcp",
          "host_group": "appservers",
          "source": "group_vars/appservers.yml"
        },
        {
          "name": "postgres",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers",
          "source": "group_vars/dbservers.yml"
        },
        {
          "name": "https",
          "port": 443,
          "protocol": "tcp",
          "host_group": "dmz",
          "source": "group_vars/dmz.yml"
        }
      ],
      "source": "group_vars"
    },
    "paths": {
      "entries": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgres",
          "source": "roles/db/tasks/main.yml"
        }
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "networks": {
      "entries": [
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
          "cidr": "10.0.3.0/24",
          "zone": "data",
          "label": "dbservers subnet",
          "source": "inventory.ini"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "internet",
          "label": "internet",
          "source": "group_vars/dmz.yml"
        }
      ],
      "source": "group_vars,inventory.ini"
    },
    "hostname": {
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
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
    "role": {
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
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
        "app",
        "postgres",
        "https"
      ],
      "source": "group_vars"
    },
    "port": {
      "domain": [
        8080,
        5432,
        443
      ],
      "source": "group_vars"
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
    "id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 8080
      },
      "host_group": {
        "equals": "appservers"
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
    "id": "rule-003",
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
    "id": "rule-004",
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
    "id": "rule-005",
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
    "id": "rule-006",
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
    "id": "rule-007",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "host_group": {
        "equals": "dbservers"
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
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "host_group": {
        "equals": "dbservers"
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
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "port": {
        "equals": 5432
      },
      "host_group": {
        "equals": "dbservers"
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
    "id": "rule-010",
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
    "id": "rule-011",
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
    "id": "rule-012",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 443
      },
      "host_group": {
        "equals": "dmz"
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
    "id": "rule-013",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "policy",
      "task": "default-deny",
      "lines": "0"
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
      "port": {
        "equals": 8080
      },
      "host_group": {
        "equals": "appservers"
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
    "id": "rule-019",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "port": {
        "equals": 5432
      },
      "host_group": {
        "equals": "dbservers"
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
    "id": "rule-020",
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
        "equals": "dmz"
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": false,
    "recommendation": "CVE-2016-0746 does not affect the pinned nginx version 1.20.0; no action required."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": false,
    "recommendation": "CVE-2021-46461 does not affect the pinned nginx version 1.20.0; no action required."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": false,
    "recommendation": "CVE-2017-20005 does not affect the pinned nginx version 1.20.0; no action required."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.7,
    "severity": "high",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from 1.20.0 to a patched version addressing CVE-2021-23017."
  },
  {
    "cve_id": "CVE-2016-0742",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": false,
    "recommendation": "CVE-2016-0742 does not affect the pinned nginx version 1.20.0; no action required."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade nginx from 1.20.0 to a patched version addressing CVE-2023-44487."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cvss_score": 5.8,
    "severity": "medium",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": false,
    "recommendation": "CVE-2009-3555 does not affect the pinned nginx version 1.20.0; no action required."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": false,
    "recommendation": "CVE-2000-0999 does not affect the pinned openssh version 9.1p1; no action required."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": false,
    "recommendation": "CVE-2001-0144 does not affect the pinned openssh version 9.1p1; no action required."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": null,
    "affects_pinned_version": false,
    "recommendation": "CVE-2000-0525 does not affect the pinned openssh version 9.1p1; no action required."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": false,
    "recommendation": "CVE-2003-0693 does not affect the pinned openssh version 9.1p1; no action required."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": null,
    "affects_pinned_version": false,
    "recommendation": "CVE-2003-0786 does not affect the pinned openssh version 9.1p1; no action required."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 9.1p1 to a patched version addressing CVE-2023-38408."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 8.1,
    "severity": "high",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh from 9.1p1 to a patched version addressing CVE-2024-6387."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": false,
    "recommendation": "CVE-2007-4752 does not affect the pinned openssh version 9.1p1; no action required."
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": false,
    "recommendation": "CVE-2019-6109 does not affect the pinned openssh version 9.1p1; no action required."
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": false,
    "recommendation": "CVE-2019-6110 does not affect the pinned openssh version 9.1p1; no action required."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": null,
    "affects_pinned_version": false,
    "recommendation": "CVE-2007-3279 does not affect the pinned postgresql version 16.2; no action required."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": null,
    "affects_pinned_version": false,
    "recommendation": "CVE-2002-1399 does not affect the pinned postgresql version 16.2; no action required."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": null,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 16.2 to a patched version addressing CVE-2024-1597."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": null,
    "affects_pinned_version": false,
    "recommendation": "CVE-2013-1902 does not affect the pinned postgresql version 16.2; no action required."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_patch_available": null,
    "affects_pinned_version": false,
    "recommendation": "CVE-2013-1903 does not affect the pinned postgresql version 16.2; no action required."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 7.2,
    "severity": "high",
    "is_remote": true,
    "is_patch_available": null,
    "affects_pinned_version": false,
    "recommendation": "CVE-2019-9193 does not affect the pinned postgresql version 16.2; no action required."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2",
    "cvss_score": 7.1,
    "severity": "high",
    "is_remote": true,
    "is_patch_available": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql from 16.2 to a patched version addressing CVE-2022-31197."
  }
]
```

## Report

# ABAC Policy Mining Report — SegCorp Ansible Infrastructure

## Scope
Policy slice requested: **all**
Files mined: `inventory.ini`, `group_vars/all.yml`, `group_vars/appservers.yml`, `group_vars/dbservers.yml`, `group_vars/dmz.yml`, `roles/app/tasks/main.yml`, `roles/db/tasks/main.yml`, `roles/dmz/tasks/main.yml`.

## Attribute Catalog Summary
- **Subjects**: 3 human users (`admin`, `developer`, `dba`) with groups `sudo`, `developers`, `dba`, clearance levels `secret`/`confidential`, and departments `operations`/`engineering`/`data`.
- **Resources**: 3 hosts (`proxy01.lab.local`, `app01.lab.local`, `db01.lab.local`), 3 services (`app` on 8080/tcp, `postgres` on 5432/tcp, `https` on 443/tcp), 1 filesystem path (`/var/lib/postgresql/data`), and 4 network CIDRs.
- **Environment**: `org=segcorp`, `environment=production`, `compliance_tier=pci`, `default_log_retention_days=365`.

## Rules Extracted
14 rules mined:
1. **user:create** on `appservers` for groups `sudo` or `developers`.
2. **network:connect** to app port `8080` from DMZ subnet (`10.0.1.0/24`).
3. **ssh:login** on `appservers` for groups `sudo` or `developers`.
4–6. **filesystem:read/write/execute** on `/var/lib/postgresql/data` for user `postgres`.
7. **db:login** (superuser) on `dbservers` for group `dba`.
8. **db:login** (read-only) on `dbservers` for group `developers`.
9. **network:connect** to postgres from appservers subnet (`10.0.2.0/24`).
10. **ssh:login** on `dbservers` for groups `sudo` or `dba`.
11. **user:create** on `dmz` for group `sudo`.
12. **network:connect** to HTTPS (`443`) from `0.0.0.0/0`.
13. **ssh:login** on `dmz` for group `sudo`.
14. **Default-deny** catch-all rule.

## Vulnerability Assessment
Three pinned packages were assessed:
- **nginx 1.20.0** — 7 unique CVEs reviewed; 2 confirmed to affect the pinned era (`CVE-2021-23017`, `CVE-2023-44487`). Recommendation: upgrade nginx.
- **openssh 9.1p1** — 10 unique CVEs reviewed; 2 confirmed to affect the pinned version range (`CVE-2023-38408`, `CVE-2024-6387`). Recommendation: upgrade openssh-server.
- **postgresql 16.2** — 7 unique CVEs reviewed; 2 confirmed to affect the client/driver stack (`CVE-2024-1597`, `CVE-2022-31197`). Recommendation: upgrade PostgreSQL client/drivers.

## Ambiguities & Gaps
1. **Sudoers**: No Ansible task explicitly deploys `/etc/sudoers` or `sudoers.d` drop-ins; sudo access is implied by group membership only.
2. **Database privileges**: The playbook sets `LOGIN,SUPERUSER` vs `LOGIN,NOSUPERUSER` but does not issue `GRANT` statements on schemas/tables, so row/table-level ABAC rules cannot be mined.
3. **No session logging / audit obligations**: No `profile.d` audit scripts or session-capture tasks were found in the role tasks.
4. **No explicit firewall DENY rules**: Firewalld tasks only add `permanent: true, state: enabled` allows; the implicit default-deny is assumed but not enforced by Ansible content.
5. **No secrets management**: Passwords, keys, or vault-encrypted values are absent from the inspected files.
6. **nopassword**: Not mentioned in any task; SSH login uses key-based assumptions but not stated.

## Compliance Note
All rules include `environment_condition` referencing the `production`/`pci` environment. No rules violate namespace discipline.
