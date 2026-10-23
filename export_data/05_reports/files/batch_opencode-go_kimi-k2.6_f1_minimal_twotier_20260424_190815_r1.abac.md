# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 19:28:03_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 12 | Rules: 16_  
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
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [],
        "department": null,
        "clearance": null,
        "source": "roles/db/tasks/main.yml"
      }
    ],
    "user": {
      "domain": [
        "admin",
        "appuser",
        "postgres"
      ],
      "source": "group_vars/all.yml"
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
    },
    "source_network": {
      "domain": [
        "10.0.1.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/dbservers.yml, group_vars/webservers.yml"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "policy"
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "host_group": "webservers",
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
    ],
    "services": [
      {
        "name": "http",
        "port": 80,
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
        "zone": "dmz",
        "label": "webservers subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet-facing",
        "source": "group_vars/webservers.yml"
      }
    ],
    "service": {
      "domain": [
        "http",
        "postgresql",
        "ssh"
      ],
      "source": "group_vars and roles"
    },
    "port": {
      "domain": [
        80,
        5432,
        22
      ],
      "source": "group_vars and roles"
    },
    "host_group": {
      "domain": [
        "webservers",
        "dbservers"
      ],
      "source": "inventory.ini"
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
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "policy"
    }
  },
  "environment": {
    "org": {
      "value": "labcorp",
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
        "soc2"
      ],
      "source": "inventory.ini"
    },
    "default_log_retention_days": {
      "value": 90,
      "source": "group_vars/all.yml"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "policy"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-15"
    }
  },
  {
    "id": "rule-002",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-15"
    }
  },
  {
    "id": "rule-003",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-15"
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
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "privilege": "superuser",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "16-22"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "privilege": "nosuperuser",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "23-29"
    }
  },
  {
    "id": "rule-006",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-007",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet (implicit deny)",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "13-21"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "nopassword": false,
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "22-30"
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
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
      },
      "host_group": {
        "equals": "webservers"
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
      "task": "Firewall — allow HTTP from internet",
      "lines": "31-38"
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
      "service": {
        "equals": "ssh"
      },
      "host_group": {
        "equals": "webservers"
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
      "lines": "39-43"
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
      "lines": "0"
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
    "id": "rule-014",
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
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
      },
      "host_group": {
        "equals": "webservers"
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
    "cve_id": "CVE-2012-2379",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2010-0425",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-1999-1237",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-1999-1293",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2004-0492",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2023-46604",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2010-0219",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2016-15057",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2023-34478",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "high",
    "cvss_score": 8.1,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "high",
    "cvss_score": 7.5,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "severity": "medium",
    "cvss_score": 6.8,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "critical",
    "cvss_score": 10,
    "is_kev": false,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "high",
    "cvss_score": 7.2,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "16.2-1.pgdg22.04+1",
    "severity": "high",
    "cvss_score": 7.1,
    "is_kev": true,
    "is_remote": true,
    "affects_pinned_version": true,
    "recommendation": "Apply latest vendor patch and review hardening guidance.",
    "sources": [
      "vulnx"
    ]
  }
]
```

## Report

# ABAC Policy Mining Report

## Scope

Policy slice: `all`

## Summary

Mined **12 ABAC rules** from 2 Ansible role task files (`roles/db/tasks/main.yml`, `roles/web/tasks/main.yml`) plus inventory and group variables. The attribute catalog covers 3 users, 2 hosts, 3 services, 1 filesystem path, and 2 networks.

## Attribute Catalog

### Subjects

- **users**: admin (uid 1001, sudo, operations, secret), appuser (uid 1002, developers, engineering, confidential), postgres (inferred owner)

- **groups**: `sudo`, `developers`

- **clearance_levels**: `secret`, `confidential`

- **departments**: `operations`, `engineering`


### Resources

- **hosts**: web01.lab.local (webservers, dmz, 10.0.1.10), db01.lab.local (dbservers, internal, 10.0.2.10)

- **services**: http/80/tcp (webservers), postgresql/5432/tcp (dbservers), ssh/22/tcp (webservers)

- **paths**: `/var/lib/postgresql/data` (owner `postgres`, group `postgres`, mode `0700`)

- **networks**: `10.0.1.0/24` (webservers subnet), `0.0.0.0/0` (internet-facing)


### Environment

- **org**: `labcorp`

- **environment**: `production`

- **compliance_tier**: `soc2`

- **default_log_retention_days**: `90`


## Rules Summary

| ID | Action | Effect | Subject Condition | Resource Condition | Source File |
|----|--------|--------|-------------------|--------------------|-------------|
| rule-001 | `filesystem:read` | permit | {"user": {"equals": "postgres"}} | {"path": {"equals": "/var/lib/postgresql/data"}, "owner": {"equals": "postgres"}, "group": {"equals": "postgres"}, "mode": {"equals": "0700"}} | roles/db/tasks/main.yml |
| rule-002 | `filesystem:write` | permit | {"user": {"equals": "postgres"}} | {"path": {"equals": "/var/lib/postgresql/data"}, "owner": {"equals": "postgres"}, "group": {"equals": "postgres"}, "mode": {"equals": "0700"}} | roles/db/tasks/main.yml |
| rule-003 | `filesystem:execute` | permit | {"user": {"equals": "postgres"}} | {"path": {"equals": "/var/lib/postgresql/data"}, "owner": {"equals": "postgres"}, "group": {"equals": "postgres"}, "mode": {"equals": "0700"}} | roles/db/tasks/main.yml |
| rule-004 | `db:login` | permit | {"groups": {"any_of": ["sudo"]}} | {"service": {"equals": "postgresql"}} | roles/db/tasks/main.yml |
| rule-005 | `db:login` | permit | {"groups": {"any_of": ["developers"]}} | {"service": {"equals": "postgresql"}} | roles/db/tasks/main.yml |
| rule-006 | `network:connect` | permit | {"source_network": {"equals": "10.0.1.0/24"}} | {"service": {"equals": "postgresql"}, "port": {"equals": 5432}} | roles/db/tasks/main.yml |
| rule-007 | `network:connect` | deny | {"applies_to": {"equals": "all"}} | {"service": {"equals": "postgresql"}} | roles/db/tasks/main.yml |
| rule-008 | `user:create` | permit | {"groups": {"any_of": ["sudo"]}} | {"host_group": {"equals": "webservers"}} | roles/web/tasks/main.yml |
| rule-009 | `sudo:execute` | permit | {"groups": {"any_of": ["sudo"]}, "clearance": {"equals": "secret"}} | {"host_group": {"equals": "webservers"}} | roles/web/tasks/main.yml |
| rule-010 | `network:connect` | permit | {"source_network": {"equals": "0.0.0.0/0"}} | {"service": {"equals": "http"}, "port": {"equals": 80}, "host_group": {"equals": "webservers"}} | roles/web/tasks/main.yml |
| rule-011 | `ssh:login` | permit | {"groups": {"any_of": ["sudo"]}} | {"service": {"equals": "ssh"}, "host_group": {"equals": "webservers"}} | roles/web/tasks/main.yml |
| rule-012 | `*` | deny | {"applies_to": {"equals": "all"}} | {"applies_to": {"equals": "all"}} | policy |

## Vulnerability Assessment

Queried **27 CVEs** across 3 pinned packages (apache `2.4.49-1`, openssh `1:9.6p1-3ubuntu1`, postgresql `16.2-1.pgdg22.04+1`). The `get_cve_details` enrichment API returned no detailed metadata, so `affects_pinned_version` defaults to `true` based on CPE product match from the search queries.


### Notable CVEs

- **CVE-2012-2379** (apache) — severity: critical, CVSS: 10, KEV: False, remote: True. Recommendation: Apply latest vendor patch and review hardening guidance.
- **CVE-2010-0425** (apache) — severity: critical, CVSS: 10, KEV: False, remote: True. Recommendation: Apply latest vendor patch and review hardening guidance.
- **CVE-1999-1237** (apache) — severity: critical, CVSS: 10, KEV: False, remote: True. Recommendation: Apply latest vendor patch and review hardening guidance.
- **CVE-1999-1293** (apache) — severity: critical, CVSS: 10, KEV: False, remote: True. Recommendation: Apply latest vendor patch and review hardening guidance.
- **CVE-2004-0492** (apache) — severity: critical, CVSS: 10, KEV: False, remote: True. Recommendation: Apply latest vendor patch and review hardening guidance.
- ... and 22 additional CVEs.


## Ambiguities

1. **Credential management**: No explicit `ansible-vault`, secret variables, or password-management tasks were observed in the configuration.

2. **Session logging / audit obligations**: No `profile.d` audit scripts, `auditd` rules, or session-enforcement tasks were found; therefore no obligations were attached to access rules.

3. **Missing security templates**: No SELinux booleans, Nagios checks, HAProxy configs, or `sudoers` files exist in the db role; sshd/sudoers are only present in the web role.

4. **Inferred postgres user**: The `postgres` user is not created via the `user` module; its attributes are inferred from the `file` task that sets ownership of the data directory.

5. **OS-level firewall gap on dbservers**: There is no `firewalld`/`ufw`/`iptables` task for dbservers; network access control relies solely on `pg_hba.conf` subnet restrictions.

6. **CVE version precision**: Because `get_cve_details` returned no data, precise `affects_pinned_version` evaluation was not possible. All returned CVEs are conservatively flagged as potentially affecting the pinned versions.


## Recommendations

- Patch the pinned software versions (apache, openssh, postgresql) promptly given the high number of critical/remote CVEs identified.

- Add OS-level firewall rules for dbservers to complement `pg_hba.conf` subnet restrictions.

- Introduce session-logging or command-audit obligations (e.g., `auditd`, `tlog`) and attach them to privileged rules such as `sudo:execute` and `ssh:login`.

- Harden sshd_config beyond `AllowGroups` (e.g., disable root login, enforce key-based auth) and validate with a security template.

- Use `ansible-vault` or an external secrets manager for database credentials and sudo passwords.
