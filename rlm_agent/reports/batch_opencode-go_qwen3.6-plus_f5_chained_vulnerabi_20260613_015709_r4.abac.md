# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 02:05:02_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 17_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "values": [
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
        },
        {
          "name": "postgres",
          "uid": 999,
          "groups": [
            "postgres"
          ],
          "department": "system",
          "clearance": "system",
          "note": "created by postgresql package"
        }
      ],
      "attributes": {
        "name": {
          "type": "string",
          "domain": [
            "admin",
            "developer",
            "dba"
          ],
          "source": "group_vars/all.yml"
        },
        "uid": {
          "type": "integer",
          "source": "group_vars/all.yml"
        },
        "groups": {
          "type": "set",
          "domain": [
            "sudo",
            "developers",
            "dba"
          ],
          "source": "group_vars/all.yml"
        },
        "department": {
          "type": "string",
          "domain": [
            "operations",
            "engineering",
            "data"
          ],
          "source": "group_vars/all.yml"
        },
        "clearance": {
          "type": "string",
          "domain": [
            "secret",
            "confidential"
          ],
          "source": "group_vars/all.yml"
        }
      }
    },
    "groups": {
      "values": [
        "sudo",
        "developers",
        "dba",
        "postgres"
      ],
      "domain": [
        "sudo",
        "developers",
        "dba",
        "postgres"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "values": [
        "secret",
        "confidential",
        "system"
      ],
      "domain": [
        "secret",
        "confidential",
        "system"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "values": [
        "operations",
        "engineering",
        "data",
        "system"
      ],
      "domain": [
        "operations",
        "engineering",
        "data",
        "system"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": {
      "values": [
        {
          "hostname": "bastion01.lab.local",
          "ip": "10.0.0.5",
          "role": "bastion",
          "zone": "mgmt",
          "host_group": "bastion"
        },
        {
          "hostname": "web01.lab.local",
          "ip": "10.0.1.10",
          "role": "frontend",
          "zone": "dmz",
          "host_group": "webservers"
        },
        {
          "hostname": "app01.lab.local",
          "ip": "10.0.2.10",
          "role": "application",
          "zone": "app",
          "host_group": "appservers"
        },
        {
          "hostname": "db01.lab.local",
          "ip": "10.0.3.10",
          "role": "primary",
          "zone": "data",
          "host_group": "dbservers"
        }
      ],
      "attributes": {
        "hostname": {
          "type": "string",
          "source": "inventory.ini"
        },
        "ip": {
          "type": "string",
          "source": "inventory.ini"
        },
        "role": {
          "type": "string",
          "domain": [
            "bastion",
            "frontend",
            "application",
            "primary"
          ],
          "source": "inventory.ini"
        },
        "zone": {
          "type": "string",
          "domain": [
            "mgmt",
            "dmz",
            "app",
            "data"
          ],
          "source": "inventory.ini"
        },
        "host_group": {
          "type": "string",
          "domain": [
            "bastion",
            "webservers",
            "appservers",
            "dbservers"
          ],
          "source": "inventory.ini"
        }
      }
    },
    "services": {
      "values": [
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
          "name": "postgres",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers"
        }
      ],
      "attributes": {
        "name": {
          "type": "string",
          "domain": [
            "ssh",
            "http",
            "app",
            "postgres"
          ],
          "source": "roles/*/tasks/main.yml"
        },
        "port": {
          "type": "integer",
          "source": "group_vars/*.yml"
        },
        "protocol": {
          "type": "string",
          "domain": [
            "tcp"
          ],
          "source": "group_vars/*.yml"
        },
        "host_group": {
          "type": "string",
          "source": "group_vars/*.yml"
        }
      }
    },
    "paths": {
      "values": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgresql"
        }
      ],
      "attributes": {
        "path": {
          "type": "string",
          "source": "roles/db/tasks/main.yml"
        },
        "owner": {
          "type": "string",
          "domain": [
            "postgres"
          ],
          "source": "roles/db/tasks/main.yml"
        },
        "group": {
          "type": "string",
          "domain": [
            "postgres"
          ],
          "source": "roles/db/tasks/main.yml"
        },
        "mode": {
          "type": "string",
          "source": "roles/db/tasks/main.yml"
        }
      }
    },
    "networks": {
      "values": [
        {
          "cidr": "0.0.0.0/0",
          "zone": "any",
          "label": "internet"
        },
        {
          "cidr": "10.0.0.0/24",
          "zone": "mgmt",
          "label": "bastion_subnet"
        },
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "web_subnet"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "app",
          "label": "app_subnet"
        }
      ],
      "attributes": {
        "cidr": {
          "type": "cidr",
          "source": "group_vars/*.yml"
        },
        "zone": {
          "type": "string",
          "source": "group_vars/*.yml"
        },
        "label": {
          "type": "string",
          "source": "group_vars/*.yml"
        }
      }
    }
  },
  "environment": {
    "values": {
      "org": "chaincorp",
      "environment": "production",
      "compliance_tier": "pci",
      "log_retention_days": 365
    },
    "attributes": {
      "org": {
        "type": "string",
        "domain": [
          "chaincorp"
        ],
        "source": "group_vars/all.yml"
      },
      "environment": {
        "type": "string",
        "domain": [
          "production",
          "staging",
          "development"
        ],
        "source": "inventory.ini"
      },
      "compliance_tier": {
        "type": "string",
        "domain": [
          "pci"
        ],
        "source": "inventory.ini"
      },
      "log_retention_days": {
        "type": "integer",
        "source": "group_vars/all.yml"
      }
    },
    "source": "group_vars/all.yml"
  }
}
```

## Rules

```json
[
  {
    "id": "rule-001",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "role": {
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "network:connect",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": [
        5,
        8
      ]
    }
  },
  {
    "id": "rule-002",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "network:connect",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        17,
        20
      ]
    }
  },
  {
    "id": "rule-003",
    "effect": "permit",
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
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "network:connect",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        18,
        21
      ]
    }
  },
  {
    "id": "rule-004",
    "effect": "permit",
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
      },
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      }
    },
    "action": "network:connect",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": [
        20,
        23
      ]
    }
  },
  {
    "id": "rule-005",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "bastion"
      }
    },
    "action": "sudo:execute",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "obligations": [
      {
        "nopassword": false,
        "commands": "ALL"
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": [
        14,
        20
      ]
    }
  },
  {
    "id": "rule-006",
    "effect": "permit",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
      }
    },
    "action": "network:connect",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": [
        11,
        16
      ]
    }
  },
  {
    "id": "rule-007",
    "effect": "permit",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
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
    "action": "network:connect",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": [
        12,
        17
      ]
    }
  },
  {
    "id": "rule-008",
    "effect": "permit",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgres"
      },
      "port": {
        "equals": 5432
      }
    },
    "action": "network:connect",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        14,
        17
      ]
    }
  },
  {
    "id": "rule-009",
    "effect": "permit",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "database": {
        "equals": "all"
      },
      "schema": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "obligations": [
      {
        "privilege_level": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        9,
        13
      ]
    }
  },
  {
    "id": "rule-010",
    "effect": "permit",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        5,
        10
      ]
    }
  },
  {
    "id": "rule-011",
    "effect": "permit",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        5,
        10
      ]
    }
  },
  {
    "id": "rule-012",
    "effect": "deny",
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
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "http"
      },
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
    "id": "rule-016",
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
    "id": "rule-017",
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
        "equals": "postgres"
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
    "cve_id": "CVE-2021-44228",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "recommendation": "Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "recommendation": "Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "recommendation": "Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "recommendation": "Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": true,
    "recommendation": "Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 9,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "recommendation": "Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-4104",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "recommendation": "Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "is_poc": false,
    "recommendation": "Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 6.6,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "recommendation": "Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "recommendation": "Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "recommendation": "Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "is_poc": false,
    "recommendation": "Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "recommendation": "Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "is_poc": false,
    "recommendation": "Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 7.2,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "recommendation": "Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available",
    "source": "group_vars/all.yml"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "openssh-server",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "cvss_score": 7.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "is_poc": true,
    "recommendation": "Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version",
    "source": "group_vars/all.yml"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
- **Organization**: chaincorp
- **Environment**: production (PCI compliance tier)
- **Policy Goal**: all
- **Rules Extracted**: 12 (11 permit, 1 deny)
- **Vulnerabilities Found**: 16 (11 critical, 8 KEV-listed)

## Infrastructure Overview
| Host | IP | Role | Zone | Group |
|------|----|------|------|-------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt | bastion |
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

## Subjects
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |
| postgres | 999 | postgres | system | system |

## Security Rules Summary
| ID | Action | Subject | Resource | Effect |
|----|--------|---------|----------|--------|
| rule-001 | network:connect (SSH) | groups in [sudo, dba] | bastion | permit |
| rule-002 | network:connect (SSH) | groups in [sudo] | webservers | permit |
| rule-003 | network:connect (SSH) | groups in [sudo, developers] | appservers | permit |
| rule-004 | network:connect (SSH) | groups in [sudo, dba] | dbservers | permit |
| rule-005 | sudo:execute | groups in [sudo] + clearance=secret | bastion | permit |
| rule-006 | network:connect (HTTP) | source=10.0.0.0/24 | webservers:80 | permit |
| rule-007 | network:connect (APP) | source=10.0.1.0/24 | appservers:8080 | permit |
| rule-008 | network:connect (PG) | source=10.0.2.0/24 | dbservers:5432 | permit |
| rule-009 | db:login (SUPERUSER) | groups in [dba] | postgres | permit |
| rule-010 | filesystem:read | user=postgres | /var/lib/postgresql/data (0700) | permit |
| rule-011 | filesystem:write | user=postgres | /var/lib/postgresql/data (0700) | permit |
| rule-012 | * | all | all | deny |

## Vulnerability Assessment

### Pinned Packages & Versions
| Package | Pinned Version | Status |
|---------|---------------|--------|
| openssh-server | 1:9.1p1-1ubuntu1 (bastion) | No critical remote vulns found |
| apache2 | 2.4.49-1 | No critical remote vulns found |
| log4j | 2.14.1 | **CRITICAL** |
| postgresql | 9.2.3-1.pgdg20.04+1 | **CRITICAL** |

### Critical Vulnerabilities (CVSS >= 9.0)
- **CVE-2021-44228** (CVSS 10) — openssh-server 1:9.1p1-1ubuntu1 [KEV]
  - Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version
- **CVE-2002-1399** (CVSS 10) — openssh-server 1:9.1p1-1ubuntu1
  - Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available
- **CVE-2007-3279** (CVSS 10) — openssh-server 1:9.1p1-1ubuntu1
  - Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available
- **CVE-2024-1597** (CVSS 10) — openssh-server 1:9.1p1-1ubuntu1 [KEV]
  - Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available
- **CVE-2013-1903** (CVSS 10) — openssh-server 1:9.1p1-1ubuntu1
  - Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available
- **CVE-2013-1902** (CVSS 10) — openssh-server 1:9.1p1-1ubuntu1
  - Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available
- **CVE-2017-5645** (CVSS 9.8) — openssh-server 1:9.1p1-1ubuntu1
  - Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version
- **CVE-2020-9493** (CVSS 9.8) — openssh-server 1:9.1p1-1ubuntu1
  - Apply compensating controls for openssh-server 1:9.1p1-1ubuntu1; no patch available
- **CVE-2022-23305** (CVSS 9.8) — openssh-server 1:9.1p1-1ubuntu1
  - Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version
- **CVE-2019-17571** (CVSS 9.8) — openssh-server 1:9.1p1-1ubuntu1
  - Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version
- **CVE-2021-45046** (CVSS 9) — openssh-server 1:9.1p1-1ubuntu1 [KEV]
  - Upgrade openssh-server from 1:9.1p1-1ubuntu1 to latest patched version

### Ambiguities & Notes
- **SSH version inconsistency**: Bastion uses openssh 1:9.1p1-1ubuntu1 (deliberately vulnerable), while other hosts use 1:9.9p1-3ubuntu1.
- **PostgreSQL user**: The `postgres` OS user is created implicitly by the package, not declared in `group_vars`. Added to catalog as system-managed subject.
- **Default deny**: Rule-012 is an implicit deny-all derived from security best practice, not explicitly defined in Ansible files.
- **No handlers files**: Present but skipped per methodology (not access-relevant).
- **pg_hba.conf**: Explicit allow for appservers subnet implies deny for all other sources (captured by rule-008 + rule-012).
- **Log4j credentials**: The application JAR is deployed via `get_url` from Maven Central — no embedded credentials detected in config.
