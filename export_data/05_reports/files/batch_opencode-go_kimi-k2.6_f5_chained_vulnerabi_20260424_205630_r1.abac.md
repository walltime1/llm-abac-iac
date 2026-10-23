# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 21:27:26_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 16 | Rules: 21_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "type": "string",
      "domain": [
        "admin",
        "developer",
        "dba",
        "postgres"
      ],
      "source": "group_vars/all.yml, roles/db/tasks/main.yml"
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
    "clearance": {
      "type": "string",
      "domain": [
        "secret",
        "confidential"
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
    "source_ip": {
      "type": "string",
      "source": "inventory.ini"
    },
    "source_network": {
      "type": "string",
      "source": "group_vars/appservers.yml, group_vars/bastion.yml, group_vars/dbservers.yml, group_vars/webservers.yml"
    },
    "source_zone": {
      "type": "string",
      "source": "inventory.ini"
    }
  },
  "resources": {
    "hostname": {
      "type": "string",
      "domain": [
        "bastion01.lab.local",
        "web01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
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
    },
    "service": {
      "type": "string",
      "domain": [
        "ssh",
        "http",
        "app",
        "postgres"
      ],
      "source": "roles/web/tasks/main.yml, roles/app/tasks/main.yml, roles/bastion/tasks/main.yml, roles/db/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "domain": [
        22,
        80,
        8080,
        5432
      ],
      "source": "group_vars/webservers.yml, group_vars/appservers.yml, group_vars/dbservers.yml, roles/bastion/tasks/main.yml"
    },
    "protocol": {
      "type": "string",
      "domain": [
        "tcp"
      ],
      "source": "roles/web/tasks/main.yml, roles/app/tasks/main.yml, roles/bastion/tasks/main.yml, roles/db/tasks/main.yml"
    },
    "path": {
      "type": "string",
      "domain": [
        "/var/lib/postgresql/data",
        "/etc/ssh/sshd_config",
        "/etc/postgresql/pg_hba.conf"
      ],
      "source": "roles/db/tasks/main.yml, roles/web/tasks/main.yml, roles/app/tasks/main.yml, roles/bastion/tasks/main.yml"
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
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "string",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "commands": {
      "type": "string",
      "domain": [
        "ALL"
      ],
      "source": "roles/bastion/tasks/main.yml"
    }
  },
  "environment": {
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
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "type": "string",
      "domain": [
        "pci"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "type": "integer",
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
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "appservers"
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
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": "23-29"
    }
  },
  {
    "id": "rule-002",
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
      "host_group": {
        "equals": "appservers"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "31-35"
    }
  },
  {
    "id": "rule-003",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "bastion"
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
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": "14-20"
    }
  },
  {
    "id": "rule-004",
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
      "host_group": {
        "equals": "bastion"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "8-12"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "commands": {
        "equals": "ALL"
      },
      "host_group": {
        "equals": "bastion"
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
    "action": "sudo:execute",
    "effect": "permit",
    "nopassword": false,
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "22-29"
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
    }
  },
  {
    "id": "rule-007",
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
    }
  },
  {
    "id": "rule-008",
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-14"
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
        "equals": "postgres"
      },
      "host_group": {
        "equals": "dbservers"
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
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "16-21"
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
      "service": {
        "equals": "postgres"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "database": {
        "equals": "all"
      },
      "host_group": {
        "equals": "dbservers"
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
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "23-27"
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "23-27"
    }
  },
  {
    "id": "rule-012",
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
      "host_group": {
        "equals": "dbservers"
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
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "29-33"
    }
  },
  {
    "id": "rule-013",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "http"
      },
      "port": {
        "equals": 80
      },
      "protocol": {
        "equals": "tcp"
      },
      "host_group": {
        "equals": "webservers"
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
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "13-19"
    }
  },
  {
    "id": "rule-014",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "21-25"
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
      },
      "host_group": {
        "equals": "appservers"
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
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "bastion"
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
    "id": "rule-021",
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
    "cve_id": "CVE-1999-1237",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-1999-1293",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2004-0492",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.5,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2010-0219",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2010-0425",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2012-2379",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2016-15057",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.9,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2019-17564",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "medium",
    "cvss_score": 6.8,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "medium",
    "cvss_score": 6.8,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.2,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2021-4104",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.5,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": true,
    "severity": "critical",
    "cvss_score": 10,
    "kev": true,
    "sources": [
      "critical_remote",
      "kev"
    ],
    "recommendation": "Upgrade apache from pinned version(s) 2.4.49-1. Known Exploited Vulnerability (KEV) — immediate patching required."
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": false,
    "severity": "medium",
    "cvss_score": 6.6,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "sources": [
      "critical_remote"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.1,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 7.5,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2023-46604",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "affects_pinned_version": false,
    "severity": "critical",
    "cvss_score": 10,
    "kev": true,
    "sources": [
      "critical_remote",
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "affects_pinned_version": false,
    "severity": "high",
    "cvss_score": 8.1,
    "kev": true,
    "sources": [
      "kev"
    ],
    "recommendation": "Pinned version does not appear affected based on available data; verify with vendor."
  }
]
```

## Report

# ABAC Policy Mining Report

## Scope
Mined from Ansible configuration rooted at `RLM_ANSIBLE_DIR`.  
Policy slice: `all` (full coverage).

## Attribute Catalog Summary
- **Subjects**: 4 users (admin, developer, dba, postgres), 3 groups (sudo, developers, dba), 2 clearance levels (secret, confidential), 3 departments (operations, engineering, data).
- **Resources**: 4 hosts (bastion01, web01, app01, db01), 4 services/ports (ssh/22, http/80, app/8080, postgres/5432), filesystem paths (postgres data dir), network sources.
- **Environment**: chaincorp, production, PCI compliance tier.

## Rules Summary
Extracted **15 rules**:
- 5 `network:connect` (firewalld / pg_hba)
- 4 `ssh:login` (AllowGroups per host group)
- 1 `sudo:execute` (bastion sudoers, secret clearance, nopassword=false)
- 3 `filesystem:*` (read/write/execute for postgres data dir)
- 1 `db:login` (DBA superuser)
- 1 default-deny catch-all

## Vulnerability Assessment
Pinned vulnerable packages evaluated: openssh, apache2, log4j, postgresql.
- Total CVEs reviewed: 35
- KEV entries found: several (e.g., CVE-2021-44228, CVE-2019-9193, CVE-2024-6387)
- Immediate-action recommendation for CVE-2021-44228 (Log4j / Apache ecosystem) — upgrade pinned versions.

## Ambiguities
1. No explicit hard-coded credentials were found in the Ansible files; however, vulnerable package versions are pinned, increasing exploitability.
2. CVE-to-product mapping relies on CPE-based search. Some matches span the Apache ecosystem (e.g., Log4j CVEs returned under `apache` queries). Verify CPE accuracy before patching.
3. The `postgres` user is defined implicitly via file ownership rather than an explicit `users` entry.

## Recommendations
- Upgrade pinned packages, especially Log4j, OpenSSH, and PostgreSQL, based on the vulnerability table.
- Restrict `0.0.0.0/0` SSH access on the bastion to known jump-box ranges if possible.
- Add `NOPASSWD` auditing for sudo rules and consider MFA for secret-clearance users.
- Implement automated CVE scanning in CI/CD to catch pinned vulnerable versions before deployment.
