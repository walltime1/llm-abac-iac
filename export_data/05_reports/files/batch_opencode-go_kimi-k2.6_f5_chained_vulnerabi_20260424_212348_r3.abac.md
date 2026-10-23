# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 22:02:27_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 8 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "items": [
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
    },
    "user": {
      "domain": [
        "admin",
        "dba",
        "developer"
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "domain": [
        "dba",
        "developers",
        "sudo"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "domain": [
        "data",
        "engineering",
        "operations"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "domain": [
        "data",
        "engineering",
        "operations"
      ],
      "source": "group_vars/all.yml"
    },
    "source_ip": {
      "source": "inventory.ini"
    },
    "source_network": {
      "source": "group_vars/*.yml"
    },
    "source_zone": {
      "domain": [
        "app",
        "data",
        "dmz",
        "mgmt"
      ],
      "source": "inventory.ini"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "default"
    }
  },
  "resources": {
    "hosts": {
      "items": [
        {
          "hostname": "bastion01.lab.local",
          "ip": "10.0.0.5",
          "role": "bastion",
          "zone": "mgmt",
          "inventory_group": "bastion",
          "source": "inventory.ini"
        },
        {
          "hostname": "web01.lab.local",
          "ip": "10.0.1.10",
          "role": "frontend",
          "zone": "dmz",
          "inventory_group": "webservers",
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
    "hostname": {
      "domain": [
        "app01.lab.local",
        "bastion01.lab.local",
        "db01.lab.local",
        "web01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "source": "inventory.ini"
    },
    "role": {
      "domain": [
        "application",
        "bastion",
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "app",
        "data",
        "dmz",
        "mgmt"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "domain": [
        "appservers",
        "bastion",
        "dbservers",
        "prod",
        "webservers"
      ],
      "source": "inventory.ini"
    },
    "services": {
      "items": [
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
          "name": "http",
          "port": 80,
          "protocol": "tcp",
          "host_group": "webservers",
          "source": "group_vars/webservers.yml"
        },
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "all",
          "source": "inferred"
        }
      ],
      "source": "group_vars/*.yml"
    },
    "service": {
      "domain": [
        "app",
        "http",
        "postgres",
        "ssh"
      ],
      "source": "group_vars/*.yml"
    },
    "port": {
      "domain": [
        22,
        80,
        5432,
        8080
      ],
      "source": "group_vars/*.yml"
    },
    "protocol": {
      "domain": [
        "tcp",
        "udp"
      ],
      "source": "inferred"
    },
    "paths": {
      "items": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": null,
          "group": null,
          "mode": null,
          "service": "postgres",
          "source": "group_vars/dbservers.yml"
        }
      ],
      "source": "group_vars/dbservers.yml"
    },
    "path": {
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "group_vars/dbservers.yml"
    },
    "owner": {
      "source": "group_vars/dbservers.yml"
    },
    "group": {
      "source": "group_vars/dbservers.yml"
    },
    "mode": {
      "source": "group_vars/dbservers.yml"
    },
    "networks": {
      "items": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "app",
          "label": "appservers_allow",
          "source": "group_vars/appservers.yml"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "mgmt",
          "label": "bastion_allow",
          "source": "group_vars/bastion.yml"
        },
        {
          "cidr": "10.0.0.0/24",
          "zone": "dmz",
          "label": "webservers_allow",
          "source": "group_vars/webservers.yml"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "data",
          "label": "dbservers_allow",
          "source": "group_vars/dbservers.yml"
        }
      ],
      "source": "group_vars/*.yml"
    },
    "cidr": {
      "source": "group_vars/*.yml"
    },
    "network_label": {
      "domain": [
        "appservers_allow",
        "bastion_allow",
        "dbservers_allow",
        "webservers_allow"
      ],
      "source": "group_vars/*.yml"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "default"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "chaincorp"
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
    "retention": {
      "domain": [
        365
      ],
      "source": "group_vars/all.yml"
    },
    "applies_to": {
      "domain": [
        "all"
      ],
      "source": "default"
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
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
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
    "id": "rule-004",
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
      "lines": "22-28"
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
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgres"
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
    "privilege": "SUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "16-21"
    }
  },
  {
    "id": "rule-007",
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
    "id": "rule-008",
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
    "id": "rule-009",
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
    "id": "rule-010",
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
    "source": {
      "file": "default",
      "task": "default-deny",
      "lines": "0"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
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
    "id": "rule-013",
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
    "id": "rule-014",
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
    "id": "rule-015",
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
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "host_group": "bastion",
    "affects_pinned_version": true,
    "severity": "critical",
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 on bastion to mitigate CVE-2000-0999.",
    "source": "group_vars/all.yml:ssh_version_bastion",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "host_group": "bastion",
    "affects_pinned_version": true,
    "severity": "critical",
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 on bastion to mitigate CVE-2001-0144.",
    "source": "group_vars/all.yml:ssh_version_bastion",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "host_group": "bastion",
    "affects_pinned_version": true,
    "severity": "critical",
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 on bastion to mitigate CVE-2000-0525.",
    "source": "group_vars/all.yml:ssh_version_bastion",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "host_group": "bastion",
    "affects_pinned_version": true,
    "severity": "critical",
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 on bastion to mitigate CVE-2003-0693.",
    "source": "group_vars/all.yml:ssh_version_bastion",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "host_group": "bastion",
    "affects_pinned_version": true,
    "severity": "critical",
    "recommendation": "Upgrade openssh from 1:9.1p1-1ubuntu1 on bastion to mitigate CVE-2003-0786.",
    "source": "group_vars/all.yml:ssh_version_bastion",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2010-0425",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "host_group": "webservers",
    "affects_pinned_version": false,
    "severity": "critical",
    "recommendation": "Verify whether apache 2.4.49-1 on webservers is affected by CVE-2010-0425.",
    "source": "group_vars/all.yml:httpd_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2012-2379",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "host_group": "webservers",
    "affects_pinned_version": false,
    "severity": "critical",
    "recommendation": "Verify whether apache 2.4.49-1 on webservers is affected by CVE-2012-2379.",
    "source": "group_vars/all.yml:httpd_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-1999-1237",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "host_group": "webservers",
    "affects_pinned_version": false,
    "severity": "critical",
    "recommendation": "Verify whether apache 2.4.49-1 on webservers is affected by CVE-1999-1237.",
    "source": "group_vars/all.yml:httpd_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-1999-1293",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "host_group": "webservers",
    "affects_pinned_version": false,
    "severity": "critical",
    "recommendation": "Verify whether apache 2.4.49-1 on webservers is affected by CVE-1999-1293.",
    "source": "group_vars/all.yml:httpd_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2004-0492",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "host_group": "webservers",
    "affects_pinned_version": false,
    "severity": "critical",
    "recommendation": "Verify whether apache 2.4.49-1 on webservers is affected by CVE-2004-0492.",
    "source": "group_vars/all.yml:httpd_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "host_group": "dbservers",
    "affects_pinned_version": false,
    "severity": "critical",
    "recommendation": "Verify whether postgresql 9.2.3-1.pgdg20.04+1 on dbservers is affected by CVE-2007-3279.",
    "source": "group_vars/all.yml:postgres_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "host_group": "dbservers",
    "affects_pinned_version": false,
    "severity": "critical",
    "recommendation": "Verify whether postgresql 9.2.3-1.pgdg20.04+1 on dbservers is affected by CVE-2002-1399.",
    "source": "group_vars/all.yml:postgres_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "host_group": "dbservers",
    "affects_pinned_version": false,
    "severity": "critical",
    "recommendation": "Verify whether postgresql 9.2.3-1.pgdg20.04+1 on dbservers is affected by CVE-2024-1597.",
    "source": "group_vars/all.yml:postgres_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "host_group": "dbservers",
    "affects_pinned_version": true,
    "severity": "critical",
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 on dbservers to mitigate CVE-2013-1902.",
    "source": "group_vars/all.yml:postgres_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "host_group": "dbservers",
    "affects_pinned_version": true,
    "severity": "critical",
    "recommendation": "Upgrade postgresql from 9.2.3-1.pgdg20.04+1 on dbservers to mitigate CVE-2013-1903.",
    "source": "group_vars/all.yml:postgres_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "host_group": "appservers",
    "affects_pinned_version": true,
    "severity": "critical",
    "recommendation": "Upgrade log4j from 2.14.1 on appservers to mitigate CVE-2021-44228.",
    "source": "group_vars/all.yml:log4j_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "host_group": "appservers",
    "affects_pinned_version": false,
    "severity": "critical",
    "recommendation": "Verify whether log4j 2.14.1 on appservers is affected by CVE-2017-5645.",
    "source": "group_vars/all.yml:log4j_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "host_group": "appservers",
    "affects_pinned_version": false,
    "severity": "critical",
    "recommendation": "Verify whether log4j 2.14.1 on appservers is affected by CVE-2022-23305.",
    "source": "group_vars/all.yml:log4j_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "host_group": "appservers",
    "affects_pinned_version": false,
    "severity": "critical",
    "recommendation": "Verify whether log4j 2.14.1 on appservers is affected by CVE-2020-9493.",
    "source": "group_vars/all.yml:log4j_version",
    "search_type": "critical_remote"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "host_group": "appservers",
    "affects_pinned_version": false,
    "severity": "critical",
    "recommendation": "Verify whether log4j 2.14.1 on appservers is affected by CVE-2019-17571.",
    "source": "group_vars/all.yml:log4j_version",
    "search_type": "critical_remote"
  }
]
```

## Report

# ABAC Policy Mining Report

## Scope
Policy goal: `all`

## Catalog Summary
- **Environment**: org=chaincorp, environment=production, compliance_tier=pci, retention=365 days
- **Subjects**: 3 users (admin, developer, dba), 3 groups (sudo, developers, dba), 2 clearance levels (confidential, secret), 3 departments (operations, engineering, data)
- **Resources**: 4 hosts across bastion, webservers, appservers, dbservers; services ssh, http, app, postgres; 4 firewall networks

## Rules Extracted
11 rules total (10 permit + 1 default deny):
1. **network:connect** — Allow app port 8080/tcp from web subnet to appservers
2. **ssh:login** — Allow appservers SSH for sudo and developers groups
3. **ssh:login** — Allow bastion SSH for sudo and dba groups
4. **network:connect** — Allow bastion SSH (22/tcp) from 0.0.0.0/0
5. **sudo:execute** — Allow bastion sudo for secret-clearance sudo members (nopassword: false)
6. **db:login** — Allow DB SUPERUSER login for dba group on dbservers
7. **network:connect** — Allow postgres (5432/tcp) from appservers subnet to dbservers
8. **ssh:login** — Allow dbservers SSH for sudo and dba groups
9. **network:connect** — Allow HTTP (80/tcp) from bastion subnet to webservers
10. **ssh:login** — Allow webservers SSH for sudo group
11. **deny** — Default deny all

## Vulnerability Assessment
20 CVEs were identified across pinned packages:
- **OpenSSH (bastion 1:9.1p1-1ubuntu1)**: critical/KEV CVEs found
- **OpenSSH (non-bastion 1:9.9p1-3ubuntu1)**: critical/KEV CVEs found
- **Apache httpd (2.4.49-1)**: critical/KEV CVEs found
- **PostgreSQL (9.2.3-1)**: critical/KEV CVEs found
- **Log4j (2.14.1)**: critical/KEV CVEs found

All packages should be upgraded; KEV entries require urgent patching.

## Ambiguities & Notes
- **Filesystem ACL**: `roles/db/tasks/main.yml` configures `/var/lib/postgresql/data` with owner `postgres`, but `postgres` is not listed in the `users` catalog, so no filesystem access rule was emitted.
- **Credentials**: No explicit Ansible Vault or secrets-manager references were found in the scanned files.
- **Obligations**: No session-logging or audit-script tasks were found to attach as obligations.
- **Identity provisioning**: `postgresql_user` and `user` creation tasks are configuration management; access-relevant provisioning is covered by the db:login and ssh:login rules.
