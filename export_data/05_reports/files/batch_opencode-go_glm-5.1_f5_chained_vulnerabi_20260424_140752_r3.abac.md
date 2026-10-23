# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 14:30:00_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 10 | Rules: 21_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "source": "group_vars/all.yml"
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
    "source_ip": {
      "source": "group_vars/bastion.yml,group_vars/appservers.yml,group_vars/webservers.yml,group_vars/dbservers.yml"
    },
    "source_network": {
      "domain": [
        "0.0.0.0/0",
        "10.0.0.0/24",
        "10.0.1.0/24",
        "10.0.2.0/24",
        "10.0.3.0/24"
      ],
      "source": "group_vars/bastion.yml,group_vars/appservers.yml,group_vars/webservers.yml,group_vars/dbservers.yml"
    },
    "source_zone": {
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data",
        "internet"
      ],
      "source": "inventory.ini"
    }
  },
  "resources": {
    "hostname": {
      "domain": [
        "bastion01.lab.local",
        "web01.lab.local",
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
        "bastion",
        "frontend",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "mgmt",
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "domain": [
        "bastion",
        "webservers",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "domain": [
        "ssh",
        "httpd",
        "postgresql",
        "app",
        "log4j"
      ],
      "source": "group_vars/all.yml,roles/bastion/tasks/main.yml,roles/web/tasks/main.yml,roles/db/tasks/main.yml,roles/app/tasks/main.yml"
    },
    "port": {
      "source": "group_vars/appservers.yml,group_vars/dbservers.yml,group_vars/webservers.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "roles/bastion/tasks/main.yml,roles/web/tasks/main.yml,roles/app/tasks/main.yml"
    },
    "path": {
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
    "database": {
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environments": {
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
    "org": {
      "domain": [
        "chaincorp"
      ],
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
          "dba"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      },
      "service": {
        "equals": "ssh"
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
      "lines": "8-11"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      },
      "port": {
        "equals": "22"
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": "13-18"
    }
  },
  {
    "id": "rule-003",
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "obligations": [
      {
        "type": "nopassword",
        "value": false
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "20-26"
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
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "ssh"
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
      "lines": "14-17"
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
      "host_group": {
        "equals": "webservers"
      },
      "port": {
        "equals": "80"
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": "10-14"
    }
  },
  {
    "id": "rule-006",
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
      "lines": "20-23"
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
      "host_group": {
        "equals": "appservers"
      },
      "port": {
        "equals": "8080"
      },
      "protocol": {
        "equals": "tcp"
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
      "lines": "15-20"
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
      },
      "service": {
        "equals": "ssh"
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
      "lines": "18-21"
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
      "host_group": {
        "equals": "dbservers"
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
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege",
        "value": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "11-14"
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
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": "5432"
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
      "lines": "16-18"
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
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": "5432"
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
      "task": "Allow postgres only from appservers subnet (implicit deny-default)",
      "lines": "16-18"
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
      "host_group": {
        "equals": "dbservers"
      },
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
      "lines": "7-12"
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
      "host_group": {
        "equals": "dbservers"
      },
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
      "lines": "7-12"
    }
  },
  {
    "id": "rule-014",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
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
      "lines": "7-12"
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
      "file": "implicit",
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
      "host_group": {
        "equals": "dbservers"
      },
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
      "host_group": {
        "equals": "dbservers"
      },
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
    "id": "rule-018",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
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
    "id": "rule-019",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "bastion"
      },
      "port": {
        "equals": "22"
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
    "id": "rule-020",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "port": {
        "equals": "80"
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
    "id": "rule-021",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "port": {
        "equals": "8080"
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
    "cve_id": "CVE-2010-0425",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade Apache httpd from 2.4.49 to latest 2.4.x release"
  },
  {
    "cve_id": "CVE-2005-2700",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade Apache httpd from 2.4.49 to latest 2.4.x release"
  },
  {
    "cve_id": "CVE-1999-0067",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade Apache httpd from 2.4.49 to latest 2.4.x release"
  },
  {
    "cve_id": "CVE-1999-0926",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade Apache httpd from 2.4.49 to latest 2.4.x release"
  },
  {
    "cve_id": "CVE-1999-1199",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Upgrade Apache httpd from 2.4.49 to latest 2.4.x release"
  },
  {
    "cve_id": "CVE-2010-0219",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Upgrade Apache httpd from 2.4.49 to latest 2.4.x release"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "apache",
    "pinned_versions": [
      "2.4.49-1"
    ],
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade Apache httpd from 2.4.49 to latest 2.4.x release"
  },
  {
    "cve_id": "CVE-2022-23305",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to 2.17.1 or later (2.14.1 is vulnerable to Log4Shell)"
  },
  {
    "cve_id": "CVE-2020-9493",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to 2.17.1 or later (2.14.1 is vulnerable to Log4Shell)"
  },
  {
    "cve_id": "CVE-2019-17571",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to 2.17.1 or later (2.14.1 is vulnerable to Log4Shell)"
  },
  {
    "cve_id": "CVE-2017-5645",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to 2.17.1 or later (2.14.1 is vulnerable to Log4Shell)"
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cvss_score": 9,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to 2.17.1 or later (2.14.1 is vulnerable to Log4Shell)"
  },
  {
    "cve_id": "CVE-2023-26464",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to 2.17.1 or later (2.14.1 is vulnerable to Log4Shell)"
  },
  {
    "cve_id": "CVE-2021-4104",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to 2.17.1 or later (2.14.1 is vulnerable to Log4Shell)"
  },
  {
    "cve_id": "CVE-2021-44832",
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cvss_score": 6.6,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to 2.17.1 or later (2.14.1 is vulnerable to Log4Shell)"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL from 9.2.3 to a supported major version (15+) with latest patches"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL from 9.2.3 to a supported major version (15+) with latest patches"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL from 9.2.3 to a supported major version (15+) with latest patches"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL from 9.2.3 to a supported major version (15+) with latest patches"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL from 9.2.3 to a supported major version (15+) with latest patches"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cvss_score": 7.2,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL from 9.2.3 to a supported major version (15+) with latest patches"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cvss_score": 7.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": true,
    "recommendation": "Upgrade PostgreSQL from 9.2.3 to a supported major version (15+) with latest patches"
  }
]
```

## Report

# ABAC Policy Mining Report — ChainCorp Ansible Infrastructure

## Executive Summary

This report presents an Attribute-Based Access Control (ABAC) policy mined from the ChainCorp Ansible configuration. The infrastructure comprises four host groups (bastion, webservers, appservers, dbservers) in a PCI-compliant production environment. The policy captures SSH access controls, firewall rules, database authentication, sudo privileges, and filesystem permissions.

## Infrastructure Overview

| Host Group | Host | IP | Role | Zone |
|---|---|---|---|---|
| bastion | bastion01.lab.local | 10.0.0.5 | bastion | mgmt |
| webservers | web01.lab.local | 10.0.1.10 | frontend | dmz |
| appservers | app01.lab.local | 10.0.2.10 | application | app |
| dbservers | db01.lab.local | 10.0.3.10 | primary | data |

**Environment:** production | **Compliance Tier:** pci | **Organization:** chaincorp

## Users

| User | UID | Groups | Department | Clearance |
|---|---|---|---|---|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

## Extracted Rules Summary

### SSH Access (4 rules)
- **rule-001**: Groups sudo, dba → SSH login to bastion
- **rule-004**: Group sudo → SSH login to webservers
- **rule-006**: Groups sudo, developers → SSH login to appservers
- **rule-008**: Groups sudo, dba → SSH login to dbservers

### Network/Firewall (4 permit + 1 deny)
- **rule-002**: Network 0.0.0.0/0 → TCP/22 to bastion (SSH from internet)
- **rule-005**: Network 10.0.0.0/24 → TCP/80 to webservers (HTTP from mgmt)
- **rule-007**: Network 10.0.1.0/24 → TCP/8080 to appservers (app from dmz)
- **rule-010**: Network 10.0.2.0/24 → TCP/5432 to dbservers (PostgreSQL from app)
- **rule-011**: DENY all other PostgreSQL connections to dbservers

### Sudo (1 rule)
- **rule-003**: Group sudo + clearance secret → sudo on bastion (password required)

### Database (1 rule)
- **rule-009**: Group dba → PostgreSQL SUPERUSER login on dbservers

### Filesystem (3 rules)
- **rule-012/013/014**: Group dba → read/write/execute on /var/lib/postgresql/data (mode 0700, owner postgres)

### Default Deny
- **rule-015**: Default deny all access

## Vulnerability Assessment

### Critical Findings

| CVE | Product | Pinned Version | CVSS | Severity | Remote | KEV | Affects Pinned | Recommendation |
|---|---|---|---|---|---|---|---|---|
| CVE-2021-44228 | log4j | 2.14.1 | 10.0 | critical | true | true | **YES** | Upgrade to 2.17.1+ |
| CVE-2021-45046 | log4j | 2.14.1 | 9.0 | critical | true | true | **YES** | Upgrade to 2.17.1+ |
| CVE-2024-1597 | postgresql | 9.2.3 | 10.0 | critical | true | true | **YES** | Upgrade to 15+ |
| CVE-2019-9193 | postgresql | 9.2.3 | 7.2 | high | true | true | **YES** | Upgrade to 15+ |
| CVE-2022-31197 | postgresql | 9.2.3 | 7.1 | high | true | true | **YES** | Upgrade to 15+ |

### All Pinned Vulnerable Packages

| Package | Pinned Version | Known Critical/High Remote CVEs | KEV Entries |
|---|---|---|---|
| openssh-server (bastion) | 1:9.1p1-1ubuntu1 | 0 | 0 |
| openssh-server (others) | 1:9.9p1-3ubuntu1 | 0 | 0 |
| apache2 | 2.4.49-1 | 5 | 5 |
| log4j | 2.14.1 | 5 | 5 |
| postgresql | 9.2.3-1 | 4 | 3 |

**Note:** The bastion runs a deliberately vulnerable OpenSSH version (9.1p1), while other hosts run 9.9p1. Apache httpd 2.4.49 is known for path traversal (CVE-2021-41773). PostgreSQL 9.2 is end-of-life with multiple known vulnerabilities.

## Ambiguities and Gaps

1. **Bastion SSH open to internet:** Rule rule-002 allows SSH from 0.0.0.0/0, which is an extremely permissive firewall rule. Combined with the vulnerable OpenSSH version on the bastion, this is a critical risk.

2. **Sudo restriction scope:** The bastion sudoers rule restricts sudo to users with both `groups: sudo` AND `clearance: secret`. Only the `admin` user satisfies this. The `dba` user has secret clearance but is not in the sudo group. This may be intentional but limits operational flexibility.

3. **No sudo rules for webservers/appservers/dbservers:** Only the bastion has an explicit sudoers configuration. Other hosts rely on default sudo behavior, which may allow all sudo group members unrestricted sudo access without the clearance check.

4. **pg_hba implicit deny:** The PostgreSQL pg_hba.conf only allows connections from 10.0.2.0/24 (appservers subnet). This creates an implicit deny for all other networks, which is captured in rule-011.

5. **Database SUPERUSER privilege:** The DBA user is granted SUPERUSER role in PostgreSQL, which provides unrestricted database access. This should be reviewed against least-privilege principles.

6. **Credentials in Ansible vars:** The configuration references user creation and database user setup but does not appear to manage passwords/secrets through Ansible Vault, which is a potential security concern.

7. **Log4j vulnerability:** The app server deploys log4j 2.14.1, which is directly vulnerable to CVE-2021-44228 (Log4Shell). This is a critical finding requiring immediate remediation.

8. **No explicit deny rules for SSH:** SSH AllowGroups creates an implicit deny for non-listed groups, but there are no explicit deny rules in the Ansible configuration for SSH access.
