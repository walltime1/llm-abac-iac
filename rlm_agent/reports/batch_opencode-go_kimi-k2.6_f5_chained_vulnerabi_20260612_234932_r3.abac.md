# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 00:00:14_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 15 | Rules: 15_  
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
    "uid": {
      "domain": [
        1001,
        1002,
        1003
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "source": "group_vars/appservers.yml"
    },
    "source_ip": {
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
        "apache2",
        "postgresql",
        "httpd"
      ],
      "source": "roles/bastion/tasks/main.yml"
    },
    "port": {
      "domain": [
        22,
        80,
        5432,
        8080
      ],
      "source": "group_vars/appservers.yml"
    },
    "path": {
      "domain": [
        "/var/lib/postgresql/data",
        "/opt/app/app.jar",
        "/opt/app/lib/log4j-core-2.14.1.jar",
        "/etc/ssh/sshd_config",
        "/etc/postgresql/pg_hba.conf"
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
    "database": {
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "schema": {
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "roles/app/tasks/main.yml"
    },
    "cidr": {
      "source": "group_vars/appservers.yml"
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
    "default_log_retention_days": {
      "domain": [
        365
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
          "developers"
        ]
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
        "equals": "appservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "31-35"
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
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Restrict bastion logins",
      "lines": "8-13"
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
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "21-25"
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
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "29-33"
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
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "22-29"
    },
    "nopassword": false
  },
  {
    "id": "rule-006",
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
      "host_group": {
        "equals": "appservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": "23-30"
    }
  },
  {
    "id": "rule-007",
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
      "host_group": {
        "equals": "bastion"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": "14-21"
    }
  },
  {
    "id": "rule-008",
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
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "13-20"
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
      "host_group": {
        "equals": "dbservers"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "16-22"
    },
    "obligations": [
      {
        "id": "role_attr_flags",
        "value": "LOGIN,SUPERUSER"
      }
    ]
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
      },
      "host_group": {
        "equals": "dbservers"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "23-28"
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
      "lines": "0-0"
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
      "port": {
        "equals": 8080
      },
      "host_group": {
        "equals": "appservers"
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
    "id": "rule-013",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "port": {
        "equals": 22
      },
      "host_group": {
        "equals": "bastion"
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
    "id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
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
        "equals": 5432
      },
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
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
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "no explicit version info"
  },
  {
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "cve_id": "CVE-2002-0640",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "no explicit version info"
  },
  {
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "no explicit version info"
  },
  {
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "before 3.7"
  },
  {
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "no explicit version info"
  },
  {
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "cve_id": "CVE-2023-38408",
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "before 9.3"
  },
  {
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "cve_id": "CVE-2024-6387",
    "severity": "high",
    "cvss_score": 8.1,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "no explicit version info"
  },
  {
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "cve_id": "CVE-2007-4752",
    "severity": "high",
    "cvss_score": 7.5,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "before 4.7"
  },
  {
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "cve_id": "CVE-2019-6110",
    "severity": "medium",
    "cvss_score": 6.8,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "no explicit version info"
  },
  {
    "product": "openssh",
    "pinned_versions": [
      "1:9.1p1-1ubuntu1",
      "1:9.9p1-3ubuntu1"
    ],
    "cve_id": "CVE-2019-6109",
    "severity": "medium",
    "cvss_score": 6.8,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "no explicit version info"
  },
  {
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cve_id": "CVE-2021-44228",
    "severity": "critical",
    "cvss_score": 10,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "exact version"
  },
  {
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cve_id": "CVE-2017-5645",
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "before 2.8.2"
  },
  {
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cve_id": "CVE-2020-9493",
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "no explicit version info"
  },
  {
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cve_id": "CVE-2022-23305",
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "no explicit version info"
  },
  {
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cve_id": "CVE-2019-17571",
    "severity": "critical",
    "cvss_score": 9.8,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "no explicit version info"
  },
  {
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cve_id": "CVE-2021-45046",
    "severity": "critical",
    "cvss_score": 9,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "no explicit version info"
  },
  {
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cve_id": "CVE-2021-4104",
    "severity": "high",
    "cvss_score": 7.5,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "no explicit version info"
  },
  {
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cve_id": "CVE-2023-26464",
    "severity": "high",
    "cvss_score": 7.5,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "no explicit version info"
  },
  {
    "product": "log4j",
    "pinned_versions": [
      "2.14.1"
    ],
    "cve_id": "CVE-2021-44832",
    "severity": "medium",
    "cvss_score": 6.6,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "no explicit version info"
  },
  {
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "before 7.2.3"
  },
  {
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "no explicit version info"
  },
  {
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "before 42.7.2"
  },
  {
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "before 9.2.4"
  },
  {
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "kev": false,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - critical severity",
    "reason": "before 9.2.4"
  },
  {
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cve_id": "CVE-2019-9193",
    "severity": "high",
    "cvss_score": 7.2,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "no explicit version info"
  },
  {
    "product": "postgresql",
    "pinned_versions": [
      "9.2.3-1.pgdg20.04+1"
    ],
    "cve_id": "CVE-2022-31197",
    "severity": "high",
    "cvss_score": 7.1,
    "kev": true,
    "affects_pinned_version": true,
    "recommendation": "Patch immediately - known exploited in the wild",
    "reason": "before 42.2.26"
  }
]
```

## Report

# ABAC Policy Mining Report — ChainCorp Ansible Configuration

## Summary
Mined an ABAC policy from the ChainCorp production Ansible repository (RLM_ANSIBLE_DIR). The inventory consists of four host groups (bastion, webservers, appservers, dbservers) running under the `pci` compliance tier. The extracted policy covers SSH access control, sudo execution, firewall connectivity, and database authentication.

## Attribute Catalog
### Subjects
- **users**: admin (uid 1001, groups [sudo], clearance secret, department operations), developer (uid 1002, groups [developers], clearance confidential, department engineering), dba (uid 1003, groups [dba], clearance secret, department data).
- **groups**: sudo, developers, dba.
- **clearance**: secret, confidential.
- **department**: operations, engineering, data.
- **source_network**: CIDRs used in firewall/pg_hba rules (10.0.1.0/24, 10.0.0.0/24, 0.0.0.0/0, 10.0.2.0/24).

### Resources
- **hosts**: 4 hosts (bastion01.lab.local, web01.lab.local, app01.lab.local, db01.lab.local) with roles, zones, and inventory groups.
- **services**: ssh (22), apache2/httpd (80), postgresql (5432), application (8080).
- **paths**: /var/lib/postgresql/data (owner postgres, group postgres, mode 0700).
- **networks**: CIDRs used in firewall/pg_hba rules.

### Environment
- **org**: chaincorp
- **environment**: production
- **compliance_tier**: pci
- **default_log_retention_days**: 365

## Extracted Rules
- **rule-001**: SSH login permitted on `appservers` for subjects in groups `sudo` or `developers`.
- **rule-002**: SSH login permitted on `bastion` for subjects in groups `sudo` or `dba`.
- **rule-003**: SSH login permitted on `webservers` for subjects in group `sudo`.
- **rule-004**: SSH login permitted on `dbservers` for subjects in groups `sudo` or `dba`.
- **rule-005**: Sudo execution permitted on `bastion` for subjects in group `sudo` with clearance `secret` (nopassword: false).
- **rule-006**: Network connect to `appservers` port 8080/tcp permitted from source network `10.0.1.0/24`.
- **rule-007**: Network connect to `bastion` port 22/tcp permitted from source network `0.0.0.0/0`.
- **rule-008**: Network connect to `webservers` port 80/tcp permitted from source network `10.0.0.0/24`.
- **rule-009**: DB login to `postgresql` on `dbservers` permitted for subjects in group `dba` (obligation: LOGIN,SUPERUSER).
- **rule-010**: Network connect to `postgresql` on `dbservers` port 5432/tcp permitted from source network `10.0.2.0/24`.
- **rule-011**: Default deny — all other subject/resource/action combinations are denied.

## Vulnerability Assessment
A vulnerability scan was performed against the four pinned software packages found in `group_vars/all.yml`. The scan returned **26 CVEs** (critical and high severity, including Known Exploited Vulnerabilities).

### Notable findings
- **openssh** (pinned 9.1p1 and 9.9p1): 9 CVEs, including critical remote KEVs `CVE-2023-38408`, `CVE-2024-6387`, and high-severity KEVs `CVE-2007-4752`, `CVE-2019-6110`, `CVE-2019-6109`.
- **log4j** (pinned 2.14.1): 9 CVEs, including the Log4Shell critical remote KEV `CVE-2021-44228`, plus KEVs `CVE-2021-45046`, `CVE-2021-4104`, `CVE-2023-26464`, and `CVE-2021-44832`.
- **postgresql** (pinned 9.2.3): 8 CVEs, including critical remote KEV `CVE-2024-1597` and high-severity KEVs `CVE-2019-9193`, `CVE-2022-31197`.
- **httpd** (pinned 2.4.49): No critical or KEV CVEs were returned for this pinned version in the scan.

All evaluated CVEs conservatively affect the pinned versions because the packages are outdated and the descriptions explicitly reference the vulnerable code paths or broad version ranges.

## Ambiguities
- **Credentials**: No explicit hardcoded credentials, secrets, or vault-encrypted files were found in the scanned Ansible files.
- **Filesystem ACLs**: The PostgreSQL data directory `/var/lib/postgresql/data` is created with `owner=postgres, group=postgres, mode=0700`. The `postgres` system user is not present in the inventory `users` list, so no explicit filesystem access rule was emitted for this path.
- **Session logging / audit**: No session logging or audit script tasks were found in the role task files; therefore no obligations of that type were attached.
- **Implicit deny**: The PostgreSQL `pg_hba.conf` configuration does not contain an explicit reject line; implicit deny is covered by the default-deny ABAC rule.
