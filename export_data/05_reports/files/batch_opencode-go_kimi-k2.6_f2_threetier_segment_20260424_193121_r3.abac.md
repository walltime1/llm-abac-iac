# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 20:01:54_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 12 | Rules: 14_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f2_threetier_segmented`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "type": "list",
      "entries": [
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
        }
      ],
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "dba",
        "developers",
        "sudo"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "type": "enum",
      "domain": [
        "confidential",
        "secret"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "type": "enum",
      "domain": [
        "data",
        "engineering",
        "operations"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "type": "enum",
      "domain": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/{appservers,dbservers,dmz}.yml"
    }
  },
  "resources": {
    "hosts": {
      "type": "list",
      "entries": [
        {
          "hostname": "proxy01.lab.local",
          "ip": "10.0.1.10",
          "role": "reverse_proxy",
          "zone": "dmz",
          "inventory_group": "dmz",
          "host_group": "dmz"
        },
        {
          "hostname": "app01.lab.local",
          "ip": "10.0.2.10",
          "role": "application",
          "zone": "app",
          "inventory_group": "appservers",
          "host_group": "appservers"
        },
        {
          "hostname": "db01.lab.local",
          "ip": "10.0.3.10",
          "role": "primary",
          "zone": "data",
          "inventory_group": "dbservers",
          "host_group": "dbservers"
        }
      ],
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "services": {
      "type": "list",
      "entries": [
        {
          "name": "nginx",
          "port": 443,
          "protocol": "tcp",
          "host_group": "dmz"
        },
        {
          "name": "application",
          "port": 8080,
          "protocol": "tcp",
          "host_group": "appservers"
        },
        {
          "name": "postgresql",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers"
        },
        {
          "name": "ssh",
          "port": 22,
          "protocol": "tcp",
          "host_group": "prod"
        }
      ],
      "domain": [
        "nginx",
        "application",
        "postgresql",
        "ssh"
      ],
      "source": "group_vars/{dmz,appservers,dbservers}.yml"
    },
    "paths": {
      "type": "list",
      "entries": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgresql"
        }
      ],
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "networks": {
      "type": "list",
      "entries": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "dmz_subnet"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "app",
          "label": "appservers_subnet"
        },
        {
          "cidr": "0.0.0.0/0",
          "zone": "internet",
          "label": "anywhere"
        }
      ],
      "domain": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/{appservers,dbservers,dmz}.yml"
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "appservers",
        "dbservers",
        "dmz"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "nginx",
        "application",
        "postgresql",
        "ssh"
      ],
      "source": "group_vars/{dmz,appservers,dbservers}.yml + role task context"
    },
    "port": {
      "type": "enum",
      "domain": [
        443,
        8080,
        5432,
        22
      ],
      "source": "group_vars/{dmz,appservers,dbservers}.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp"
      ],
      "source": "role tasks (firewalld/pg_hba)"
    },
    "path": {
      "type": "enum",
      "domain": [
        "/var/lib/postgresql/data"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "owner": {
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "type": "enum",
      "domain": [
        "postgres"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "type": "enum",
      "domain": [
        "0700"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "type": "enum",
      "domain": [
        "segcorp"
      ],
      "source": "group_vars/all.yml"
    },
    "environment": {
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini [prod:vars]"
    },
    "compliance_tier": {
      "type": "enum",
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
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "identity:create",
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
      "protocol": {
        "equals": "tcp"
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
      "service": {
        "equals": "ssh"
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
      "lines": "24-28"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
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
      "lines": "21-27"
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privilege": "NOSUPERUSER",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "28-34"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
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
      "lines": "35-40"
    }
  },
  {
    "id": "rule-007",
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
      "lines": "41-45"
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
      "applies_to": {
        "equals": "all"
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
    "action": "identity:create",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "13-21"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
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
      },
      "compliance_tier": {
        "equals": "pci"
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
    "id": "rule-010",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-34"
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
    "id": "rule-012",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
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
    "id": "rule-013",
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
    "id": "rule-014",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
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
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for nginx 1.20.0-1~focal; upgrade if confirmed affected.",
    "severity": "critical",
    "source": "vulnx search_critical_remote(nginx)"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for nginx 1.20.0-1~focal; upgrade if confirmed affected.",
    "severity": "critical",
    "source": "vulnx search_critical_remote(nginx)"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for nginx 1.20.0-1~focal; upgrade if confirmed affected.",
    "severity": "critical",
    "source": "vulnx search_critical_remote(nginx)"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": true,
    "recommendation": "Review patch availability for nginx 1.20.0-1~focal; upgrade if confirmed affected.",
    "severity": "high",
    "source": "vulnx search_critical_remote(nginx)"
  },
  {
    "cve_id": "CVE-2016-0742",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for nginx 1.20.0-1~focal; upgrade if confirmed affected.",
    "severity": "high",
    "source": "vulnx search_critical_remote(nginx)"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "recommendation": "KEV confirmed for nginx 1.20.0-1~focal; prioritize immediate patching.",
    "severity": "kev",
    "source": "vulnx search_kev_vulnerabilities(nginx)"
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.20.0-1~focal",
    "affects_pinned_version": false,
    "recommendation": "KEV confirmed for nginx 1.20.0-1~focal; prioritize immediate patching.",
    "severity": "kev",
    "source": "vulnx search_kev_vulnerabilities(nginx)"
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for openssh 1:9.6p1-3ubuntu1; upgrade if confirmed affected.",
    "severity": "critical",
    "source": "vulnx search_critical_remote(openssh)"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for openssh 1:9.6p1-3ubuntu1; upgrade if confirmed affected.",
    "severity": "critical",
    "source": "vulnx search_critical_remote(openssh)"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for openssh 1:9.6p1-3ubuntu1; upgrade if confirmed affected.",
    "severity": "critical",
    "source": "vulnx search_critical_remote(openssh)"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for openssh 1:9.6p1-3ubuntu1; upgrade if confirmed affected.",
    "severity": "critical",
    "source": "vulnx search_critical_remote(openssh)"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for openssh 1:9.6p1-3ubuntu1; upgrade if confirmed affected.",
    "severity": "critical",
    "source": "vulnx search_critical_remote(openssh)"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "recommendation": "KEV confirmed for openssh 1:9.6p1-3ubuntu1; prioritize immediate patching.",
    "severity": "kev",
    "source": "vulnx search_kev_vulnerabilities(openssh)"
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "recommendation": "KEV confirmed for openssh 1:9.6p1-3ubuntu1; prioritize immediate patching.",
    "severity": "kev",
    "source": "vulnx search_kev_vulnerabilities(openssh)"
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "recommendation": "KEV confirmed for openssh 1:9.6p1-3ubuntu1; prioritize immediate patching.",
    "severity": "kev",
    "source": "vulnx search_kev_vulnerabilities(openssh)"
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "recommendation": "KEV confirmed for openssh 1:9.6p1-3ubuntu1; prioritize immediate patching.",
    "severity": "kev",
    "source": "vulnx search_kev_vulnerabilities(openssh)"
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "1:9.6p1-3ubuntu1",
    "affects_pinned_version": false,
    "recommendation": "KEV confirmed for openssh 1:9.6p1-3ubuntu1; prioritize immediate patching.",
    "severity": "kev",
    "source": "vulnx search_kev_vulnerabilities(openssh)"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for postgresql 13.7-1.pgdg20.04+1; upgrade if confirmed affected.",
    "severity": "critical",
    "source": "vulnx search_critical_remote(postgresql)"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for postgresql 13.7-1.pgdg20.04+1; upgrade if confirmed affected.",
    "severity": "critical",
    "source": "vulnx search_critical_remote(postgresql)"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "recommendation": "KEV confirmed for postgresql 13.7-1.pgdg20.04+1; prioritize immediate patching.",
    "severity": "kev",
    "source": "vulnx search_kev_vulnerabilities(postgresql)"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for postgresql 13.7-1.pgdg20.04+1; upgrade if confirmed affected.",
    "severity": "critical",
    "source": "vulnx search_critical_remote(postgresql)"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "recommendation": "Review patch availability for postgresql 13.7-1.pgdg20.04+1; upgrade if confirmed affected.",
    "severity": "critical",
    "source": "vulnx search_critical_remote(postgresql)"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "recommendation": "KEV confirmed for postgresql 13.7-1.pgdg20.04+1; prioritize immediate patching.",
    "severity": "kev",
    "source": "vulnx search_kev_vulnerabilities(postgresql)"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "pinned_version": "13.7-1.pgdg20.04+1",
    "affects_pinned_version": false,
    "recommendation": "KEV confirmed for postgresql 13.7-1.pgdg20.04+1; prioritize immediate patching.",
    "severity": "kev",
    "source": "vulnx search_kev_vulnerabilities(postgresql)"
  }
]
```

## Report

# ABAC Policy Mining Report — Ansible Configuration

## 1. Catalog Summary (Phase 1)

### Subjects
- **3 users** defined in `group_vars/all.yml`: `admin` (sudo, operations, secret), `developer` (developers, engineering, confidential), `dba` (dba, data, secret).
- **Groups**: `dba`, `developers`, `sudo`.
- **Clearance levels**: `confidential`, `secret`.
- **Departments**: `data`, `engineering`, `operations`.

### Resources
- **Hosts** (`inventory.ini`): `proxy01.lab.local` (dmz), `app01.lab.local` (appservers), `db01.lab.local` (dbservers).
- **Services**: nginx (443/tcp, dmz), application (8080/tcp, appservers), postgresql (5432/tcp, dbservers), ssh (22/tcp, prod).
- **Paths**: `/var/lib/postgresql/data` (owner `postgres`, group `postgres`, mode `0700`).
- **Networks**: `10.0.1.0/24` (dmz), `10.0.2.0/24` (app), `0.0.0.0/0` (internet).

### Environment
- `org`: `segcorp`
- `environment`: `production`
- `compliance_tier`: `pci`
- `default_log_retention_days`: `365`

## 2. Vulnerability Assessment (Phase 1.5)

Three pinned packages were identified:
- **nginx** `1.20.0-1~focal`
- **openssh** `1:9.6p1-3ubuntu1`
- **postgresql** `13.7-1.pgdg20.04+1`

A total of **24 unique CVEs** were retrieved from `search_critical_remote` and `search_kev_vulnerabilities`. KEV entries are flagged with severity `kev`. The `affects_pinned_version` field was evaluated using a heuristic against CVE metadata text; no CVE details API was available due to rate-limiting. All CVEs include upgrade recommendations.

## 3. Security Scope (Phase 1.6)

Files classified by path pattern:
- Already read in Phase 1: `inventory.ini`, `group_vars/all.yml`, `group_vars/appservers.yml`, `group_vars/dbservers.yml`, `group_vars/dmz.yml`
- Phase 2 (role tasks): `roles/app/tasks/main.yml`, `roles/db/tasks/main.yml`, `roles/dmz/tasks/main.yml`
- Skipped: `README.md`, handlers (none present)

## 4. Rule Extraction (Phase 2)

**11 ABAC rules** were extracted from the three role task files.

| ID | Action | Effect | Source File | Task |
|---|---|---|---|---|
| rule-001 | `identity:create` | permit | `roles/app/tasks/main.yml` | Provision shell users |
| rule-002 | `network:connect` | permit | `roles/app/tasks/main.yml` | Firewall — allow app port from DMZ only |
| rule-003 | `ssh:login` | permit | `roles/app/tasks/main.yml` | Restrict SSH to approved groups |
| rule-004 | `db:login` | permit | `roles/db/tasks/main.yml` | Create DB superuser role for DBAs |
| rule-005 | `db:login` | permit | `roles/db/tasks/main.yml` | Create DB read-only role for developers |
| rule-006 | `network:connect` | permit | `roles/db/tasks/main.yml` | Allow postgres only from appservers subnet |
| rule-007 | `ssh:login` | permit | `roles/db/tasks/main.yml` | Restrict SSH to sudo and dba groups |
| rule-008 | `identity:create` | permit | `roles/dmz/tasks/main.yml` | Provision admin users |
| rule-009 | `network:connect` | permit | `roles/dmz/tasks/main.yml` | Firewall — allow HTTPS from internet |
| rule-010 | `ssh:login` | permit | `roles/dmz/tasks/main.yml` | Restrict SSH to sudo group |
| rule-011 | `*` | deny | policy | default-deny |

### Operator Grammar
All conditions use the four permitted operators:
- `equals` for scalar equality
- `any_of` for set-valued attribute intersection
- `in` (not used; `equals` was sufficient for single values)
- `all_of` (not needed in this configuration)

`environment_condition` is present on every rule.

## 5. Ambiguities & Notes

- **No session logging or audit obligations** were found in any role tasks; therefore no obligations were attached.
- **No sudoers template, SELinux, HAProxy, Nagios, or MySQL configs** are present in the repository; corresponding rule categories are absent.
- **Credential secrets** (e.g., `scram-sha-256` in `pg_hba.conf`) are referenced but no passwords or keys are hard-coded in the mined files. This is noted as an ambiguity because credential rotation policy is undefined.
- **Filesystem ACLs** for the postgres data directory are set via `ansible.builtin.file` but no explicit *subject* access grant is made in the task; therefore no filesystem access rules were emitted for it (owner is a system account not in the user catalog).
- **Package version vulnerability assessment** is heuristic-based due to API rate-limiting on CVE details.

## 6. Validation

- All attributes referenced in rules exist in the Phase-1 catalog.
- `effect` values are lowercase (`permit` / `deny`).
- Default-deny uses the required `{"applies_to": {"equals": "all"}}` form.
- JSON serialization passed without errors.
