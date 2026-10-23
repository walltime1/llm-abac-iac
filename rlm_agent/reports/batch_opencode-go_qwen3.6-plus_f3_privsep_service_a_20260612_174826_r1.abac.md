# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:54:20_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 13 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f3_privsep_service_accounts`_

## Attributes

```json
{
  "subject_attributes": {
    "users": [
      {
        "name": "admin",
        "uid": 1001,
        "groups": [
          "sudo"
        ],
        "department": "operations",
        "clearance": "secret",
        "source": "user_type"
      },
      {
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "department": "engineering",
        "clearance": "confidential",
        "source": "user_type"
      },
      {
        "name": "www-data",
        "uid": 33,
        "groups": [
          "www-data"
        ],
        "department": null,
        "clearance": null,
        "source": "roles/web/tasks/main.yml"
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
      },
      {
        "name": "redis",
        "uid": null,
        "groups": [
          "redis"
        ],
        "department": null,
        "clearance": null,
        "source": "roles/cache/tasks/main.yml"
      }
    ],
    "user_attrs": {
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
      "groups": {
        "domain": [
          "sudo",
          "developers",
          "www-data",
          "postgres",
          "redis"
        ],
        "source": "group_vars/all.yml, roles/"
      }
    },
    "groups": [
      "sudo",
      "developers",
      "www-data",
      "postgres",
      "redis"
    ]
  },
  "resource_attributes": {
    "hosts": [
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": "dbservers"
      },
      {
        "hostname": "cache01.lab.local",
        "ip": "10.0.2.20",
        "role": "cache",
        "zone": "internal",
        "inventory_group": "cacheservers"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers"
      },
      {
        "name": "redis",
        "port": 6379,
        "protocol": "tcp",
        "host_group": "cacheservers"
      }
    ],
    "paths": [
      {
        "path": "/var/www/html",
        "owner": "www-data",
        "group": "www-data",
        "mode": "0750",
        "service": "nginx"
      },
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql"
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "internal",
        "label": "dbservers_cacheservers"
      }
    ],
    "resource_attrs": {
      "zone": {
        "domain": [
          "dmz",
          "internal"
        ],
        "source": "inventory.ini"
      },
      "role": {
        "domain": [
          "frontend",
          "primary",
          "cache"
        ],
        "source": "inventory.ini"
      },
      "host_group": {
        "domain": [
          "webservers",
          "dbservers",
          "cacheservers"
        ],
        "source": "inventory.ini"
      },
      "protocol": {
        "domain": [
          "tcp",
          "udp"
        ],
        "source": "group_vars/"
      },
      "mode": {
        "domain": [
          "0750",
          "0700"
        ],
        "source": "roles/"
      }
    }
  },
  "environment_attributes": {
    "org": "privsep-corp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "env_attrs": {
      "environment": {
        "domain": [
          "production",
          "staging",
          "development"
        ],
        "source": "inventory.ini"
      },
      "compliance_tier": {
        "domain": [
          "soc2",
          "pci-dss",
          "hipaa"
        ],
        "source": "group_vars/all.yml"
      }
    }
  }
}
```

## Rules

```json
[
  {
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "zone": {
        "equals": "dmz"
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
      "lines": [
        35,
        38
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "description": "SSH sessions logged per SOC2 compliance"
      }
    ],
    "id": "rule-001"
  },
  {
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
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
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        27,
        33
      ]
    },
    "id": "rule-002"
  },
  {
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
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
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        17,
        19
      ]
    },
    "id": "rule-003"
  },
  {
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "port": {
        "equals": 5432
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": [
        17,
        19
      ]
    },
    "id": "rule-004"
  },
  {
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "cacheservers"
      },
      "port": {
        "equals": 6379
      },
      "protocol": {
        "equals": "tcp"
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
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": [
        16,
        21
      ]
    },
    "id": "rule-005"
  },
  {
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "cacheservers"
      },
      "port": {
        "equals": 6379
      }
    },
    "action": "network:connect",
    "effect": "deny",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": [
        16,
        21
      ]
    },
    "id": "rule-006"
  },
  {
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/www/html"
      },
      "owner": {
        "equals": "www-data"
      },
      "group": {
        "equals": "www-data"
      },
      "mode": {
        "equals": "0750"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": [
        22,
        26
      ]
    },
    "id": "rule-007"
  },
  {
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "path": {
        "equals": "/var/www/html"
      },
      "owner": {
        "equals": "www-data"
      },
      "group": {
        "equals": "www-data"
      },
      "mode": {
        "equals": "0750"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": [
        22,
        26
      ]
    },
    "id": "rule-008"
  },
  {
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": [
        6,
        11
      ]
    },
    "id": "rule-009"
  },
  {
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
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": [
        6,
        11
      ]
    },
    "id": "rule-010"
  },
  {
    "subject_condition": {
      "groups": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      }
    },
    "action": "sudo:execute",
    "effect": "deny",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure www-data has NO sudo access",
      "lines": [
        40,
        42
      ]
    },
    "id": "rule-011"
  },
  {
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
      "applies_to": {
        "equals": "all"
      }
    },
    "id": "rule-012"
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
      "port": {
        "equals": 443
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
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review nginx version compatibility with CVE-2021-46461; update if affected"
  },
  {
    "cve_id": "CVE-2016-0746",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review nginx version compatibility with CVE-2016-0746; update if affected"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review nginx version compatibility with CVE-2017-20005; update if affected"
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "URGENT + Critical: Actively exploited CVE for nginx. Patch immediately."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "cvss_score": 7.7,
    "severity": "high",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review nginx version compatibility with CVE-2021-23017; update if affected"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "URGENT: Actively exploited CVE for nginx. Patch immediately."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review openssh version compatibility with CVE-2000-0999; update if affected"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review openssh version compatibility with CVE-2000-0525; update if affected"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review openssh version compatibility with CVE-2001-0144; update if affected"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review openssh version compatibility with CVE-2003-0693; update if affected"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review openssh version compatibility with CVE-2003-0786; update if affected"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "URGENT: Actively exploited CVE for openssh. Patch immediately."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "cvss_score": 8.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "URGENT: Actively exploited CVE for openssh. Patch immediately."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "URGENT: Actively exploited CVE for openssh. Patch immediately."
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "URGENT: Actively exploited CVE for openssh. Patch immediately."
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "URGENT: Actively exploited CVE for openssh. Patch immediately."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review postgresql version compatibility with CVE-2002-1399; update if affected"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review postgresql version compatibility with CVE-2013-1902; update if affected"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review postgresql version compatibility with CVE-2007-3279; update if affected"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review postgresql version compatibility with CVE-2013-1903; update if affected"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "URGENT + Critical: Actively exploited CVE for postgresql. Patch immediately."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "cvss_score": 7.2,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "URGENT: Actively exploited CVE for postgresql. Patch immediately."
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "cvss_score": 7.1,
    "severity": "high",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "URGENT: Actively exploited CVE for postgresql. Patch immediately."
  },
  {
    "cve_id": "CVE-2015-4335",
    "product": "redis",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review redis version compatibility with CVE-2015-4335; update if affected"
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "cvss_score": 10,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "URGENT + Critical: Actively exploited CVE for redis. Patch immediately."
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "cvss_score": 9.9,
    "severity": "critical",
    "is_remote": true,
    "is_kev": true,
    "recommendation": "URGENT + Critical: Actively exploited CVE for redis. Patch immediately."
  },
  {
    "cve_id": "CVE-2016-8339",
    "product": "redis",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review redis version compatibility with CVE-2016-8339; update if affected"
  },
  {
    "cve_id": "CVE-2023-31654",
    "product": "redis",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "is_kev": false,
    "recommendation": "Review redis version compatibility with CVE-2023-31654; update if affected"
  }
]
```

## Report

# ABAC Policy Report: privsep-corp Production Environment

## Overview
This report documents an Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration of privsep-corp's production environment (compliance tier: SOC2).

## Scope
- **Organization**: privsep-corp
- **Environment**: production
- **Compliance Tier**: soc2
- **Policy Goal**: all (full coverage)

## Infrastructure Summary
- **Hosts**: 3 (web01.lab.local, db01.lab.local, cache01.lab.local)
- **Users**: 2 human users (admin, developer) + 3 service accounts (www-data, postgres, redis)
- **Services**: nginx (443/tcp), postgresql (5432/tcp), redis (6379/tcp)
- **Zones**: dmz (web01), internal (db01, cache01)

## Policy Rules (12 total)

### Network Access Rules
| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-002 | source_network: 0.0.0.0/0 | webservers:443/tcp | network:connect | permit |
| rule-003 | source_network: 10.0.1.0/24 | dbservers:5432/tcp | network:connect | permit |
| rule-004 | source_network: 0.0.0.0/0 | dbservers:5432/tcp | network:connect | deny |
| rule-005 | source_network: 10.0.1.0/24 | cacheservers:6379/tcp | network:connect | permit |
| rule-006 | source_network: 0.0.0.0/0 | cacheservers:6379/tcp | network:connect | deny |

### SSH Access Rules
| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-001 | groups: sudo | web01.lab.local (dmz) | ssh:login | permit |

### Filesystem Access Rules
| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-007 | groups: www-data | /var/www/html (0750) | filesystem:read | permit |
| rule-008 | groups: www-data | /var/www/html (0750) | filesystem:write | permit |
| rule-009 | groups: postgres | /var/lib/postgresql/data (0700) | filesystem:read | permit |
| rule-010 | groups: postgres | /var/lib/postgresql/data (0700) | filesystem:write | permit |

### Sudo Rules
| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-011 | groups: www-data | web01.lab.local | sudo:execute | deny |

### Default Deny
| Rule | Subject | Resource | Action | Effect |
|------|---------|----------|--------|--------|
| rule-012 | all | all | * | deny |

## Vulnerability Assessment
28 vulnerabilities identified across 4 pinned packages:

### nginx (1.20.0-1~focal)
- 5 critical/remote CVEs (CVE-2021-46461, CVE-2016-0746, CVE-2017-20005, CVE-2009-3555, CVE-2021-23017)
- 1 KEV: CVE-2023-44487 (HTTP/2 Rapid Reset, CVSS 7.5)
- CVE-2009-3555 is both critical/remote and KEV

### openssh (1:9.6p1-3ubuntu1)
- 5 critical/remote CVEs (all CVSS 10.0, legacy vulnerabilities)
- 5 KEV: CVE-2023-38408 (CVSS 9.8), CVE-2024-6387 (regreSSHion, CVSS 8.1), CVE-2007-4752, CVE-2019-6109, CVE-2019-6110

### postgresql (16.2-1.pgdg22.04+1)
- 5 critical/remote CVEs (CVE-2002-1399, CVE-2013-1902, CVE-2007-3279, CVE-2013-1903, CVE-2024-1597)
- 2 KEV: CVE-2019-9193 (CVSS 7.2), CVE-2022-31197 (CVSS 7.1)
- CVE-2024-1597 is both critical/remote and KEV

### redis (7.0.11-1)
- 5 critical/remote CVEs (CVE-2015-4335, CVE-2022-0543, CVE-2025-49844, CVE-2016-8339, CVE-2023-31654)
- 2 KEV: CVE-2022-0543 (Lua sandbox escape, CVSS 10.0), CVE-2025-49844 (CVSS 9.9)

## Obligations
- **Session logging**: All SSH access (rule-001) requires session logging per SOC2 compliance requirements.

## Ambiguities and Notes
1. **No explicit sudoers rules**: The configuration only denies sudo for www-data. No explicit sudo rules exist for admin or developer users.
2. **No database user authentication rules**: The Ansible config sets up pg_hba.conf for network access but does not define database-level user privileges (SUPERUSER/NOSUPERUSER, ALL/SELECT).
3. **No explicit nginx or redis ACL rules beyond network**: Application-level access controls for nginx (HTTP auth) and redis (AUTH command) are not configured in Ansible.
4. **Service accounts created without clearance/department**: www-data, postgres, and redis are created as system accounts without clearance levels or departments defined.
5. **Redis bind address**: Redis is bound to 10.0.2.20 (internal only) which provides defense-in-depth, but this is a resource configuration rather than a subject-based rule.
6. **Package versions**: The pinned versions may be vulnerable to the CVEs listed above. Version compatibility assessment is recommended.
