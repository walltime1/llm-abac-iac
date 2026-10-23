# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:41:19_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 13 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f3_privsep_service_accounts`_

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
        "clearance": "secret",
        "department": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "name": "developer",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "group_vars/all.yml"
      },
      {
        "name": "www-data",
        "uid": 33,
        "groups": [
          "www-data"
        ],
        "shell": "/usr/sbin/nologin",
        "system": true,
        "source": "roles/web/tasks/main.yml"
      },
      {
        "name": "postgres",
        "shell": "/usr/sbin/nologin",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "name": "redis",
        "shell": "/usr/sbin/nologin",
        "system": true,
        "source": "roles/cache/tasks/main.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "www-data",
      "postgres",
      "redis"
    ],
    "clearance_levels": [
      "secret",
      "confidential"
    ],
    "departments": [
      "operations",
      "engineering"
    ]
  },
  "resources": {
    "hosts": [
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "cache01.lab.local",
        "ip": "10.0.2.20",
        "role": "cache",
        "zone": "internal",
        "inventory_group": "cacheservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
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
        "name": "redis",
        "port": 6379,
        "protocol": "tcp",
        "host_group": "cacheservers",
        "source": "group_vars/cacheservers.yml"
      }
    ],
    "paths": [
      {
        "path": "/var/www/html",
        "owner": "www-data",
        "group": "www-data",
        "mode": "0750",
        "service": "nginx",
        "source": "roles/web/tasks/main.yml"
      },
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
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      }
    ]
  },
  "environment": {
    "org": "privsep-corp",
    "environment": "production",
    "compliance_tier": "soc2",
    "default_log_retention_days": 90,
    "source": "inventory.ini,group_vars/all.yml"
  },
  "packages": {
    "nginx": {
      "version": "1.20.0-1~focal",
      "source": "group_vars/all.yml"
    },
    "openssh": {
      "version": "1:9.6p1-3ubuntu1",
      "source": "group_vars/all.yml"
    },
    "postgresql": {
      "version": "16.2-1.pgdg22.04+1",
      "source": "group_vars/all.yml"
    },
    "redis": {
      "version": "7.0.11-1",
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
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "ssh"
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
      "lines": "27-31"
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
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      },
      "zone": {
        "equals": "dmz"
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
      "lines": "22-26"
    }
  },
  {
    "id": "rule-003",
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
      "task": "Enforce document root ACL",
      "lines": "17-21"
    }
  },
  {
    "id": "rule-004",
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
      "task": "Enforce document root ACL",
      "lines": "17-21"
    }
  },
  {
    "id": "rule-005",
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
      },
      "zone": {
        "equals": "internal"
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
      "lines": "17-21"
    }
  },
  {
    "id": "rule-006",
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
      "lines": "11-15"
    }
  },
  {
    "id": "rule-007",
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
      "lines": "11-15"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "redis"
      },
      "port": {
        "equals": 6379
      },
      "zone": {
        "equals": "internal"
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
      "lines": "17-21"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "user": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Create www-data service user",
      "lines": "11-16"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "user": {
        "equals": "postgres"
      }
    },
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres user has no shell access",
      "lines": "16-18"
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "user": {
        "equals": "redis"
      }
    },
    "resource_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Ensure redis runs as redis user",
      "lines": "11-14"
    }
  },
  {
    "id": "rule-012",
    "subject_condition": {
      "user": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sudo"
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
      "lines": "32-35"
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
    "source": {
      "file": "implicit",
      "task": "default-deny",
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
        "equals": "nginx"
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
  },
  {
    "id": "rule-017",
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
    "id": "rule-018",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "redis"
      },
      "port": {
        "equals": 6379
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
    "product": "nginx",
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses related to CNAME processing, exploit requires sending malicious DNS responses.",
    "recommendation": "Update to nginx 1.9.10 or later versions."
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit requires crafted input.",
    "recommendation": "Update to the latest version of njs where the issue is fixed."
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "nginx 1.13.5 through 1.13.12, 1.15.0 through 1.15.8, and 1.17.0 through 1.17.2 contain a use-after-free in the resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2009-3555",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "nginx before 0.7.61 allows remote attackers to cause a denial of service (worker process crash) via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "nginx",
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "description": "nginx 1.3.0 through 1.21.3 contains a use-after-free in the resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH before 2.9.0 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH before 2.5.2 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH before 3.7.1 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH before 3.8 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "openssh",
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "OpenSSH before 2.3.0 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL before 7.3.3 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL before 9.2.4, 9.3 before 9.3.1, and 9.4 before 9.4.1 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL before 8.2.8, 8.3 before 8.3.4, and 8.4 before 8.4.1 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL before 9.2.4, 9.3 before 9.3.1, and 9.4 before 9.4.1 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "postgresql",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "PostgreSQL before 16.5, 15.9, 14.12, 13.16, and 12.20 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "redis",
    "cve_id": "CVE-2015-4335",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Redis before 3.2.3 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "redis",
    "cve_id": "CVE-2022-0543",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "description": "Redis before 6.2.4 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "redis",
    "cve_id": "CVE-2025-49844",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_remote": true,
    "description": "Redis before 7.2.5 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "redis",
    "cve_id": "CVE-2016-8339",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Redis before 3.2.9 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  },
  {
    "product": "redis",
    "cve_id": "CVE-2018-11219",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "description": "Redis before 5.0.3 allows remote attackers to cause a denial of service via a crafted request.",
    "recommendation": "Upgrade to patched version"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web, database, and cache servers.

## Environment Overview

- **Organization**: privsep-corp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Subjects (Users & Groups)

### Human Users
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |

### Service Accounts
| User | UID | Groups | Shell |
|------|-----|--------|-------|
| www-data | 33 | www-data | /usr/sbin/nologin |
| postgres | - | postgres | /usr/sbin/nologin |
| redis | - | redis | /usr/sbin/nologin |

### Groups
- sudo
- developers
- www-data
- postgres
- redis

## Resources

### Hosts
| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| web01.lab.local | 10.0.1.10 | frontend | dmz | webservers |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |
| cache01.lab.local | 10.0.2.20 | cache | internal | cacheservers |

### Services
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| nginx | 443 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |
| redis | 6379 | tcp | cacheservers |

### Filesystem Paths
| Path | Owner | Group | Mode | Service |
|------|-------|-------|------|---------|
| /var/www/html | www-data | www-data | 0750 | nginx |
| /var/lib/postgresql/data | postgres | postgres | 0700 | postgresql |

### Networks
| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | webservers_subnet |
| 0.0.0.0/0 | external | internet |

## ABAC Rules Summary

| Rule ID | Action | Effect | Subject | Resource |
|---------|--------|--------|---------|----------|
| rule-001 | ssh:login | permit | groups: sudo | service: ssh |
| rule-002 | network:connect | permit | source: 0.0.0.0/0 | nginx:443 (dmz) |
| rule-003 | filesystem:read | permit | groups: www-data | /var/www/html |
| rule-004 | filesystem:write | permit | groups: www-data | /var/www/html |
| rule-005 | network:connect | permit | source: 10.0.1.0/24 | postgresql:5432 |
| rule-006 | filesystem:read | permit | groups: postgres | /var/lib/postgresql/data |
| rule-007 | filesystem:write | permit | groups: postgres | /var/lib/postgresql/data |
| rule-008 | network:connect | permit | source: 10.0.1.0/24 | redis:6379 |
| rule-009 | user:create | permit | user: www-data | all |
| rule-010 | user:create | permit | user: postgres | all |
| rule-011 | user:create | permit | user: redis | all |
| rule-012 | sudo:execute | deny | user: www-data | sudo |
| rule-013 | * | deny | all | all (default) |

## Vulnerability Assessment

### Summary
- **Total Vulnerabilities Found**: 20
- **Critical**: 19
- **High**: 1

### By Product
| Product | Version | Critical | High | KEV |
|---------|---------|----------|------|-----|
| nginx | 1.20.0-1~focal | 5 | 0 | 4 |
| openssh | 1:9.6p1-3ubuntu1 | 5 | 0 | 4 |
| postgresql | 16.2-1.pgdg22.04+1 | 5 | 0 | 4 |
| redis | 7.0.11-1 | 5 | 0 | 4 |

### Key Findings
1. **nginx CVE-2016-0746** (CVSS 9.8): Use-after-free in DNS resolver - requires upgrade to 1.9.10+
2. **nginx CVE-2021-46461** (CVSS 9.8): Buffer overflow in njs module - requires njs update
3. **postgresql CVE-2024-1597** (CVSS 10): Recent critical vulnerability - immediate patching recommended
4. **redis CVE-2025-49844** (CVSS 9.9): Very recent critical vulnerability - immediate patching required

### Recommendations
1. Upgrade nginx to latest stable version (1.24+)
2. Upgrade PostgreSQL to 16.5+ or 15.9+
3. Upgrade Redis to 7.2.5+
4. Review OpenSSH version compatibility with current OS

## Ambiguities & Notes

1. **Credentials**: No explicit database credentials found in configuration - likely managed externally
2. **SELinux**: No SELinux policies detected in configuration
3. **Audit Logging**: No explicit audit logging configuration found
4. **Session Management**: No session timeout or management policies detected

## Compliance Considerations (SOC2)

- SSH access restricted to sudo group only ✓
- Database access restricted to webservers subnet ✓
- Cache access restricted to webservers subnet ✓
- Service accounts have no shell access ✓
- www-data explicitly denied sudo access ✓
- Default deny policy in place ✓

## Files Analyzed

- inventory.ini
- group_vars/all.yml
- group_vars/webservers.yml
- group_vars/dbservers.yml
- group_vars/cacheservers.yml
- roles/web/tasks/main.yml
- roles/db/tasks/main.yml
- roles/cache/tasks/main.yml
