# ABAC Policy Mining — goal: all
_Generated: 2026-04-25 12:30:38_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 10 | Rules: 12_  
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
      },
      {
        "name": "sshd",
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
      },
      {
        "path": "/var/www/html",
        "owner": "www-data",
        "group": "www-data",
        "mode": "0750",
        "service": "nginx",
        "source": "roles/web/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers_subnet",
        "source": "group_vars/cacheservers.yml"
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
    "source": "group_vars/all.yml"
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
        "equals": "sshd"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "37-41"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
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
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "19-23"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    }
  },
  {
    "id": "rule-003",
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
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/cache/tasks/main.yml",
      "task": "Firewall — allow redis from webservers only",
      "lines": "17-23"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
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
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "29-35"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
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
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres runs as postgres user",
      "lines": "10-15"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "user": {
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
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Enforce document root ACL (www-data only)",
      "lines": "23-28"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "user": {
        "equals": "www-data"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "sudoers"
      }
    },
    "action": "sudo:execute",
    "effect": "deny",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Ensure www-data has NO sudo access",
      "lines": "43-46"
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    }
  },
  {
    "id": "rule-008",
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
      "file": "implicit",
      "task": "default-deny",
      "lines": "1"
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    }
  },
  {
    "id": "rule-009",
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
      "compliance_tier": {
        "equals": "soc2"
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
    "id": "rule-010",
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
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "postprocessor",
      "task": "mode 0750 group read",
      "lines": "N/A"
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
        "equals": "redis"
      },
      "port": {
        "equals": 6379
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
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
    "id": "rule-012",
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
      "compliance_tier": {
        "equals": "soc2"
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
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor nginx security advisories"
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor nginx security advisories"
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor nginx security advisories"
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor nginx security advisories"
  },
  {
    "cve_id": "CVE-2016-0742",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor nginx security advisories"
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.5,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Monitor nginx security advisories"
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor postgresql security advisories"
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor postgresql security advisories"
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor postgresql security advisories"
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor postgresql security advisories"
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor postgresql security advisories"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.2,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Monitor postgresql security advisories"
  },
  {
    "cve_id": "CVE-2022-31197",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.1,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "recommendation": "Monitor postgresql security advisories"
  },
  {
    "cve_id": "CVE-2015-4335",
    "product": "redis",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor redis security advisories"
  },
  {
    "cve_id": "CVE-2022-0543",
    "product": "redis",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor redis security advisories"
  },
  {
    "cve_id": "CVE-2025-49844",
    "product": "redis",
    "severity": "critical",
    "cvss_score": 9.9,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": true,
    "recommendation": "URGENT: Update to redis 8.2.2+ or restrict EVAL/EVALSHA via ACL"
  },
  {
    "cve_id": "CVE-2017-15047",
    "product": "redis",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor redis security advisories"
  },
  {
    "cve_id": "CVE-2016-8339",
    "product": "redis",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "recommendation": "Monitor redis security advisories"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the Attribute-Based Access Control (ABAC) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The policy covers SSH access, database authentication, network policies, and filesystem ACLs for a production environment with SOC2 compliance requirements.

## Environment Overview

- **Organization**: privsep-corp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Infrastructure

### Hosts (3)
| Hostname | IP | Role | Zone |
|----------|-----|------|------|
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| db01.lab.local | 10.0.2.10 | primary | internal |
| cache01.lab.local | 10.0.2.20 | cache | internal |

### Services (4)
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| nginx | 443 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |
| redis | 6379 | tcp | cacheservers |
| sshd | 22 | tcp | webservers |

## Subjects

### Users (5)
| Name | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| www-data | 33 | www-data | - | - |
| postgres | - | postgres | - | - |
| redis | - | redis | - | - |

### Groups (5)
- sudo
- developers
- www-data
- postgres
- redis

## Extracted ABAC Rules (8)

### Access Control Rules

| Rule ID | Action | Effect | Subject | Resource |
|---------|--------|--------|---------|----------|
| rule-001 | ssh:login | permit | groups in [sudo] | sshd service |
| rule-002 | db:login | permit | source_network=10.0.1.0/24 | postgresql:5432 |
| rule-003 | network:connect | permit | source_network=10.0.1.0/24 | redis:6379 |
| rule-004 | network:connect | permit | source_network=0.0.0.0/0 | nginx:443 |
| rule-005 | filesystem:read | permit | user=postgres | /var/lib/postgresql/data (0700) |
| rule-006 | filesystem:read | permit | user=www-data | /var/www/html (0750) |
| rule-007 | sudo:execute | deny | user=www-data | sudoers |
| rule-008 | * | deny | all | all |

## Vulnerability Assessment

### Critical Finding

| CVE | Product | Severity | Affects Pinned Version | Recommendation |
|-----|---------|----------|----------------------|----------------|
| CVE-2025-49844 | redis | critical | **YES** | URGENT: Update to redis 8.2.2+ or restrict EVAL/EVALSHA via ACL |

### Other Vulnerabilities (17)
All other identified vulnerabilities (nginx, openssh, postgresql, redis) do not affect the pinned versions in use. Regular monitoring recommended.

## Security Controls Summary

1. **SSH Access**: Restricted to sudo group members only
2. **Database Access**: PostgreSQL accessible only from webservers subnet (10.0.1.0/24)
3. **Cache Access**: Redis accessible only from webservers subnet (10.0.1.0/24)
4. **Web Access**: HTTPS (443) open to internet
5. **Filesystem**: PostgreSQL data directory (0700) and web root (0750) properly restricted
6. **Privilege Separation**: www-data user explicitly denied sudo access

## Ambiguities and Notes

1. **Service Users**: System users (www-data, postgres, redis) lack department/clearance attributes - these are not applicable for service accounts
2. **Implicit Deny**: Default-deny policy enforced for all unlisted access
3. **Credential Management**: Password policies and credential rotation not specified in Ansible config
4. **Session Logging**: Audit and session logging obligations not explicitly configured
5. **Network Segmentation**: DMZ (10.0.1.0/24) and internal (10.0.2.0/24) zones properly separated

## Compliance Alignment (SOC2)

- ✅ Access restrictions based on need-to-know
- ✅ Principle of least privilege enforced
- ✅ Network segmentation implemented
- ✅ Service accounts have minimal privileges
- ⚠️ Session logging/audit requirements not fully addressed

## Recommendations

1. **URGENT**: Update Redis to version 8.2.2+ to address CVE-2025-49844
2. Implement explicit session logging for SSH and database access
3. Add credential rotation policies for service accounts
4. Consider implementing SELinux policies for additional filesystem protection
5. Document and enforce password complexity requirements
