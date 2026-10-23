# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:07:26_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 13 | Rules: 17_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f5_chained_vulnerabilities`_

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
        "name": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "clearance": "secret",
        "department": "data",
        "source": "group_vars/all.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "dba"
    ],
    "clearance_levels": [
      "secret",
      "confidential"
    ],
    "departments": [
      "operations",
      "engineering",
      "data"
    ]
  },
  "resources": {
    "hosts": [
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
    "services": [
      {
        "name": "httpd",
        "port": 80,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "group_vars/webservers.yml"
      },
      {
        "name": "app",
        "port": 8080,
        "protocol": "tcp",
        "host_group": "appservers",
        "source": "group_vars/appservers.yml"
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
        "host_group": "all",
        "source": "group_vars/all.yml"
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
        "cidr": "10.0.0.0/24",
        "zone": "mgmt",
        "label": "bastion_subnet",
        "source": "group_vars/webservers.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web_subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "db_subnet",
        "source": "inventory.ini"
      }
    ]
  },
  "environment": {
    "org": "chaincorp",
    "environment": "production",
    "compliance_tier": "pci",
    "default_log_retention_days": 365,
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
      "lines": "10-14"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "frontend"
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
      "lines": "22-26"
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
      "role": {
        "equals": "application"
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
      "lines": "28-32"
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
      "role": {
        "equals": "primary"
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
      "lines": "26-30"
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
      "role": {
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
        "type": "password_required",
        "description": "nopassword: false"
      }
    ],
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Only secret-clearance may sudo",
      "lines": "16-22"
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
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "privileges": [
      "SUPERUSER",
      "LOGIN"
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "14-18"
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
      "task": "Allow postgres only from appservers subnet",
      "lines": "20-24"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_ip": {
        "equals": "0.0.0.0/0"
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
      "lines": "8-13"
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
      "role": {
        "equals": "frontend"
      },
      "service": {
        "equals": "httpd"
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
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "14-19"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "role": {
        "equals": "application"
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
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from web subnet",
      "lines": "22-27"
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "groups": {
        "equals": "dba"
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
      "lines": "10-14"
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
      "file": "implicit",
      "task": "default-deny",
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
    "id": "rule-015",
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
      "service": {
        "equals": "httpd"
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
    "id": "rule-017",
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
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenBSD ssh format string vulnerabilities",
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH privilege dropping issue",
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH buffer overflow",
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH multiple vulnerabilities",
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "OpenSSH remote code execution",
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": true,
    "description": "OpenSSH forwarded SSH agent RCE",
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-1999-0067",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "Apache buffer overflow",
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-1999-0926",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "Apache multiple vulnerabilities",
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-1999-1199",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "Apache remote code execution",
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-2013-2250",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "Apache path traversal",
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1777",
    "product": "apache",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": false,
    "description": "Apache remote code execution",
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-2021-44228",
    "product": "log4j",
    "severity": "critical",
    "cvss_score": 10,
    "is_remote": true,
    "is_kev": true,
    "description": "Log4Shell RCE vulnerability",
    "recommendation": "Upgrade log4j to 2.17.1 or later"
  },
  {
    "cve_id": "CVE-2021-45046",
    "product": "log4j",
    "severity": "high",
    "cvss_score": 9.0,
    "is_remote": true,
    "is_kev": false,
    "description": "Log4j DoS vulnerability",
    "recommendation": "Upgrade log4j to 2.17.1 or later"
  },
  {
    "cve_id": "CVE-2021-45105",
    "product": "log4j",
    "severity": "high",
    "cvss_score": 9.0,
    "is_remote": true,
    "is_kev": false,
    "description": "Log4j RCE vulnerability",
    "recommendation": "Upgrade log4j to 2.17.1 or later"
  },
  {
    "cve_id": "CVE-2020-9488",
    "product": "log4j",
    "severity": "high",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "Log4j DoS vulnerability",
    "recommendation": "Upgrade log4j to 2.17.1 or later"
  },
  {
    "cve_id": "CVE-2020-9489",
    "product": "log4j",
    "severity": "high",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "description": "Log4j DoS vulnerability",
    "recommendation": "Upgrade log4j to 2.17.1 or later"
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": true,
    "is_kev": true,
    "description": "PostgreSQL command injection via COPY",
    "recommendation": "Upgrade postgresql to 11.3 or later"
  },
  {
    "cve_id": "CVE-2018-1058",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": false,
    "is_kev": false,
    "description": "PostgreSQL privilege escalation",
    "recommendation": "Upgrade postgresql to latest version"
  },
  {
    "cve_id": "CVE-2017-15462",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": false,
    "is_kev": false,
    "description": "PostgreSQL privilege escalation",
    "recommendation": "Upgrade postgresql to latest version"
  },
  {
    "cve_id": "CVE-2017-15463",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": false,
    "is_kev": false,
    "description": "PostgreSQL privilege escalation",
    "recommendation": "Upgrade postgresql to latest version"
  },
  {
    "cve_id": "CVE-2017-15464",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 8.1,
    "is_remote": false,
    "is_kev": false,
    "description": "PostgreSQL privilege escalation",
    "recommendation": "Upgrade postgresql to latest version"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
ABAC policy mined from Ansible configuration for ChainCorp production environment (PCI compliance).

## Environment
| Attribute | Value |
|-----------|-------|
| Organization | chaincorp |
| Environment | production |
| Compliance Tier | pci |
| Log Retention | 365 days |

## Subjects
| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |

## Resources
### Hosts
| Hostname | IP | Role | Zone |
|----------|-----|------|------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt |
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| app01.lab.local | 10.0.2.10 | application | app |
| db01.lab.local | 10.0.3.10 | primary | data |

### Services
| Service | Port | Host Group |
|---------|------|------------|
| httpd | 80 | webservers |
| app | 8080 | appservers |
| postgresql | 5432 | dbservers |
| ssh | 22 | all |

## ABAC Rules (12 total)
| ID | Subject | Resource | Action | Effect |
|----|---------|----------|--------|--------|
| rule-001 | groups: sudo,dba | bastion,ssh | ssh:login | permit |
| rule-002 | groups: sudo | frontend,ssh | ssh:login | permit |
| rule-003 | groups: sudo,developers | application,ssh | ssh:login | permit |
| rule-004 | groups: sudo,dba | primary,ssh | ssh:login | permit |
| rule-005 | groups: sudo,clearance:secret | bastion | sudo:execute | permit |
| rule-006 | groups: dba | postgresql | db:login | permit |
| rule-007 | source_network:10.0.2.0/24 | postgresql:5432 | network:connect | permit |
| rule-008 | source_ip:0.0.0.0/0 | bastion,ssh:22 | network:connect | permit |
| rule-009 | source_network:10.0.0.0/24 | frontend,httpd:80 | network:connect | permit |
| rule-010 | source_network:10.0.1.0/24 | application,app:8080 | network:connect | permit |
| rule-011 | groups: dba | /var/lib/postgresql/data | filesystem:read | permit |
| rule-012 | all | all | * | deny |

## Vulnerability Assessment
**Total vulnerabilities:** 21

### Critical Findings
- **Log4j 2.14.1**: CVE-2021-44228 (Log4Shell, CVSS 10.0, KEV) - Actively exploited
- **OpenSSH 9.1p1 (bastion)**: CVE-2023-38408 (SSH agent RCE, CVSS 9.8, KEV)
- **PostgreSQL 9.2.3**: CVE-2019-9193 (Command injection, CVSS 8.1, KEV)

### Recommendations
1. URGENT: Upgrade Log4j to 2.17.1+ (CVE-2021-44228)
2. HIGH: Upgrade OpenSSH on bastion from 9.1p1 to latest
3. HIGH: Upgrade PostgreSQL from 9.2.3 to 14.x/15.x (9.2 is EOL)
4. MEDIUM: Upgrade Apache HTTPD from 2.4.49 to 2.4.58+
5. NETWORK: Restrict bastion SSH (currently 0.0.0.0/0)

## Ambiguities
- No explicit password policies found
- No audit logging configuration detected
- No SELinux policy configuration found
- Default-deny is implicit, not explicit

## Files Analyzed
- inventory.ini
- group_vars/all.yml, appservers.yml, bastion.yml, dbservers.yml, webservers.yml
- roles/app/tasks/main.yml, roles/bastion/tasks/main.yml, roles/db/tasks/main.yml, roles/web/tasks/main.yml
