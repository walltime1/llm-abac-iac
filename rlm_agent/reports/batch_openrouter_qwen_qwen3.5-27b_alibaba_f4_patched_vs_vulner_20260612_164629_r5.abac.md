# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 16:53:36_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 10 | Rules: 13_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

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
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "clearance": "confidential",
        "department": "engineering",
        "source": "group_vars/all.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers"
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
        "hostname": "web-new01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_patched",
        "source": "inventory.ini"
      },
      {
        "hostname": "web-old01.lab.local",
        "ip": "10.0.1.20",
        "role": "frontend",
        "zone": "dmz",
        "inventory_group": "webservers_legacy",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "inventory_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "group_vars/webservers_patched.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml"
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
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "external",
        "label": "internet",
        "source": "group_vars/webservers_patched.yml"
      }
    ]
  },
  "environment": {
    "org": "patchcorp",
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
      "role": {
        "equals": "frontend"
      },
      "zone": {
        "equals": "dmz"
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
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "20-24"
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
      "inventory_group": {
        "equals": "webservers_patched"
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "20-24"
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
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      },
      "role": {
        "equals": "frontend"
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
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "14-19"
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
      "port": {
        "equals": 443
      },
      "protocol": {
        "equals": "tcp"
      },
      "inventory_group": {
        "equals": "webservers_patched"
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
      "file": "roles/web_patched/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "14-19"
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": "14-18"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-13"
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
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-13"
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
    "id": "rule-010",
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
    "id": "rule-011",
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
    "id": "rule-012",
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
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS r",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update nginx to latest patched version",
    "cvss_score": 9.8
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "severity": "critical",
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof i",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update nginx to latest patched version",
    "cvss_score": 9.8
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modific",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update nginx to latest patched version",
    "cvss_score": 9.8
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "severity": "critical",
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4,",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update nginx to latest patched version",
    "cvss_score": 9.8
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, lett",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update nginx to latest patched version",
    "cvss_score": 7.7
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerabi",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update postgresql to latest patched version",
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary file",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update postgresql to latest patched version",
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update postgresql to latest patched version",
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update postgresql to latest patched version",
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2024-1597",
    "product": "postgresql",
    "severity": "critical",
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 co",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update postgresql to latest patched version",
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities cau",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update openssh to latest patched version",
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege manag",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update openssh to latest patched version",
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "severity": "critical",
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect mem",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update openssh to latest patched version",
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 P",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update openssh to latest patched version",
    "cvss_score": 10
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calc",
    "vuln_type": "critical_remote",
    "affects_pinned_version": true,
    "recommendation": "Update openssh to latest patched version",
    "cvss_score": 10
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC (Attribute-Based Access Control) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a production environment with web servers (patched and legacy) and database servers.

## Environment Overview

- **Organization**: patchcorp
- **Environment**: production
- **Compliance Tier**: SOC2
- **Log Retention**: 90 days

## Subjects (Users & Groups)

### Users
| Name | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| appuser | 1002 | developers | confidential | engineering |

### Groups
- `sudo` - Administrative access
- `developers` - Application development

## Resources

### Hosts
| Hostname | IP | Role | Zone | Inventory Group |
|----------|-----|------|------|-----------------|
| web-new01.lab.local | 10.0.1.10 | frontend | dmz | webservers_patched |
| web-old01.lab.local | 10.0.1.20 | frontend | dmz | webservers_legacy |
| db01.lab.local | 10.0.2.10 | primary | internal | dbservers |

### Services
| Service | Port | Protocol | Host Group |
|---------|------|----------|------------|
| nginx | 443 | tcp | webservers |
| postgresql | 5432 | tcp | dbservers |

### Filesystem Paths
| Path | Owner | Group | Mode | Service |
|------|-------|-------|------|---------|
| /var/lib/postgresql/data | postgres | postgres | 0700 | postgresql |

### Networks
| CIDR | Zone | Label |
|------|------|-------|
| 10.0.1.0/24 | dmz | web_subnet |
| 0.0.0.0/0 | external | internet |

## Extracted ABAC Rules

### SSH Access Rules
| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-001 | groups: sudo | role: frontend, zone: dmz | ssh:login | permit |
| rule-002 | groups: sudo | inventory_group: webservers_patched | ssh:login | permit |

### Network Access Rules
| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-003 | source_network: 0.0.0.0/0 | port: 443/tcp, role: frontend | network:connect | permit |
| rule-004 | source_network: 0.0.0.0/0 | port: 443/tcp, inventory_group: webservers_patched | network:connect | permit |
| rule-005 | source_network: 10.0.1.0/24 | service: postgresql, port: 5432 | network:connect | permit |

### Filesystem Access Rules
| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-006 | user: postgres | path: /var/lib/postgresql/data | filesystem:read | permit |
| rule-007 | user: postgres | path: /var/lib/postgresql/data | filesystem:write | permit |

### Default Policy
| Rule ID | Subject | Resource | Action | Effect |
|---------|---------|----------|--------|--------|
| rule-008 | all | all | * | deny |

## Vulnerability Assessment

### Summary
- **Total Vulnerabilities Found**: 15
- **Nginx**: 5 vulnerabilities
- **PostgreSQL**: 5 vulnerabilities
- **OpenSSH**: 5 vulnerabilities

### Critical Findings
| CVE ID | Product | Severity | CVSS Score |
|--------|---------|----------|------------|
| CVE-2002-1399 | postgresql | critical | 10.0 |
| CVE-2013-1902 | postgresql | critical | 10.0 |
| CVE-2007-3279 | postgresql | critical | 10.0 |
| CVE-2013-1903 | postgresql | critical | 10.0 |
| CVE-2024-1597 | postgresql | critical | 10.0 |
| CVE-2000-0999 | openssh | critical | 10.0 |
| CVE-2000-0525 | openssh | critical | 10.0 |
| CVE-2003-0693 | openssh | critical | 10.0 |
| CVE-2003-0786 | openssh | critical | 10.0 |
| CVE-2001-0144 | openssh | critical | 10.0 |

### Recommendations
1. **PostgreSQL**: Update to latest patched version to address critical vulnerabilities
2. **OpenSSH**: Review and update SSH server configuration
3. **Nginx**: Legacy version (1.20.0) on web-old01 should be upgraded to patched version (1.24.0)

## Ambiguities and Notes

1. **Credentials**: No explicit credential management found in configuration
2. **Session Logging**: No explicit audit/logging obligations defined
3. **SELinux**: No SELinux policy rules found
4. **Sudoers**: No explicit sudoers configuration found
5. **Package Versions**: Some vulnerabilities may not affect pinned versions - manual verification recommended

## Compliance Considerations

- SOC2 compliance tier requires strict access controls
- Default-deny policy is in place (rule-008)
- SSH access restricted to sudo group only
- Database access limited to web subnet (10.0.1.0/24)
- PostgreSQL data directory has restrictive permissions (0700)

## Files Analyzed

### Phase 1 (Catalog)
- inventory.ini
- group_vars/all.yml
- group_vars/dbservers.yml
- group_vars/webservers_legacy.yml
- group_vars/webservers_patched.yml

### Phase 2 (Rule Extraction)
- roles/db/tasks/main.yml
- roles/web_legacy/tasks/main.yml
- roles/web_patched/tasks/main.yml

---
*Report generated from Ansible configuration mining*
