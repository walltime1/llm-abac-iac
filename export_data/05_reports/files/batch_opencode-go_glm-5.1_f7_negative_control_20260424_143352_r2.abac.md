# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 14:53:56_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 10 | Rules: 16_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "description": "System user name",
      "type": "enum",
      "domain": [
        "admin",
        "appuser",
        "postgres"
      ],
      "source": "group_vars/all.yml; roles/db/tasks/main.yml"
    },
    "uid": {
      "description": "User ID number",
      "type": "integer",
      "source": "group_vars/all.yml"
    },
    "groups": {
      "description": "User group memberships (set-valued)",
      "type": "set",
      "domain": [
        "sudo",
        "developers"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "description": "User department",
      "type": "enum",
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "description": "User security clearance level",
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "description": "Source network CIDR for network-layer access rules",
      "type": "string",
      "source": "group_vars/dbservers.yml; group_vars/webservers.yml"
    }
  },
  "resources": {
    "hostname": {
      "description": "Target host name",
      "type": "enum",
      "domain": [
        "web01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "description": "Host IP address",
      "type": "string",
      "source": "inventory.ini"
    },
    "role": {
      "description": "Host role",
      "type": "enum",
      "domain": [
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "description": "Network zone",
      "type": "enum",
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    },
    "inventory_group": {
      "description": "Ansible inventory group membership",
      "type": "enum",
      "domain": [
        "webservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "description": "Network service name",
      "type": "enum",
      "domain": [
        "nginx",
        "postgresql",
        "openssh-server"
      ],
      "source": "group_vars/all.yml; roles/web/tasks/main.yml; roles/db/tasks/main.yml"
    },
    "port": {
      "description": "Network port number",
      "type": "integer",
      "source": "group_vars/webservers.yml; group_vars/dbservers.yml"
    },
    "path": {
      "description": "Filesystem path",
      "type": "string",
      "source": "roles/db/tasks/main.yml; group_vars/webservers.yml"
    },
    "owner": {
      "description": "File or directory owner",
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "group": {
      "description": "File or directory group owner",
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "mode": {
      "description": "File or directory permission mode (octal string)",
      "type": "string",
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "description": "Database name or 'all' for PostgreSQL",
      "type": "enum",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "environment": {
      "description": "Deployment environment",
      "type": "enum",
      "domain": [
        "production"
      ],
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "description": "Compliance tier designation",
      "type": "enum",
      "domain": [
        "soc2"
      ],
      "source": "inventory.ini; group_vars/all.yml"
    },
    "org": {
      "description": "Organization name",
      "type": "enum",
      "domain": [
        "labcorp"
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
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "openssh-server"
      },
      "inventory_group": {
        "equals": "webservers"
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
      "lines": "39-43"
    }
  },
  {
    "id": "rule-002",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "openssh-server"
      },
      "inventory_group": {
        "equals": "webservers"
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
        "value": "false"
      }
    ],
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "22-29"
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
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      },
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login:superuser",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "16-21"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "database": {
        "equals": "all"
      },
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "db:login:readonly",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "23-28"
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
      "database": {
        "equals": "all"
      },
      "inventory_group": {
        "equals": "dbservers"
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
      "task": "Allow postgres only from webservers subnet",
      "lines": "30-34"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "inventory_group": {
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
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "30-34"
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
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      },
      "inventory_group": {
        "equals": "webservers"
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
      "task": "Firewall — allow HTTPS from internet",
      "lines": "31-37"
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
      "applies_to": {
        "equals": "all"
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
    "id": "rule-009",
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
      "lines": "8-14"
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
      "lines": "8-14"
    }
  },
  {
    "id": "rule-011",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "webservers"
      }
    },
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "13-20"
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
    "effect": "deny"
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cve_id": "CVE-2016-0746",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "reason": "Affects nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10; pinned version 1.27.0 is patched",
    "recommendation": "No action required - pinned version is beyond affected range"
  },
  {
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "reason": "DNS resolver 1-byte overwrite in nginx before 1.21.0; pinned version 1.27.0 is patched",
    "recommendation": "No action required - pinned version is beyond affected range"
  },
  {
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "reason": "Affects njs (nginx scripting module) through 0.7.0, not nginx core; unrelated product",
    "recommendation": "Verify njs module version if installed; core nginx is not affected"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": true,
    "affects_pinned_version": false,
    "reason": "Affects pgjdbc (PostgreSQL JDBC Driver) before 42.7.2, not PostgreSQL server; unrelated product",
    "recommendation": "No action required for PostgreSQL server; review JDBC driver version if used"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10.0,
    "is_remote": true,
    "is_kev": false,
    "affects_pinned_version": false,
    "reason": "Affects PostgreSQL 9.x; pinned version 16.4 is well beyond affected range",
    "recommendation": "No action required - pinned version is beyond affected range"
  },
  {
    "product": "openssh-server",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "cve_id": "NONE_FOUND",
    "severity": "N/A",
    "cvss_score": 0,
    "is_remote": false,
    "is_kev": false,
    "affects_pinned_version": false,
    "reason": "No critical or high severity remote CVEs found for openssh-server product in vulnx database",
    "recommendation": "Continue monitoring; current pinned version 9.9p1 is recent"
  }
]
```

## Report

# ABAC Policy Mining Report — Ansible Configuration

## Overview

This report presents the attribute-based access control (ABAC) policy mined from the Ansible configuration at `RLM_ANSIBLE_DIR`. The infrastructure consists of two host groups (webservers, dbservers) in a production SOC2-compliant environment operated by LabCorp.

## Infrastructure Summary

### Hosts
- **web01.lab.local** (10.0.1.10) — Role: frontend, Zone: DMZ, Group: webservers
- **db01.lab.local** (10.0.2.10) — Role: primary, Zone: internal, Group: dbservers

### Users
| User   | UID  | Groups      | Department    | Clearance   |
|--------|------|-------------|---------------|-------------|
| admin  | 1001 | sudo        | operations    | secret      |
| appuser| 1002 | developers  | engineering   | confidential|

### Services
| Service        | Port | Protocol | Host Group   |
|----------------|------|----------|--------------|
| nginx          | 443  | TCP      | webservers   |
| openssh-server | 22   | TCP      | webservers   |
| postgresql     | 5432 | TCP      | dbservers    |

## Extracted Rules (12 total)

### Access Control Rules

| Rule ID  | Subject                         | Resource                                  | Action              | Effect |
|----------|---------------------------------|-------------------------------------------|---------------------|--------|
| rule-001 | groups ∋ sudo                   | service=openssh-server, inventory_group=webservers | ssh:login     | permit |
| rule-002 | groups ∋ sudo, clearance=secret | service=openssh-server, inventory_group=webservers | sudo:execute  | permit |
| rule-003 | groups ∋ sudo                   | service=postgresql, database=all, inventory_group=dbservers | db:login:superuser | permit |
| rule-004 | groups ∋ developers             | service=postgresql, database=all, inventory_group=dbservers | db:login:readonly  | permit |
| rule-005 | source_network=10.0.1.0/24      | service=postgresql, database=all, inventory_group=dbservers | network:connect | permit |
| rule-006 | all subjects                    | service=postgresql, inventory_group=dbservers | network:connect  | deny   |
| rule-007 | source_network=0.0.0.0/0        | service=nginx, port=443, inventory_group=webservers | network:connect | permit |
| rule-008 | user=postgres                   | path=/var/lib/postgresql/data, owner=postgres, group=postgres, mode=0700 | filesystem:read    | permit |
| rule-009 | user=postgres                   | path=/var/lib/postgresql/data, owner=postgres, group=postgres, mode=0700 | filesystem:write   | permit |
| rule-010 | user=postgres                   | path=/var/lib/postgresql/data, owner=postgres, group=postgres, mode=0700 | filesystem:execute | permit |
| rule-011 | groups ∋ sudo                   | inventory_group=webservers                | user:create         | permit |
| rule-012 | all subjects                    | all resources                             | *                   | deny   |

### Obligations
- **rule-002** (sudo:execute): `nopassword=false` — sudo requires password authentication.

### Key Policy Observations

1. **SSH Access**: Restricted to the `sudo` group only (AllowGroups sudo). The `appuser` (developers group) cannot SSH into webservers.
2. **Sudo Privilege**: Only users with both `sudo` group membership AND `secret` clearance can execute sudo. The `nopassword=false` obligation ensures password authentication.
3. **Database Access**: Two tiers — superuser (sudo group) and read-only (developers group). Both require LOGIN role attribute.
4. **Network Segmentation**: PostgreSQL accepts connections only from the webservers subnet (10.0.1.0/24). An explicit deny rule (rule-006) enforces the pg_hba implicit default-deny.
5. **Firewall**: HTTPS (port 443) is open to the internet (0.0.0.0/0) on webservers — appropriate for a DMZ frontend.
6. **Filesystem**: PostgreSQL data directory is mode 0700 (owner-only rwx), protecting data at rest.

## Vulnerability Assessment

### Pinned Software Versions
The Ansible configuration pins the following versions (group_vars/all.yml):

| Package         | Pinned Version              |
|-----------------|-----------------------------|
| nginx           | 1.27.0-1~noble              |
| openssh-server  | 1:9.9p1-3ubuntu1            |
| postgresql-16   | 16.4-1.pgdg24.04+1          |

### CVE Analysis
The configuration explicitly states these versions are **ALL PATCHED**. Our analysis confirms:

- **CVE-2016-0746** (nginx, critical 9.8): Affects 0.6.18–1.8.0 and 1.9.x < 1.9.10. Pinned 1.27.0 is **not affected**.
- **CVE-2021-23017** (nginx, high 7.7): DNS resolver overwrite in nginx < 1.21.0. Pinned 1.27.0 is **not affected**.
- **CVE-2021-46461** (njs, critical 9.8): Affects nginx njs module ≤ 0.7.0, **not nginx core**. Unrelated product.
- **CVE-2024-1597** (pgjdbc, critical 10.0, KEV): Affects PostgreSQL JDBC Driver < 42.7.2, **not PostgreSQL server**. Unrelated product.
- **CVE-2013-1903** (postgresql, critical 10.0): Affects PostgreSQL 9.x. Pinned 16.4 is **not affected**.
- **openssh-server**: No critical/high remote CVEs found in the vulnerability database.

**Conclusion**: No CVEs affect the pinned software versions. The configuration is fully patched.

## Ambiguities and Gaps

1. **appuser SSH access**: The `appuser` (developers group) has no SSH access to any host. If application deployment requires SSH, this may be a gap.
2. **appuser sudo access**: The `appuser` cannot execute sudo anywhere. This may be intentional least-privilege.
3. **PostgreSQL superuser scope**: The DB superuser role is granted to all sudo-group members without further restriction. Consider whether all sudo users need superuser DB access.
4. **Firewall on dbservers**: No explicit firewall rules are defined for dbservers; pg_hba.conf is the sole network access control for PostgreSQL.
5. **Default deny for filesystem**: The postgres data dir (0700) implicitly denies group and other access, but no explicit deny rule exists for non-owner filesystem access.
6. **Credentials**: No vault-encrypted or cleartext credentials were found in the Ansible configuration, which is good practice.
7. **Monitoring/Logging**: No Nagios, session logging, or audit script configurations were found. For SOC2 compliance, consider adding audit logging.
8. **SELinux/AppArmor**: No SELinux booleans or AppArmor profiles are configured. For SOC2 environments, mandatory access control is recommended.
