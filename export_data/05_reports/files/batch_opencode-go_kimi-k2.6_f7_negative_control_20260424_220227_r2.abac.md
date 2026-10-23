# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 22:30:07_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 12 | Rules: 17_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

## Attributes

```json
{
  "subjects": {
    "user": {
      "domain": [
        "admin",
        "appuser",
        "postgres"
      ],
      "source": "group_vars/all.yml,roles/db/tasks/main.yml"
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "postgres"
      ],
      "source": "group_vars/all.yml,roles/db/tasks/main.yml"
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
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "domain": [
        "10.0.1.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/dbservers.yml,group_vars/webservers.yml"
    },
    "source_zone": {
      "domain": [
        "dmz",
        "internet"
      ],
      "source": "inventory.ini,group_vars/dbservers.yml,group_vars/webservers.yml"
    }
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
        "name": "ssh",
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
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "webservers subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet",
        "source": "group_vars/webservers.yml"
      }
    ],
    "host_group": {
      "domain": [
        "webservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "domain": [
        "nginx",
        "postgresql",
        "ssh"
      ],
      "source": "group_vars/webservers.yml,group_vars/dbservers.yml,roles/web/tasks/main.yml"
    },
    "port": {
      "domain": [
        443,
        5432,
        22
      ],
      "source": "group_vars/webservers.yml,group_vars/dbservers.yml,roles/web/tasks/main.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "group_vars/webservers.yml,group_vars/dbservers.yml"
    },
    "path": {
      "domain": [
        "/var/lib/postgresql/data"
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
    "database_privilege": {
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    }
  },
  "environment": {
    "org": {
      "domain": [
        "labcorp"
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
        "soc2"
      ],
      "source": "group_vars/all.yml"
    },
    "default_log_retention_days": {
      "value": 90,
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-15"
    }
  },
  {
    "id": "rule-002",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-15"
    }
  },
  {
    "id": "rule-003",
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
      "environment": {
        "equals": "production"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": "8-15"
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
      "service": {
        "equals": "postgresql"
      },
      "database_privilege": {
        "equals": "SUPERUSER"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "16-22"
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
      },
      "database_privilege": {
        "equals": "NOSUPERUSER"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "23-29"
    }
  },
  {
    "id": "rule-006",
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
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
    "id": "rule-007",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
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
      }
    },
    "action": "user:create",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "13-21"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      },
      "clearance": {
        "equals": "secret"
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
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "nopassword": false,
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "22-30"
    }
  },
  {
    "id": "rule-010",
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
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "31-38"
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
      "service": {
        "equals": "ssh"
      },
      "port": {
        "equals": 22
      },
      "protocol": {
        "equals": "tcp"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
    "id": "rule-012",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
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
      }
    },
    "action": "ssh:login",
    "effect": "deny",
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "39-43"
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
      "environment": {
        "equals": "production"
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
      "environment": {
        "equals": "production"
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
      "environment": {
        "equals": "production"
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
      "service": {
        "equals": "nginx"
      },
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
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
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cve_id": "CVE-2021-46461",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cve_id": "CVE-2017-20005",
    "severity": "critical",
    "cvss_score": 9.8,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cve_id": "CVE-2021-23017",
    "severity": "high",
    "cvss_score": 7.7,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "nginx",
    "pinned_version": "1.27.0-1~noble",
    "cve_id": "CVE-2016-0742",
    "severity": "high",
    "cvss_score": 7.5,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "cve_id": "CVE-2000-0999",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "cve_id": "CVE-2001-0144",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "cve_id": "CVE-2000-0525",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "cve_id": "CVE-2003-0693",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "openssh",
    "pinned_version": "1:9.9p1-3ubuntu1",
    "cve_id": "CVE-2003-0786",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cve_id": "CVE-2007-3279",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cve_id": "CVE-2002-1399",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cve_id": "CVE-2024-1597",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cve_id": "CVE-2013-1902",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  },
  {
    "product": "postgresql",
    "pinned_version": "16.4-1.pgdg24.04+1",
    "cve_id": "CVE-2013-1903",
    "severity": "critical",
    "cvss_score": 10,
    "affects_pinned_version": false,
    "recommendation": "No action required; pinned version appears current and patched."
  }
]
```

## Report

# ABAC Policy Mining Report

## 1. Executive Summary
Ansible repository for **labcorp** (production environment, SOC-2 compliance tier) contains two security-relevant role task files. The mined policy covers filesystem ACLs, database authentication, network policies, identity provisioning, sudo access, and SSH access controls. No dedicated firewall, SELinux, or sudoers template files exist in the repository; access controls are embedded in the web and database role tasks.

## 2. Attribute Catalog
### Subjects
- **users**: admin (sudo, operations, secret), appuser (developers, engineering, confidential), postgres (postgres group)
- **groups**: sudo, developers, postgres
- **clearance**: secret, confidential
- **department**: operations, engineering
- **source_network / source_zone**: Used for network-layer rules (10.0.1.0/24 / dmz, 0.0.0.0/0 / internet)

### Resources
- **hosts**: web01.lab.local (frontend, dmz), db01.lab.local (primary, internal)
- **services**: nginx (443/tcp, webservers), postgresql (5432/tcp, dbservers), ssh (22/tcp, webservers)
- **paths**: /var/lib/postgresql/data (owner postgres, group postgres, mode 0700)
- **networks**: 10.0.1.0/24 (webservers subnet), 0.0.0.0/0 (internet)
- **host_group**: webservers, dbservers
- **database_privilege**: SUPERUSER, NOSUPERUSER

### Environment
- **org**: labcorp
- **environment**: production
- **compliance_tier**: soc2
- **default_log_retention_days**: 90

## 3. Extracted Rules (13 total)
| ID | Action | Effect | Subject Condition | Resource Condition | Source File |
|---|---|---|---|---|---|
| rule-001 | filesystem:read | permit | user = postgres | path = /var/lib/postgresql/data, owner = postgres, group = postgres, mode = 0700 | roles/db/tasks/main.yml |
| rule-002 | filesystem:write | permit | user = postgres | path = /var/lib/postgresql/data, owner = postgres, group = postgres, mode = 0700 | roles/db/tasks/main.yml |
| rule-003 | filesystem:execute | permit | user = postgres | path = /var/lib/postgresql/data, owner = postgres, group = postgres, mode = 0700 | roles/db/tasks/main.yml |
| rule-004 | db:login | permit | groups any_of [sudo] | service = postgresql, database_privilege = SUPERUSER | roles/db/tasks/main.yml |
| rule-005 | db:login | permit | groups any_of [developers] | service = postgresql, database_privilege = NOSUPERUSER | roles/db/tasks/main.yml |
| rule-006 | network:connect | permit | source_network = 10.0.1.0/24 | service = postgresql, port = 5432, protocol = tcp | roles/db/tasks/main.yml |
| rule-007 | network:connect | deny | applies_to = all | service = postgresql | roles/db/tasks/main.yml |
| rule-008 | user:create | permit | groups any_of [sudo] | applies_to = all | roles/web/tasks/main.yml |
| rule-009 | sudo:execute | permit | groups any_of [sudo], clearance = secret | applies_to = all | roles/web/tasks/main.yml |
| rule-010 | network:connect | permit | source_network = 0.0.0.0/0 | service = nginx, port = 443, protocol = tcp | roles/web/tasks/main.yml |
| rule-011 | ssh:login | permit | groups any_of [sudo] | service = ssh, port = 22, protocol = tcp | roles/web/tasks/main.yml |
| rule-012 | ssh:login | deny | applies_to = all | service = ssh | roles/web/tasks/main.yml |
| rule-013 | * | deny | applies_to = all | applies_to = all | default-deny |

## 4. Vulnerability Assessment
Three pinned packages were evaluated:
- **nginx 1.27.0-1~noble**: 5 critical/high remote CVEs + 1 KEV found; none affect the pinned version.
- **openssh 1:9.9p1-3ubuntu1**: 5 critical remote CVEs + 1 KEV found; none affect the pinned version.
- **postgresql 16.4-1.pgdg24.04+1**: 5 critical remote CVEs + 1 KEV found; none affect the pinned version.

All CVEs predate the pinned versions or were specifically matched by CPE-based search and confirmed not applicable.

## 5. Ambiguities
- **Credentials**: No explicit secrets management (Vault, encrypted vars) observed in the scanned files; credential storage method is ambiguous.
- **No dedicated security templates**: No `sshd_config.j2`, `sudoers.j2`, `iptables.yml`, or SELinux policy files exist. Access controls are inline tasks, which may be incomplete or host-conditional logic hidden in Jinja2 templating not fully expanded.
- **PostgreSQL read-only privileges**: The role `LOGIN,NOSUPERUSER` does not strictly imply read-only; the playbook omits explicit `GRANT SELECT` or `REVOKE` statements, leaving actual data access ambiguous.
- **Session logging / audit**: No audit scripts or profile.d logging configurations were found; therefore no obligations could be attached.

## 6. Recommendations
1. Expand `pg_hba.conf` management into a dedicated template to capture implicit deny scopes and reduce ambiguity.
2. Introduce Ansible Vault or an external secrets manager to eliminate plaintext credential risk.
3. Add explicit `postgresql_privs` tasks to clarify read-only vs. read-write database access.
4. Consider dedicated `roles/security/` templates for sshd, sudoers, and firewall rules to improve auditability.
5. Continue monitoring the three pinned packages; although current CVEs do not affect these versions, new disclosures should be evaluated promptly.
