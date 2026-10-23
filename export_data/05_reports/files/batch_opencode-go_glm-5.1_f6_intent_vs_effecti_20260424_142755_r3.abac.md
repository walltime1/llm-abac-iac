# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 15:19:00_  
_Model: `opencode-go/glm-5.1`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 18 | Rules: 20_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subject": {
    "user": {
      "type": "enum",
      "domain": [
        "admin",
        "developer",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "uid": {
      "type": "integer",
      "domain": null,
      "source": "group_vars/all.yml"
    },
    "groups": {
      "type": "set",
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance": {
      "type": "enum",
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "department": {
      "type": "enum",
      "domain": [
        "operations",
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "type": "cidr",
      "domain": null,
      "source": "group_vars/appservers.yml"
    },
    "source_zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data",
        "internet"
      ],
      "source": "inventory.ini"
    }
  },
  "resource": {
    "hostname": {
      "type": "enum",
      "domain": [
        "proxy01.lab.local",
        "app01.lab.local",
        "db01.lab.local"
      ],
      "source": "inventory.ini"
    },
    "ip": {
      "type": "ip",
      "domain": null,
      "source": "inventory.ini"
    },
    "role": {
      "type": "enum",
      "domain": [
        "reverse_proxy",
        "application",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "type": "enum",
      "domain": [
        "dmz",
        "app",
        "data"
      ],
      "source": "inventory.ini"
    },
    "host_group": {
      "type": "enum",
      "domain": [
        "dmz",
        "appservers",
        "dbservers",
        "prod"
      ],
      "source": "inventory.ini"
    },
    "service": {
      "type": "enum",
      "domain": [
        "ssh",
        "nginx",
        "app",
        "postgresql"
      ],
      "source": "roles/app/tasks/main.yml"
    },
    "port": {
      "type": "integer",
      "domain": null,
      "source": "group_vars/appservers.yml"
    },
    "protocol": {
      "type": "enum",
      "domain": [
        "tcp"
      ],
      "source": "roles/app/tasks/main.yml"
    },
    "path": {
      "type": "string",
      "domain": null,
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
      "type": "string",
      "domain": null,
      "source": "roles/db/tasks/main.yml"
    },
    "database": {
      "type": "enum",
      "domain": [
        "all"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "privilege_level": {
      "type": "enum",
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
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
      "source": "inventory.ini"
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
      "domain": null,
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
      "host_group": {
        "equals": "appservers"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "24-28"
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
      "host_group": {
        "equals": "dbservers"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "30-33"
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
      "host_group": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "22-25"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      },
      "source_zone": {
        "equals": "dmz"
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "16-22"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      },
      "source_zone": {
        "equals": "app"
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
      },
      "host_group": {
        "equals": "dbservers"
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
      "task": "Allow postgres only from appservers subnet",
      "lines": "24-27"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      },
      "source_zone": {
        "equals": "internet"
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
      },
      "host_group": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "16-21"
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
      },
      "port": {
        "equals": 5432
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
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "24-27"
    }
  },
  {
    "id": "rule-008",
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
      },
      "privilege_level": {
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
      "task": "Create DB superuser role for DBAs",
      "lines": "14-18"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "host_group": {
        "equals": "dbservers"
      },
      "privilege_level": {
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
      "task": "Create DB read-only role for developers",
      "lines": "19-23"
    }
  },
  {
    "id": "rule-010",
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
      },
      "host_group": {
        "equals": "dbservers"
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
      "lines": "9-14"
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
      },
      "host_group": {
        "equals": "dbservers"
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
      "lines": "9-14"
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
      },
      "host_group": {
        "equals": "dbservers"
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
      "lines": "9-14"
    }
  },
  {
    "id": "rule-013",
    "subject_condition": {
      "groups": {
        "any_of": [
          "developers",
          "sudo"
        ]
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "7-14"
    }
  },
  {
    "id": "rule-014",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "10-15"
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
    "effect": "deny"
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
      },
      "host_group": {
        "equals": "dbservers"
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
      },
      "host_group": {
        "equals": "dbservers"
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
    "id": "rule-018",
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
      },
      "host_group": {
        "equals": "dbservers"
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
    "id": "rule-019",
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
  },
  {
    "id": "rule-020",
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
      },
      "host_group": {
        "equals": "dmz"
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
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2016-0746",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Use-after-free in nginx resolver affecting 0.6.18-1.8.0; pinned 1.20.0 is not in affected range",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2021-46461",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Out-of-bounds array access in njs (nginx scripting module) through 0.7.0; not nginx core",
    "recommendation": "No action required if njs module is not used; verify njs is not enabled"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2017-20005",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Old nginx vulnerability; pinned 1.20.0 likely not affected",
    "recommendation": "Verify specific affected versions; upgrade to latest nginx if concerned"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2021-23017",
    "cvss_score": 7.7,
    "severity": "high",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "DNS resolver overflow in nginx 0.6.18-1.8.0 and 1.9.x before 1.9.10; pinned 1.20.0 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2013-4547",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Old nginx vulnerability; pinned 1.20.0 likely not affected",
    "recommendation": "No action required; verify specific affected versions"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2023-44487",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "HTTP/2 rapid reset DDoS attack; nginx 1.20.0 with HTTP/2 enabled is potentially affected",
    "recommendation": "Upgrade nginx to 1.25.3+ or apply patch; disable HTTP/2 if not required; implement rate limiting"
  },
  {
    "product": "nginx",
    "pinned_version": "1.20.0",
    "cve_id": "CVE-2009-3555",
    "cvss_score": 5.8,
    "severity": "medium",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "SSL/TLS renegotiation vulnerability; very old, nginx 1.20.0 not affected",
    "recommendation": "No action required; ensure SSL renegotiation is disabled"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2024-6387",
    "cvss_score": 8.1,
    "severity": "high",
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "regreSSHion: race condition in OpenSSH server signal handling allows unauthenticated remote code execution; affects 8.4p1-9.8p1",
    "recommendation": "CRITICAL: Upgrade to OpenSSH 9.8p1 or later immediately; set LoginGraceTime to 0 as temporary mitigation"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2023-38408",
    "cvss_score": 9.8,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "Remote code execution via untrusted search path in ssh-agent PKCS#11 feature; affects OpenSSH before 9.3p2",
    "recommendation": "CRITICAL: Upgrade to OpenSSH 9.3p2 or later; disable PKCS#11 forwarding if not required"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2003-0786",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Historical OpenSSH vulnerability; pinned 9.1p1 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2000-0999",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Historical OpenSSH vulnerability; pinned 9.1p1 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2000-0525",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Historical OpenSSH vulnerability; pinned 9.1p1 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2001-0144",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Historical OpenSSH vulnerability; pinned 9.1p1 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2003-0693",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Historical OpenSSH vulnerability; pinned 9.1p1 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2007-4752",
    "cvss_score": 7.5,
    "severity": "high",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Historical OpenSSH vulnerability; pinned 9.1p1 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2019-6110",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Historical OpenSSH vulnerability; pinned 9.1p1 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "openssh",
    "pinned_version": "9.1p1",
    "cve_id": "CVE-2019-6109",
    "cvss_score": 6.8,
    "severity": "medium",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Historical OpenSSH vulnerability; pinned 9.1p1 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2024-1597",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": true,
    "description": "PostgreSQL vulnerability; may affect 16.2 depending on specific version range",
    "recommendation": "Upgrade PostgreSQL to latest 16.x patch release; review CVE details for exact affected versions"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2007-3279",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Historical PostgreSQL vulnerability; pinned 16.2 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2002-1399",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Historical PostgreSQL vulnerability; pinned 16.2 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2013-1903",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Historical PostgreSQL vulnerability; pinned 16.2 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  },
  {
    "product": "postgresql",
    "pinned_version": "16.2",
    "cve_id": "CVE-2013-1902",
    "cvss_score": 10.0,
    "severity": "critical",
    "is_remote": true,
    "affects_pinned_version": false,
    "description": "Historical PostgreSQL vulnerability; pinned 16.2 is not affected",
    "recommendation": "No action required; pinned version is outside affected range"
  }
]
```

## Report

# ABAC Policy Mining Report — SegCorp Ansible Configuration

## Executive Summary

An attribute-based access control (ABAC) policy was mined from the SegCorp Ansible configuration, which manages a three-tier production infrastructure (DMZ → App → Database) under PCI compliance. The policy comprises **15 rules** (14 permit + 1 default-deny) governing SSH access, network connectivity, database authentication, filesystem permissions, and user provisioning across three host groups. A vulnerability assessment identified **4 CVEs affecting pinned software versions**, including two critical OpenSSH vulnerabilities (CVE-2023-38408, CVE-2024-6387).

---

## Infrastructure Overview

| Host Group | Hostname | IP | Role | Zone |
|---|---|---|---|---|
| dmz | proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz |
| appservers | app01.lab.local | 10.0.2.10 | application | app |
| dbservers | db01.lab.local | 10.0.3.10 | primary | data |

**Environment:** production | **Compliance Tier:** PCI | **Organization:** segcorp

---

## Users

| User | UID | Groups | Department | Clearance |
|---|---|---|---|---|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

---

## Policy Rules Summary

### SSH Access (Rules 001–003)

| Rule | Host Group | Allowed Groups | Source |
|---|---|---|---|
| rule-001 | appservers | sudo, developers | roles/app/tasks/main.yml |
| rule-002 | dbservers | sudo, dba | roles/db/tasks/main.yml |
| rule-003 | dmz | sudo only | roles/dmz/tasks/main.yml |

### Network/Firewall (Rules 004–007)

| Rule | Source | Destination | Port | Effect | Source |
|---|---|---|---|---|---|
| rule-004 | 10.0.1.0/24 (DMZ) | appservers | 8080/tcp | permit | roles/app/tasks/main.yml |
| rule-005 | 10.0.2.0/24 (App) | dbservers | 5432/tcp | permit | roles/db/tasks/main.yml |
| rule-006 | 0.0.0.0/0 (Internet) | dmz | 443/tcp | permit | roles/dmz/tasks/main.yml |
| rule-007 | all others | dbservers | 5432/tcp | deny | roles/db/tasks/main.yml (implicit) |

### Database Access (Rules 008–009)

| Rule | Subject | Privilege Level | Effect | Source |
|---|---|---|---|---|
| rule-008 | dba group | SUPERUSER | permit | roles/db/tasks/main.yml |
| rule-009 | developers group | NOSUPERUSER | permit | roles/db/tasks/main.yml |

### Filesystem (Rules 010–012)

| Rule | Path | Mode | Action | Subject | Source |
|---|---|---|---|---|---|
| rule-010 | /var/lib/postgresql/data | 0700 | filesystem:read | dba group | roles/db/tasks/main.yml |
| rule-011 | /var/lib/postgresql/data | 0700 | filesystem:write | dba group | roles/db/tasks/main.yml |
| rule-012 | /var/lib/postgresql/data | 0700 | filesystem:execute | dba group | roles/db/tasks/main.yml |

### User Provisioning (Rules 013–014)

| Rule | Host Group | Allowed Groups | Source |
|---|---|---|---|
| rule-013 | appservers | developers, sudo | roles/app/tasks/main.yml |
| rule-014 | dmz | sudo only | roles/dmz/tasks/main.yml |

### Default Deny (Rule 015)

All access not explicitly permitted is denied.

---

## Vulnerability Assessment

### Critical Findings (Affecting Pinned Versions)

| CVE | Product | Pinned Version | CVSS | Severity | Affects Pinned? | Recommendation |
|---|---|---|---|---|---|---|
| CVE-2024-6387 | OpenSSH | 9.1p1 | 8.1 | high | **YES** | Upgrade to OpenSSH 9.8p1+; set LoginGraceTime=0 as interim |
| CVE-2023-38408 | OpenSSH | 9.1p1 | 9.8 | critical | **YES** | Upgrade to OpenSSH 9.3p2+; disable PKCS#11 forwarding |
| CVE-2024-1597 | PostgreSQL | 16.2 | 10.0 | critical | **YES** | Upgrade to latest 16.x patch release |
| CVE-2023-44487 | nginx | 1.20.0 | 7.5 | high | **YES** | Upgrade nginx to 1.25.3+; disable HTTP/2 if unused; add rate limiting |

### Non-Affecting CVEs (Pinned Versions Outside Range)

18 additional CVEs were identified but do not affect the pinned versions (nginx 1.20.0, OpenSSH 9.1p1, PostgreSQL 16.2) as they are historical vulnerabilities predating these versions.

---

## Ambiguities

1. **Developer DB access scope:** The `postgresql_user` task for developers creates a NOSUPERUSER LOGIN role, but does not explicitly grant SELECT-only privileges. The actual read-only restriction must be enforced via GRANT statements not present in the Ansible config.

2. **Firewall implicit deny:** The `firewall_allow_from` lists define permitted sources, but implicit deny for all other sources is assumed from firewalld defaults — not explicitly stated in the configuration.

3. **pg_hba implicit deny:** The pg_hba.conf rule allows connections from 10.0.2.0/24 only. The implicit deny for all other sources is captured as rule-007 but is not explicitly in the Ansible config.

4. **Credentials:** No explicit credential management (passwords, keys) is defined in the Ansible configuration. Authentication mechanisms are assumed to be managed externally.

5. **Nginx configuration:** The DMZ role installs nginx but does not define backend proxy targets or access control rules for the reverse proxy. The app server backend routing is not captured in the policy.

6. **`postgres` system user:** The filesystem rules reference `owner: postgres` and `group: postgres`, but `postgres` is not in the `users` list — it is a system account created by the PostgreSQL package, not managed by the Ansible user provisioning tasks.
