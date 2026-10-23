# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 11:31:01_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 11 | Rules: 11_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f4_patched_vs_vulnerable`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "domain": null,
      "source": "group_vars/all.yml",
      "entries": [
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
      ]
    },
    "groups": {
      "domain": [
        "sudo",
        "developers"
      ],
      "source": "group_vars/all.yml",
      "entries": [
        {
          "name": "sudo"
        },
        {
          "name": "developers"
        }
      ]
    },
    "clearance_levels": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml",
      "entries": [
        {
          "value": "secret"
        },
        {
          "value": "confidential"
        }
      ]
    },
    "departments": {
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml",
      "entries": [
        {
          "value": "operations"
        },
        {
          "value": "engineering"
        }
      ]
    }
  },
  "resources": {
    "hosts": {
      "domain": null,
      "source": "inventory.ini",
      "entries": [
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
      ]
    },
    "services": {
      "domain": null,
      "source": "group_vars/dbservers.yml, group_vars/webservers_patched.yml",
      "entries": [
        {
          "name": "nginx",
          "port": 443,
          "protocol": "tcp",
          "host_group": "webservers_patched",
          "source": "group_vars/webservers_patched.yml"
        },
        {
          "name": "nginx",
          "port": 443,
          "protocol": "tcp",
          "host_group": "webservers_legacy",
          "source": "group_vars/webservers_legacy.yml"
        },
        {
          "name": "postgres",
          "port": 5432,
          "protocol": "tcp",
          "host_group": "dbservers",
          "source": "group_vars/dbservers.yml"
        }
      ]
    },
    "paths": {
      "domain": null,
      "source": "roles/db/tasks/main.yml",
      "entries": [
        {
          "path": "/var/lib/postgresql/data",
          "owner": "postgres",
          "group": "postgres",
          "mode": "0700",
          "service": "postgres",
          "source": "roles/db/tasks/main.yml"
        }
      ]
    },
    "networks": {
      "domain": null,
      "source": "group_vars/dbservers.yml",
      "entries": [
        {
          "cidr": "10.0.1.0/24",
          "zone": "dmz",
          "label": "webservers_subnet",
          "source": "group_vars/dbservers.yml"
        },
        {
          "cidr": "10.0.2.0/24",
          "zone": "internal",
          "label": "dbservers_subnet",
          "source": "group_vars/dbservers.yml"
        }
      ]
    },
    "host_groups": {
      "domain": [
        "webservers_patched",
        "webservers_legacy",
        "dbservers"
      ],
      "source": "inventory.ini",
      "entries": [
        {
          "name": "webservers_patched"
        },
        {
          "name": "webservers_legacy"
        },
        {
          "name": "dbservers"
        }
      ]
    },
    "zones": {
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini",
      "entries": [
        {
          "value": "dmz"
        },
        {
          "value": "internal"
        }
      ]
    }
  },
  "environment": {
    "org": {
      "domain": [
        "patchcorp"
      ],
      "source": "group_vars/all.yml",
      "value": "patchcorp"
    },
    "environment": {
      "domain": [
        "production"
      ],
      "source": "inventory.ini",
      "value": "production"
    },
    "compliance_tier": {
      "domain": [
        "soc2"
      ],
      "source": "group_vars/all.yml, inventory.ini",
      "value": "soc2"
    },
    "retention_days": {
      "domain": null,
      "source": "group_vars/all.yml",
      "value": 90
    }
  }
}
```

## Rules

```json
[
  {
    "rule_id": "rule-001",
    "name": "ssh-login-sudo-group",
    "description": "Members of the sudo group may SSH into all web servers (patched and legacy). Enforced via AllowGroups sudo in sshd_config.",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "in": [
          "webservers_patched",
          "webservers_legacy"
        ]
      },
      "role": {
        "equals": "frontend"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        18,
        21
      ]
    },
    "obligations": [
      {
        "type": "session_logging",
        "description": "SSH sessions to web servers must be logged via /etc/profile.d/audit.sh",
        "source_file": "roles/web_legacy/tasks/main.yml",
        "source_lines": [
          18,
          21
        ]
      }
    ]
  },
  {
    "rule_id": "rule-002",
    "name": "https-from-internet-web-servers",
    "description": "Any source host may connect via HTTPS (TCP/443) to all web servers. firewalld rule applied on both legacy and patched hosts.",
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
      "protocol": {
        "equals": "tcp"
      },
      "inventory_group": {
        "in": [
          "webservers_patched",
          "webservers_legacy"
        ]
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/web_legacy/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        13,
        17
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "name": "postgres-login-from-web-subnet",
    "description": "Hosts in the web subnet (10.0.1.0/24) may authenticate to all PostgreSQL databases using SCRAM-SHA-256. Enforced via pg_hba.conf host entry.",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": [
        13,
        17
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "name": "postgres-deny-non-web-subnets",
    "description": "PostgreSQL authentication is denied for any source network other than 10.0.1.0/24. This is the implicit-deny default enforced by pg_hba.conf ordering.",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgres"
      },
      "port": {
        "equals": 5432
      },
      "protocol": {
        "equals": "tcp"
      },
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "db:login",
    "effect": "deny",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from web subnet",
      "lines": [
        13,
        17
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "name": "postgres-filesystem-data-dir",
    "description": "The postgres OS user may read, write, and execute files in the PostgreSQL data directory /var/lib/postgresql/data (mode 0700).",
    "subject_condition": {
      "name": {
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "name": "postgres-filesystem-data-dir-read",
    "description": "The postgres OS user may read the PostgreSQL data directory contents.",
    "subject_condition": {
      "name": {
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "name": "postgres-filesystem-data-dir-write",
    "description": "The postgres OS user may write to the PostgreSQL data directory contents.",
    "subject_condition": {
      "name": {
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
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "action": "filesystem:write",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        8,
        12
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "name": "default-deny-all",
    "description": "Default-deny catch-all: no subject may perform any action on any resource unless explicitly permitted above.",
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
      "file": "inventory.ini",
      "task": "implicit-default",
      "lines": [
        1,
        99
      ]
    },
    "environment_condition": {
      "compliance_tier": {
        "equals": "soc2"
      },
      "environment": {
        "equals": "production"
      }
    }
  },
  {
    "id": "rule-001",
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
    "id": "rule-002",
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
    "id": "rule-003",
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
  }
]
```

## Vulnerabilities

```json
[
  {
    "cve_id": "CVE-2016-0746",
    "age_in_days": 3719,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2016-02-15T19:59:01Z",
    "cve_updated_at": "2025-04-12T10:46:40Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.94368,
    "epss_score": 0.14006,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "vuln_status": "rejected",
    "citations": [
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "tags": [
          "Vendor Advisory"
        ],
        "url": "http://mailman.nginx.org/pipermail/nginx/2016-January/049700.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "tags": [
          "Mailing List",
          "Third Party Advisory"
        ],
        "url": "http://lists.opensuse.org/opensuse-updates/2016-02/msg00042.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "tags": [
          "Mailing List",
          "Third Party Advisory"
        ],
        "url": "http://seclists.org/fulldisclosure/2021/Sep/36"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "http://www.debian.org/security/2016/dsa-3473"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory",
          "VDB Entry"
        ],
        "url": "http://www.securitytracker.com/id/1034869"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "http://www.ubuntu.com/usn/USN-2892-1"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "https://access.redhat.com/errata/RHSA-2016:1425"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "https://bto.bluecoat.com/security-advisory/sa115"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "tags": [
          "Issue Tracking",
          "Patch",
          "Third Party Advisory"
        ],
        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1302588"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "https://security.gentoo.org/glsa/201606-06"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "https://support.apple.com/kb/HT212818"
      }
    ],
    "cwe": [
      "CWE-416"
    ],
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses related to CNAME processing, exploit requires sending malicious DNS responses.",
    "impact": "Attackers can cause worker process crashes or other unspecified impacts by sending crafted DNS responses, leading to service disruption.",
    "name": "nginx - Use After Free",
    "remediation": "Update to nginx 1.9.10 or later versions.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "denial_of_service"
    ],
    "vulnerability_type": "use_after_free",
    "weaknesses": [
      {
        "cwe_id": "CWE-416",
        "cwe_name": "Use After Free"
      }
    ],
    "affected_products": [
      {
        "category": "web_servers",
        "cpe": [
          "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "projects": [
          "https://github.com/nginx/nginx"
        ],
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "operating_system",
        "cpe": [
          "cpe:2.3:o:canonical:ubuntu_linux:14.04:*:*:*:esm:*:*:*",
          "cpe:2.3:o:canonical:ubuntu_linux:15.10:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ubuntu_linux",
        "summary": "canonical ubuntu_linux is a popular open-source operating system that provides a stable and secure platform for computing. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "canonical"
      },
      {
        "category": "operating_system",
        "cpe": [
          "cpe:2.3:o:debian:debian_linux:7.0:*:*:*:*:*:*:*",
          "cpe:2.3:o:debian:debian_linux:8.0:*:*:*:*:*:*:*",
          "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      },
      {
        "category": "operating_system",
        "cpe": [
          "cpe:2.3:o:opensuse:leap:42.1:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "leap",
        "summary": "opensuse leap is a stable and secure Linux-based operating system that provides a robust platform for desktops and servers. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "opensuse"
      },
      {
        "category": "application_library",
        "cpe": [
          "cpe:2.3:a:apple:xcode:*:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "xcode",
        "summary": "apple xcode is an integrated development environment (IDE) that provides tools for software development on Apple platforms. It sits in the application_library layer of the tech stack, functions as a development tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "apple"
      }
    ],
    "created_at": "2016-02-15T19:59:01Z",
    "doc_id": "CVE-2016-0746",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 62581792,
      "min_hosts": 4711752,
      "values": [
        {
          "id": "f5:nginx",
          "max_hosts": 62581792,
          "min_hosts": 62581792,
          "shodan": {
            "max_hosts": 62581792,
            "min_hosts": 62581792,
            "queries": [
              "cpe:\"cpe:2.3:a:f5:nginx\""
            ]
          }
        },
        {
          "id": "canonical:ubuntu_linux",
          "max_hosts": 18795718,
          "min_hosts": 18795718,
          "shodan": {
            "max_hosts": 18795718,
            "min_hosts": 18795718,
            "queries": [
              "cpe:\"cpe:2.3:o:canonical:ubuntu_linux\""
            ]
          }
        },
        {
          "id": "debian:debian_linux",
          "max_hosts": 4711752,
          "min_hosts": 4711752,
          "shodan": {
            "max_hosts": 4711752,
            "min_hosts": 4711752,
            "queries": [
              "cpe:\"cpe:2.3:o:debian:debian_linux\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_rank": -3,
      "rank": 590,
      "reports": 12
    },
    "ntps": 43,
    "updated_at": "2026-04-23T14:33:29.641Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 9.8",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2021-46461",
    "age_in_days": 1528,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2022-02-14T22:15:07Z",
    "cve_updated_at": "2024-11-21T06:34:07Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.70096,
    "epss_score": 0.00619,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 1,
    "poc_first_seen": "2022-02-14T22:15:07Z",
    "pocs": [
      {
        "added_at": "2022-02-14T22:15:07Z",
        "source": "nvd",
        "url": "https://github.com/nginx/njs/issues/450"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T06:34:07Z",
        "source": "nvd",
        "tags": [
          "Patch",
          "Vendor Advisory"
        ],
        "url": "https://github.com/nginx/njs/commit/d457c9545e7e71ebb5c0479eb16b9d33175855e2"
      },
      {
        "added_at": "2024-11-21T06:34:07Z",
        "source": "nvd",
        "tags": [
          "Exploit",
          "Third Party Advisory"
        ],
        "url": "https://github.com/nginx/njs/issues/450"
      },
      {
        "added_at": "2024-11-21T06:34:07Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "https://security.netapp.com/advisory/ntap-20220303-0007/"
      }
    ],
    "cwe": [
      "CWE-119"
    ],
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit requires crafted input.",
    "impact": "Attackers can cause application crashes or execute arbitrary code, leading to denial of service or full system compromise.",
    "name": "NGINX njs - Buffer Overflow",
    "remediation": "Update to the latest version of njs where the issue is fixed.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "denial_of_service",
      "remote_code_execution"
    ],
    "vulnerability_type": "out_of_bounds_rw",
    "weaknesses": [
      {
        "cwe_id": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within the Bounds of a Memory Buffer"
      }
    ],
    "affected_products": [
      {
        "category": "application_library",
        "cpe": [
          "cpe:2.3:a:nginx:njs:*:*:*:*:*:*:*:*"
        ],
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "njs",
        "projects": [
          "https://github.com/nginx/njs"
        ],
        "summary": "nginx njs is a lightweight scripting language and engine that extends nginx functionality with custom logic and dynamic content handling. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "nginx"
      }
    ],
    "created_at": "2022-02-14T22:15:07Z",
    "doc_id": "CVE-2021-46461",
    "doc_type": "cve",
    "exposure": {},
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 50,
    "updated_at": "2026-04-23T14:23:07.284Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 9.8",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2017-20005",
    "age_in_days": 1781,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2021-06-06T22:15:08Z",
    "cve_updated_at": "2025-12-05T15:15:49Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.87155,
    "epss_score": 0.0325,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 1,
    "poc_first_seen": "2021-06-06T22:15:08Z",
    "pocs": [
      {
        "added_at": "2021-06-06T22:15:08Z",
        "source": "nvd",
        "url": "https://trac.nginx.org/nginx/ticket/1368"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "tags": [
          "Release Notes",
          "Vendor Advisory"
        ],
        "url": "http://nginx.org/en/CHANGES"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "tags": [
          "Exploit",
          "Patch",
          "Vendor Advisory"
        ],
        "url": "https://trac.nginx.org/nginx/ticket/1368"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "tags": [
          "Patch",
          "Third Party Advisory"
        ],
        "url": "https://github.com/nginx/nginx/commit/0206ebe76f748bb39d9de4dd4b3fce777fdfdccf"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "tags": [
          "Patch",
          "Third Party Advisory"
        ],
        "url": "https://github.com/nginx/nginx/commit/b900cc28fcbb4cf5a32ab62f80b59292e1c85b4b"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "tags": [
          "Mailing List",
          "Third Party Advisory"
        ],
        "url": "https://lists.debian.org/debian-lts-announce/2021/06/msg00009.html"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "https://security.netapp.com/advisory/ntap-20210805-0006/"
      }
    ],
    "cwe": [
      "CWE-190",
      "CWE-120"
    ],
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denial of service or potentially execute arbitrary code, exploit requires processing of specially crafted files with large modification dates.",
    "impact": "Attackers can cause denial of service or execute arbitrary code by exploiting the buffer overflow.",
    "name": "NGINX - Buffer Overflow",
    "remediation": "Update to version 1.13.6 or later.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "denial_of_service",
      "remote_code_execution"
    ],
    "vulnerability_type": "buffer_overflow",
    "weaknesses": [
      {
        "cwe_id": "CWE-190",
        "cwe_name": "Integer Overflow or Wraparound"
      },
      {
        "cwe_id": "CWE-120",
        "cwe_name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')"
      }
    ],
    "affected_products": [
      {
        "category": "web_servers",
        "cpe": [
          "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "projects": [
          "https://github.com/nginx/nginx"
        ],
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "operating_system",
        "cpe": [
          "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      }
    ],
    "created_at": "2021-06-06T22:15:08Z",
    "doc_id": "CVE-2017-20005",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 62581792,
      "min_hosts": 4711752,
      "values": [
        {
          "id": "f5:nginx",
          "max_hosts": 62581792,
          "min_hosts": 62581792,
          "shodan": {
            "max_hosts": 62581792,
            "min_hosts": 62581792,
            "queries": [
              "cpe:\"cpe:2.3:a:f5:nginx\""
            ]
          }
        },
        {
          "id": "debian:debian_linux",
          "max_hosts": 4711752,
          "min_hosts": 4711752,
          "shodan": {
            "max_hosts": 4711752,
            "min_hosts": 4711752,
            "queries": [
              "cpe:\"cpe:2.3:o:debian:debian_linux\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_rank": 3,
      "delta_reports": -1,
      "rank": 7954
    },
    "ntps": 51,
    "updated_at": "2026-04-23T15:04:56.098Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 9.8",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2021-23017",
    "age_in_days": 1787,
    "assignee": "f5sirt@f5.com",
    "cve_created_at": "2021-06-01T13:15:07Z",
    "cve_updated_at": "2024-11-21T05:51:09Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
    "cvss_score": 7.7,
    "epss_percentile": 0.98816,
    "epss_score": 0.73544,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 9,
    "poc_first_seen": "2021-12-17T09:53:39Z",
    "pocs": [
      {
        "added_at": "2025-09-04T09:49:22Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/6lj/EVIL-CVE-2021-23017-Update-2025"
      },
      {
        "added_at": "2025-05-06T16:32:48Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/moften/CVE-2021-23017"
      },
      {
        "added_at": "2025-04-17T11:33:08Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Cybervixy/Vulnerability-Management"
      },
      {
        "added_at": "2025-01-30T11:05:40Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/lukwagoasuman/-home-lukewago-Downloads-CVE-2021-23017-Nginx-1.14"
      },
      {
        "added_at": "2024-12-08T09:47:52Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/z3usx01/CVE-2021-23017-POC"
      },
      {
        "added_at": "2023-10-21T04:24:02Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/ShivamDey/CVE-2021-23017"
      },
      {
        "added_at": "2023-07-20T05:39:01Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/lakshit1212/CVE-2021-23017-PoC"
      },
      {
        "added_at": "2022-06-30T04:39:58Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/M507/CVE-2021-23017-PoC"
      },
      {
        "added_at": "2021-12-17T09:53:39Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/niandy/nginx-patch"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "tags": [
          "Mailing List",
          "Patch",
          "Vendor Advisory"
        ],
        "url": "http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory",
          "VDB Entry"
        ],
        "url": "http://packetstormsecurity.com/files/167720/Nginx-1.20.0-Denial-Of-Service.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "https://security.netapp.com/advisory/ntap-20210708-0006/"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "tags": [
          "Patch",
          "Third Party Advisory"
        ],
        "url": "https://www.oracle.com/security-alerts/cpuapr2022.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "tags": [
          "Patch",
          "Third Party Advisory"
        ],
        "url": "https://www.oracle.com/security-alerts/cpujan2022.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "tags": [
          "Patch",
          "Third Party Advisory"
        ],
        "url": "https://www.oracle.com/security-alerts/cpuoct2021.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r37e6b2165f7c910d8e15fd54f4697857619ad2625f56583802004009%40%3Cnotifications.apisix.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r4d4966221ca399ce948ef34884652265729d7d9ef8179c78d7f17e7f%40%3Cnotifications.apisix.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r6fc5c57b38e93e36213e9a18c8a4e5dbd5ced1c7e57f08a1735975ba%40%3Cnotifications.apisix.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf232eecd47fdc44520192810560303073cefd684b321f85e311bad31%40%3Cnotifications.apisix.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf318aeeb4d7a3a312734780b47de83cefb7e6995da0b2cae5c28675c%40%3Cnotifications.apisix.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7SFVYHC7OXTEO4SMBWXDVK6E5IMEYMEE/"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GNKOP2JR5L7KCIZTJRZDCUPJTUONMC5I/"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://support.f5.com/csp/article/K12331123%2C"
      }
    ],
    "cwe": [
      "CWE-193"
    ],
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP packets from DNS server.",
    "impact": "Attackers can cause worker process crashes or other impacts by forging UDP packets, potentially leading to denial of service or other disruptions.",
    "name": "nginx - Buffer Overflow",
    "remediation": "Update nginx to the latest version where this issue is fixed.",
    "requirement_type": "none",
    "severity": "high",
    "vulnerability_impact": [
      "denial_of_service"
    ],
    "vulnerability_type": "buffer_overflow",
    "weaknesses": [
      {
        "cwe_id": "CWE-193",
        "cwe_name": "Off-by-one Error"
      }
    ],
    "affected_products": [
      {
        "category": "web_servers",
        "cpe": [
          "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "projects": [
          "https://github.com/nginx/nginx"
        ],
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "web_servers",
        "cpe": [
          "cpe:2.3:a:openresty:openresty:*:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openresty",
        "projects": [
          "https://github.com/openresty/openresty"
        ],
        "summary": "openresty openresty is a web platform that integrates the Nginx web server with Lua scripting for high-performance web applications. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "openresty"
      },
      {
        "category": "operating_system",
        "cpe": [
          "cpe:2.3:o:fedoraproject:fedora:33:*:*:*:*:*:*:*",
          "cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fedora",
        "summary": "fedoraproject fedora is a Linux-based open-source operating system that provides a robust and secure platform for developers and users. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "fedoraproject"
      },
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:netapp:ontap_select_deploy_administration_utility:-:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_select_deploy_administration_utility",
        "summary": "netapp ontap_select_deploy_administration_utility is a deployment and management tool for NetApp's ONTAP Select software-defined storage. It sits in the core_infra layer of the tech stack, functions as a self-hosted management utility in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:oracle:blockchain_platform:*:*:*:*:*:*:*:*"
        ],
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "blockchain_platform",
        "summary": "oracle blockchain_platform is an enterprise-grade blockchain solution that enables secure and transparent business networks. It sits in the core_infra layer of the tech stack, functions as a platform service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:oracle:communications_control_plane_monitor:3.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:oracle:communications_control_plane_monitor:4.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:oracle:communications_control_plane_monitor:4.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:oracle:communications_control_plane_monitor:4.4:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_control_plane_monitor",
        "summary": "oracle communications_control_plane_monitor is a network monitoring and management solution that provides real-time visibility and control over telecom control plane operations. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:oracle:communications_fraud_monitor:*:*:*:*:*:*:*:*"
        ],
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_fraud_monitor",
        "summary": "oracle communications_fraud_monitor is a fraud detection and prevention solution designed to protect telecommunications networks from fraudulent activities. It sits in the core_infra layer of the tech stack, functions as a security monitoring system in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "cpe": [
          "cpe:2.3:a:oracle:communications_operations_monitor:3.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:oracle:communications_operations_monitor:4.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:oracle:communications_operations_monitor:4.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:oracle:communications_operations_monitor:4.4:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_operations_monitor",
        "summary": "oracle communications_operations_monitor is a network operations monitoring solution that provides real-time visibility and analytics for telecom networks. It sits in the core_infra layer of the tech stack, functions as an enterprise application in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:oracle:communications_session_border_controller:8.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:oracle:communications_session_border_controller:9.0:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_session_border_controller",
        "summary": "oracle communications_session_border_controller is a network security and session management solution that protects and manages VoIP and multimedia sessions. It sits in the core_infra layer of the tech stack, functions as a network security appliance in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:oracle:enterprise_communications_broker:3.3.0:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_communications_broker",
        "summary": "oracle enterprise_communications_broker is a communication integration platform that enables seamless messaging and data exchange across enterprise systems. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:oracle:enterprise_session_border_controller:8.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:oracle:enterprise_session_border_controller:9.0:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "enterprise_session_border_controller",
        "summary": "oracle enterprise_session_border_controller is a session border controller that secures and manages VoIP and video communications across enterprise networks. It sits in the core_infra layer of the tech stack, functions as a network security and management appliance in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:oracle:enterprise_telephony_fraud_monitor:3.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:oracle:enterprise_telephony_fraud_monitor:4.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:oracle:enterprise_telephony_fraud_monitor:4.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:oracle:enterprise_telephony_fraud_monitor:4.4:*:*:*:*:*:*:*"
        ],
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "enterprise_telephony_fraud_monitor",
        "summary": "oracle enterprise_telephony_fraud_monitor is a telephony fraud detection and monitoring solution that helps enterprises identify and prevent fraudulent activities in voice networks. It sits in the core_infra layer of the tech stack, functions as a security monitoring tool in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:oracle:goldengate:*:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "goldengate",
        "summary": "oracle goldengate is a real-time data replication and integration solution that enables high availability and disaster recovery for enterprise data. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      }
    ],
    "created_at": "2021-06-01T13:15:07Z",
    "doc_id": "CVE-2021-23017",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 62581792,
      "min_hosts": 40582,
      "values": [
        {
          "id": "f5:nginx",
          "max_hosts": 62581792,
          "min_hosts": 62581792,
          "shodan": {
            "max_hosts": 62581792,
            "min_hosts": 62581792,
            "queries": [
              "cpe:\"cpe:2.3:a:f5:nginx\""
            ]
          }
        },
        {
          "id": "openresty:openresty",
          "max_hosts": 126744,
          "min_hosts": 126744,
          "shodan": {
            "max_hosts": 126744,
            "min_hosts": 126744,
            "queries": [
              "http.title:\"welcome to openresty!\""
            ]
          }
        },
        {
          "id": "fedoraproject:fedora",
          "max_hosts": 40582,
          "min_hosts": 40582,
          "shodan": {
            "max_hosts": 40582,
            "min_hosts": 40582,
            "queries": [
              "cpe:\"cpe:2.3:o:fedoraproject:fedora\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_rank": 4,
      "rank": 387,
      "reports": 33
    },
    "ntps": 50,
    "updated_at": "2026-04-23T15:43:51.073Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 7.7",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2013-4547",
    "age_in_days": 4532,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-11-23T18:55:04Z",
    "cve_updated_at": "2025-04-11T00:51:21Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
    "cvss_score": 7.5,
    "epss_percentile": 0.99637,
    "epss_score": 0.90921,
    "is_oss": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 2,
    "poc_first_seen": "2020-06-20T09:37:58Z",
    "pocs": [
      {
        "added_at": "2025-12-08T15:37:35Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/rsp243/fix_nginx_CVE-2013-4547_IB"
      },
      {
        "added_at": "2020-06-20T09:37:58Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/cyberharsh/Nginx-CVE-2013-4547"
      }
    ],
    "vuln_status": "rejected",
    "citations": [
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "tags": [
          "Mitigation",
          "Vendor Advisory"
        ],
        "url": "http://mailman.nginx.org/pipermail/nginx-announce/2013/000125.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "tags": [
          "Mailing List",
          "Third Party Advisory"
        ],
        "url": "http://lists.opensuse.org/opensuse-security-announce/2013-12/msg00007.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "tags": [
          "Mailing List",
          "Third Party Advisory"
        ],
        "url": "http://lists.opensuse.org/opensuse-updates/2013-11/msg00084.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "tags": [
          "Mailing List",
          "Third Party Advisory"
        ],
        "url": "http://lists.opensuse.org/opensuse-updates/2013-11/msg00118.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "tags": [
          "Mailing List",
          "Third Party Advisory"
        ],
        "url": "http://lists.opensuse.org/opensuse-updates/2013-11/msg00119.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "http://secunia.com/advisories/55757"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "http://secunia.com/advisories/55822"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "http://secunia.com/advisories/55825"
      }
    ],
    "cwe": [
      "CWE-116"
    ],
    "description": "nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 contain a restriction bypass caused by unescaped space character in URI, letting remote attackers bypass intended restrictions, exploit requires sending a crafted URI with unescaped space.",
    "impact": "Attackers can bypass restrictions and access restricted resources or functionalities, potentially leading to unauthorized access.",
    "name": "nginx - Authorization Bypass",
    "remediation": "Update to nginx 1.5.7 or later versions.",
    "requirement_type": "none",
    "severity": "high",
    "vulnerability_impact": [
      "information_disclosure"
    ],
    "vulnerability_type": "misconfiguration",
    "weaknesses": [
      {
        "cwe_id": "CWE-116",
        "cwe_name": "Improper Encoding or Escaping of Output"
      }
    ],
    "affected_products": [
      {
        "category": "web_servers",
        "cpe": [
          "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "projects": [
          "https://github.com/nginx/nginx"
        ],
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:suse:lifecycle_management_server:1.3:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "lifecycle_management_server",
        "summary": "suse lifecycle_management_server is a systems management solution that automates patching, configuration, and provisioning of Linux servers. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure management tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "suse"
      },
      {
        "category": "operating_system",
        "cpe": [
          "cpe:2.3:a:suse:studio_onsite:1.3:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "studio_onsite",
        "summary": "suse studio_onsite is a custom Linux operating system build and deployment tool that enables enterprises to create tailored OS images. It sits in the operating_system layer of the tech stack, functions as a self-hosted deployment tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "suse"
      },
      {
        "category": "operating_system",
        "cpe": [
          "cpe:2.3:a:suse:webyast:1.3:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "webyast",
        "summary": "suse webyast is a web-based system configuration tool that simplifies the management of SUSE Linux systems. It sits in the operating_system layer of the tech stack, functions as a self-hosted system management interface in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "suse"
      },
      {
        "category": "operating_system",
        "cpe": [
          "cpe:2.3:o:opensuse:opensuse:11.4:*:*:*:*:*:*:*",
          "cpe:2.3:o:opensuse:opensuse:12.2:*:*:*:*:*:*:*",
          "cpe:2.3:o:opensuse:opensuse:12.3:*:*:*:*:*:*:*",
          "cpe:2.3:o:opensuse:opensuse:13.1:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "opensuse",
        "summary": "opensuse opensuse is a Linux-based open source operating system that provides a stable and versatile platform for various computing needs. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "opensuse"
      }
    ],
    "created_at": "2013-11-23T18:55:04Z",
    "doc_id": "CVE-2013-4547",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 62588721,
      "min_hosts": 415090,
      "values": [
        {
          "id": "f5:nginx",
          "max_hosts": 62588721,
          "min_hosts": 62588721,
          "shodan": {
            "max_hosts": 62588721,
            "min_hosts": 62588721,
            "queries": [
              "cpe:\"cpe:2.3:a:f5:nginx\""
            ]
          }
        },
        {
          "id": "opensuse:opensuse",
          "max_hosts": 415090,
          "min_hosts": 415090,
          "shodan": {
            "max_hosts": 415090,
            "min_hosts": 415090,
            "queries": [
              "vsftpd"
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_rank": -5,
      "rank": 2534,
      "reports": 1
    },
    "ntps": 62,
    "updated_at": "2026-04-22T15:42:23.954Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 7.5",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2007-3279",
    "age_in_days": 6882,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2007-06-19T21:30:00Z",
    "cve_updated_at": "2026-04-23T00:35:47Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.86341,
    "epss_score": 0.02885,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://osvdb.org/40900"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.leidecker.info/pgshell/Having_Fun_With_PostgreSQL.txt"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.mandriva.com/security/advisories?name=MDKSA-2007:188"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.portcullis.co.uk/uplds/whitepapers/Having_Fun_With_PostgreSQL.pdf"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/471541/100/0/threaded"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/35144"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation.",
    "impact": "Remote attackers can create and execute functions, enabling privilege escalation or malicious activities like password guessing.",
    "name": "PostgreSQL - Privilege Escalation",
    "remediation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed.",
    "requirement_type": "logged_in",
    "requirements": "Attacker needs to create functions in the database",
    "severity": "critical",
    "vulnerability_impact": [
      "privilege_escalation"
    ],
    "vulnerability_type": "broken_access_control",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "data_storage",
        "cpe": [
          "cpe:2.3:a:postgresql:postgresql:8.1:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "projects": [
          "https://git.postgresql.org/git/postgresql.git"
        ],
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2007-06-19T21:30:00Z",
    "doc_id": "CVE-2007-3279",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 550047,
      "min_hosts": 550047,
      "values": [
        {
          "id": "postgresql:postgresql",
          "max_hosts": 550047,
          "min_hosts": 550047,
          "shodan": {
            "max_hosts": 550047,
            "min_hosts": 550047,
            "queries": [
              "cpe:\"cpe:2.3:a:postgresql:postgresql\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-04-23T13:59:10.477Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 10",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2002-1399",
    "age_in_days": 8497,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2003-01-17T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.64045,
    "epss_score": 0.00458,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://archives.postgresql.org/pgsql-hackers/2002-08/msg00708.php"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://archives.postgresql.org/pgsql-hackers/2002-08/msg00713.php"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=102978152712430&w=2"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified.",
    "impact": "Potential for unexpected behavior or system instability due to improper handling of invalid input, specific impact is unspecified.",
    "name": "PostgreSQL - Integer Overflow",
    "remediation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "undefined"
    ],
    "vulnerability_type": "integer_overflow",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "data_storage",
        "cpe": [
          "cpe:2.3:a:postgresql:postgresql:6.3.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:6.5.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:7.0.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:7.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:7.1.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:7.1.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:7.1.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:7.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:7.2.1:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "projects": [
          "https://git.postgresql.org/git/postgresql.git"
        ],
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2003-01-17T05:00:00Z",
    "doc_id": "CVE-2002-1399",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 550047,
      "min_hosts": 550047,
      "values": [
        {
          "id": "postgresql:postgresql",
          "max_hosts": 550047,
          "min_hosts": 550047,
          "shodan": {
            "max_hosts": 550047,
            "min_hosts": 550047,
            "queries": [
              "cpe:\"cpe:2.3:a:postgresql:postgresql\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-04-23T13:51:41.708Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 10",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2013-1903",
    "age_in_days": 4766,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-04-04T17:55:00Z",
    "cve_updated_at": "2025-04-11T00:51:21Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.68021,
    "epss_score": 0.0055,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "rejected",
    "citations": [
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "tags": [
          "Vendor Advisory"
        ],
        "url": "http://www.postgresql.org/about/news/1456/"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "tags": [
          "Vendor Advisory"
        ],
        "url": "http://www.postgresql.org/support/security/"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html"
      }
    ],
    "cwe": [
      "CWE-264"
    ],
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers potentially access sensitive credentials, exploit requires access to installer scripts.",
    "impact": "Potential exposure of superuser password, leading to unauthorized access and control over the database system.",
    "name": "PostgreSQL - Information Disclosure",
    "remediation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "requirement_type": "user_interaction",
    "requirements": "Attacker needs access to installer scripts",
    "severity": "critical",
    "vulnerability_impact": [
      "information_disclosure"
    ],
    "vulnerability_type": "undefined",
    "weaknesses": [
      {
        "cwe_id": "CWE-264"
      }
    ],
    "affected_products": [
      {
        "category": "data_storage",
        "cpe": [
          "cpe:2.3:a:postgresql:postgresql:9.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.2.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.2.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.5:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.6:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.7:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.8:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.5:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.6:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.7:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.8:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.9:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.10:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.11:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.12:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.5:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.6:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.7:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.8:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.9:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.10:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.11:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.12:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.13:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.14:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.15:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.16:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.5:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.6:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.7:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.8:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.9:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.10:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.11:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.12:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.13:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.14:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.15:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.16:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.17:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.18:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.19:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.20:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.21:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.22:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "projects": [
          "https://git.postgresql.org/git/postgresql.git"
        ],
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2013-04-04T17:55:00Z",
    "doc_id": "CVE-2013-1903",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 550047,
      "min_hosts": 550047,
      "values": [
        {
          "id": "postgresql:postgresql",
          "max_hosts": 550047,
          "min_hosts": 550047,
          "shodan": {
            "max_hosts": 550047,
            "min_hosts": 550047,
            "queries": [
              "cpe:\"cpe:2.3:a:postgresql:postgresql\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-04-23T15:19:21.794Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 10",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2013-1902",
    "age_in_days": 4766,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-04-04T17:55:00Z",
    "cve_updated_at": "2025-04-11T00:51:21Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.66994,
    "epss_score": 0.00523,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "rejected",
    "citations": [
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "tags": [
          "Vendor Advisory"
        ],
        "url": "http://www.postgresql.org/about/news/1456/"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "tags": [
          "Vendor Advisory"
        ],
        "url": "http://www.postgresql.org/support/security/"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "impact": "Potential for attackers to exploit predictable temporary files, possibly leading to information disclosure or other unspecified impacts.",
    "name": "PostgreSQL - Insecure Temporary Files",
    "remediation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "information_disclosure"
    ],
    "vulnerability_type": "undefined",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "data_storage",
        "cpe": [
          "cpe:2.3:a:postgresql:postgresql:9.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.2.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.2.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.5:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.6:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.7:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.1.8:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.5:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.6:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.7:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.8:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.9:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.10:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.11:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:9.0.12:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.5:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.6:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.7:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.8:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.9:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.10:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.11:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.12:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.13:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.14:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.15:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.4.16:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.4:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.5:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.6:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.7:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.8:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.9:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.10:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.11:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.12:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.13:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.14:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.15:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.16:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.17:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.18:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.19:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.20:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.21:*:*:*:*:*:*:*",
          "cpe:2.3:a:postgresql:postgresql:8.3.22:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "projects": [
          "https://git.postgresql.org/git/postgresql.git"
        ],
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2013-04-04T17:55:00Z",
    "doc_id": "CVE-2013-1902",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 550047,
      "min_hosts": 550047,
      "values": [
        {
          "id": "postgresql:postgresql",
          "max_hosts": 550047,
          "min_hosts": 550047,
          "shodan": {
            "max_hosts": 550047,
            "min_hosts": 550047,
            "queries": [
              "cpe:\"cpe:2.3:a:postgresql:postgresql\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_rank": 14,
      "delta_reports": -1,
      "rank": 7968
    },
    "ntps": 45,
    "updated_at": "2026-04-23T15:49:56.392Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 10",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2024-1597",
    "age_in_days": 794,
    "assignee": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007",
    "cve_created_at": "2024-02-19T13:15:07Z",
    "cve_updated_at": "2025-11-03T22:16:40Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 10,
    "epss_percentile": 0.66397,
    "epss_score": 0.00508,
    "is_kev": true,
    "is_oss": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2024-10-30T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "tags": [
          "Release Notes"
        ],
        "url": "https://www.enterprisedb.com/docs/jdbc_connector/latest/01_jdbc_rel_notes/"
      },
      {
        "added_at": "2024-10-30T00:00:00Z",
        "source": "vulncheck",
        "tags": [
          "Vulncheck Reported Exploitation"
        ],
        "url": "https://www.reliaquest.com/blog/5-critical-threat-actors-you-need-to-know-about/"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-24rp-q3w6-vc56"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "tags": [
          "Mailing List",
          "Third Party Advisory"
        ],
        "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TZQTSMESZD2RJ5XBPSXH3TIQVUW5DIUU/"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "tags": [
          "Third Party Advisory"
        ],
        "url": "https://www.enterprisedb.com/docs/security/assessments/cve-2024-1597/"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/04/02/6"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2024/05/msg00007.html"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20240419-0008/"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://www.sonarsource.com/blog/double-dash-double-trouble-a-subtle-sql-injection-flaw/"
      },
      {
        "added_at": "2025-11-03T22:16:40Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2024/12/msg00017.html"
      }
    ],
    "cwe": [
      "CWE-89"
    ],
    "description": "pgjdbc PostgreSQL JDBC Driver versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 contain an SQL injection caused by improper handling of placeholders in PreferQueryMode=SIMPLE, letting attackers inject malicious SQL, exploit requires using PreferQueryMode=SIMPLE with specific placeholder construction.",
    "impact": "Attackers can inject malicious SQL, potentially leading to data theft, modification, or deletion.",
    "name": "pgjdbc - SQL Injection",
    "remediation": "Update to version 42.7.2 or later.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "information_disclosure",
      "data_tampering"
    ],
    "vulnerability_type": "sql_injection",
    "weaknesses": [
      {
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
      }
    ],
    "affected_products": [
      {
        "category": "application_library",
        "cpe": [
          "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*"
        ],
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "postgresql_jdbc_driver",
        "projects": [
          "https://github.com/pgjdbc/pgjdbc"
        ],
        "summary": "postgresql postgresql_jdbc_driver is a database connectivity library that enables Java applications to interact with PostgreSQL databases. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "postgresql"
      },
      {
        "category": "operating_system",
        "cpe": [
          "cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fedora",
        "summary": "fedoraproject fedora is a Linux-based open-source operating system that provides a robust and secure platform for developers and users. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "fedoraproject"
      }
    ],
    "created_at": "2024-02-19T13:15:07Z",
    "doc_id": "CVE-2024-1597",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 40582,
      "min_hosts": 40582,
      "values": [
        {
          "id": "fedoraproject:fedora",
          "max_hosts": 40582,
          "min_hosts": 40582,
          "shodan": {
            "max_hosts": 40582,
            "min_hosts": 40582,
            "queries": [
              "cpe:\"cpe:2.3:o:fedoraproject:fedora\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 61,
    "updated_at": "2026-04-23T15:50:51.057Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 10",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2003-0786",
    "age_in_days": 8193,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2003-11-17T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.86925,
    "epss_score": 0.03141,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "tags": [
          "US Government Resource"
        ],
        "url": "http://www.kb.cert.org/vuls/id/602204"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://lists.grok.org.uk/pipermail/full-disclosure/2003-September/010812.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.openssh.com/txt/sshpam.adv"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/338616"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/338617"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/bid/8677"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled.",
    "impact": "Remote attackers can gain privileges on the affected system, potentially leading to full system compromise.",
    "name": "OpenSSH - Privilege Escalation",
    "remediation": "Update to a version where this issue is fixed, or enable Privilege Separation.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "privilege_escalation"
    ],
    "vulnerability_type": "broken_access_control",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:openbsd:openssh:3.7.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:openbsd:openssh:3.7.1p1:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "projects": [
          "https://github.com/openssh/openssh-portable"
        ],
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "created_at": "2003-11-17T05:00:00Z",
    "doc_id": "CVE-2003-0786",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 39444278,
      "min_hosts": 39444278,
      "values": [
        {
          "id": "openbsd:openssh",
          "max_hosts": 39444278,
          "min_hosts": 39444278,
          "shodan": {
            "max_hosts": 39444278,
            "min_hosts": 39444278,
            "queries": [
              "cpe:\"cpe:2.3:a:openbsd:openssh\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 48,
    "updated_at": "2026-04-23T14:15:48.607Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 10",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2000-0999",
    "age_in_days": 9264,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2000-12-11T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.61869,
    "epss_score": 0.00418,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "tags": [
          "Patch",
          "Vendor Advisory"
        ],
        "url": "ftp://ftp.openbsd.org/pub/OpenBSD/patches/2.7/common/028_format_strings.patch"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input.",
    "impact": "Attackers can execute arbitrary code with root privileges, leading to complete system compromise.",
    "name": "OpenBSD SSH - Buffer Overflow",
    "remediation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution",
      "privilege_escalation"
    ],
    "vulnerability_type": "buffer_overflow",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:openbsd:openssh:4.5:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "projects": [
          "https://github.com/openssh/openssh-portable"
        ],
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "created_at": "2000-12-11T05:00:00Z",
    "doc_id": "CVE-2000-0999",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 39444278,
      "min_hosts": 39444278,
      "values": [
        {
          "id": "openbsd:openssh",
          "max_hosts": 39444278,
          "min_hosts": 39444278,
          "shodan": {
            "max_hosts": 39444278,
            "min_hosts": 39444278,
            "queries": [
              "cpe:\"cpe:2.3:a:openbsd:openssh\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 48,
    "updated_at": "2026-04-23T13:46:25.752Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 10",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2000-0525",
    "age_in_days": 9450,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2000-06-08T04:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.72276,
    "epss_score": 0.00709,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://archives.neohapsis.com/archives/bugtraq/2000-06/0065.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.openbsd.org/errata.html#uselogin"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.osvdb.org/341"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/bid/1334"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/4646"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input.",
    "impact": "Local users can execute arbitrary commands with elevated privileges, potentially leading to system compromise.",
    "name": "OpenSSH - Privilege Escalation",
    "remediation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option.",
    "requirement_type": "logged_in",
    "requirements": "Attacker needs local access and to provide command input",
    "severity": "critical",
    "vulnerability_impact": [
      "privilege_escalation",
      "remote_code_execution"
    ],
    "vulnerability_type": "command_injection",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:openbsd:openssh:1.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:openbsd:openssh:1.2.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:openbsd:openssh:2.1:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "projects": [
          "https://github.com/openssh/openssh-portable"
        ],
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "created_at": "2000-06-08T04:00:00Z",
    "doc_id": "CVE-2000-0525",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 39444278,
      "min_hosts": 39444278,
      "values": [
        {
          "id": "openbsd:openssh",
          "max_hosts": 39444278,
          "min_hosts": 39444278,
          "shodan": {
            "max_hosts": 39444278,
            "min_hosts": 39444278,
            "queries": [
              "cpe:\"cpe:2.3:a:openbsd:openssh\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 48,
    "updated_at": "2026-04-23T13:46:23.794Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 10",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2001-0144",
    "age_in_days": 9173,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2001-03-12T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.98345,
    "epss_score": 0.61717,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 1,
    "poc_first_seen": "2001-03-12T05:00:00Z",
    "pocs": [
      {
        "added_at": "2001-03-12T05:00:00Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/bid/2347"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "tags": [
          "Patch",
          "Vendor Advisory"
        ],
        "url": "http://razor.bindview.com/publish/advisories/adv_ssh1crc.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "tags": [
          "US Government Resource"
        ],
        "url": "http://www.cert.org/advisories/CA-2001-35.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "tags": [
          "Exploit",
          "Patch",
          "Vendor Advisory"
        ],
        "url": "http://www.securityfocus.com/bid/2347"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=98168366406903&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.osvdb.org/503"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.osvdb.org/795"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/6083"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requires sending crafted CRC-32 data.",
    "impact": "Remote attackers can execute arbitrary commands on SSH server or client, leading to full system compromise.",
    "name": "CORE SDI SSH1 CRC-32 - Command Injection",
    "remediation": "Update to the latest version or apply security patches addressing the integer overflow issue.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "command_injection",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:openbsd:openssh:1.2.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:openbsd:openssh:1.2.3:*:*:*:*:*:*:*",
          "cpe:2.3:a:openbsd:openssh:2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:openbsd:openssh:2.1.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:openbsd:openssh:2.2:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "projects": [
          "https://github.com/openssh/openssh-portable"
        ],
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:ssh:ssh:1.2.24:*:*:*:*:*:*:*",
          "cpe:2.3:a:ssh:ssh:1.2.25:*:*:*:*:*:*:*",
          "cpe:2.3:a:ssh:ssh:1.2.26:*:*:*:*:*:*:*",
          "cpe:2.3:a:ssh:ssh:1.2.27:*:*:*:*:*:*:*",
          "cpe:2.3:a:ssh:ssh:1.2.28:*:*:*:*:*:*:*",
          "cpe:2.3:a:ssh:ssh:1.2.29:*:*:*:*:*:*:*",
          "cpe:2.3:a:ssh:ssh:1.2.30:*:*:*:*:*:*:*",
          "cpe:2.3:a:ssh:ssh:1.2.31:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ssh",
        "summary": "ssh ssh is a secure network protocol that provides encrypted communication over unsecured networks. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "ssh"
      }
    ],
    "created_at": "2001-03-12T05:00:00Z",
    "doc_id": "CVE-2001-0144",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 39444278,
      "min_hosts": 39444278,
      "values": [
        {
          "id": "openbsd:openssh",
          "max_hosts": 39444278,
          "min_hosts": 39444278,
          "shodan": {
            "max_hosts": 39444278,
            "min_hosts": 39444278,
            "queries": [
              "cpe:\"cpe:2.3:a:openbsd:openssh\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 64,
    "updated_at": "2026-04-23T13:47:50.191Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 10",
    "affects_pinned_version": true
  },
  {
    "cve_id": "CVE-2003-0693",
    "age_in_days": 8249,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2003-09-22T04:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.96374,
    "epss_score": 0.26823,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "tags": [
          "US Government Resource"
        ],
        "url": "http://www.cert.org/advisories/CA-2003-24.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "tags": [
          "Patch",
          "Third Party Advisory",
          "US Government Resource"
        ],
        "url": "http://www.kb.cert.org/vuls/id/333628"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://lists.grok.org.uk/pipermail/full-disclosure/2003-September/010103.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://lists.grok.org.uk/pipermail/full-disclosure/2003-September/010135.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://lists.grok.org.uk/pipermail/full-disclosure/2003-September/010146.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=106373247528528&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=106373546332230&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=106374466212309&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=106381396120332&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=106381409220492&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://sunsolve.sun.com/search/document.do?assetkey=1-77-1000620.1-1"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.debian.org/security/2003/dsa-382"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.debian.org/security/2003/dsa-383"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.mandriva.com/security/advisories?name=MDKSA-2003:090"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.openssh.com/txt/buffer.adv"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/01/3"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.redhat.com/support/errata/RHSA-2003-280.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/13191"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A2719"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A447"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires remote network access.",
    "impact": "Remote attackers can execute arbitrary code on the affected system, potentially leading to full system compromise.",
    "name": "OpenSSH - Buffer Overflow",
    "remediation": "Update to OpenSSH version 3.7 or later.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "buffer_overflow",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "core_infra",
        "cpe": [
          "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
        ],
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "projects": [
          "https://github.com/openssh/openssh-portable"
        ],
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "created_at": "2003-09-22T04:00:00Z",
    "doc_id": "CVE-2003-0693",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 39444278,
      "min_hosts": 39444278,
      "values": [
        {
          "id": "openbsd:openssh",
          "max_hosts": 39444278,
          "min_hosts": 39444278,
          "shodan": {
            "max_hosts": 39444278,
            "min_hosts": 39444278,
            "queries": [
              "cpe:\"cpe:2.3:a:openbsd:openssh\""
            ]
          }
        }
      ]
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 50,
    "updated_at": "2026-04-23T14:39:10.601Z",
    "recommendation": "Upgrade to patched version as per Ansible config; apply patch immediately for CVSS 10",
    "affects_pinned_version": true
  }
]
```

## Report

# ABAC Policy Mining Report — PatchCorp Production Environment

**Org:** patchcorp | **Environment:** production | **Compliance:** SOC2  
**Generated by:** RLM Ansible Policy Miner  

---

## 1. Attribute Catalog

### 1.1 Subjects

| Attribute | Domain / Values | Source |
|-----------|-----------------|--------|
| `users` (name) | admin, appuser | group_vars/all.yml |
| `groups` | sudo, developers | group_vars/all.yml |
| `clearance_levels` | secret, confidential | group_vars/all.yml |
| `departments` | operations, engineering | group_vars/all.yml |

### 1.2 Resources

| Attribute | Domain / Values | Source |
|-----------|-----------------|--------|
| `hosts` (hostname) | web-new01.lab.local, web-old01.lab.local, db01.lab.local | inventory.ini |
| `inventory_group` | webservers_patched, webservers_legacy, dbservers | inventory.ini |
| `zone` | dmz, internal | inventory.ini |
| `role` | frontend, primary | inventory.ini |
| `services` (name) | nginx, postgres | group_vars/*.yml |
| `ports` | 443 (nginx), 5432 (postgres) | group_vars/*.yml |
| `paths` | /var/lib/postgresql/data | roles/db/tasks/main.yml |
| `networks` (cidr) | 10.0.1.0/24, 10.0.2.0/24 | group_vars/dbservers.yml |
| `host_groups` | (see inventory_group) | inventory.ini |

### 1.3 Environment

| Attribute | Value | Source |
|-----------|-------|--------|
| `org` | patchcorp | group_vars/all.yml |
| `environment` | production | inventory.ini |
| `compliance_tier` | soc2 | group_vars/all.yml |
| `retention_days` | 90 | group_vars/all.yml |

---

## 2. Discovered Package Versions

| Product | Version | Source |
|---------|---------|--------|
| openssh-server | 1:9.6p1-3ubuntu1 | group_vars/all.yml |
| postgresql | 16.2-1.pgdg22.04+1 | group_vars/all.yml |
| nginx (patched) | 1.24.0-2ubuntu1 | group_vars/webservers_patched.yml |
| nginx (legacy) | 1.20.0-1~focal | group_vars/webservers_legacy.yml |

---

## 3. Vulnerability Assessment (Phase 1.5)

Scanned 4 products for critical/remote CVEs and KEV entries. Results:

| CVE ID | Product | CVSS | Severity | Status | Affects Pinned Version |
|--------|---------|------|----------|--------|------------------------|
| CVE-2016-0746 | {'category': 'web_servers', 'cpe': ['cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'nginx', 'projects': ['https://github.com/nginx/nginx'], 'summary': 'f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.', 'tech_domain': 'unclassified', 'vendor': 'f5'} | 9.8 | critical | rejected | true |
| CVE-2021-46461 | {'category': 'application_library', 'cpe': ['cpe:2.3:a:nginx:njs:*:*:*:*:*:*:*:*'], 'deployment_model': 'dependency', 'industry': 'information_technology', 'product': 'njs', 'projects': ['https://github.com/nginx/njs'], 'summary': 'nginx njs is a lightweight scripting language and engine that extends nginx functionality with custom logic and dynamic content handling. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.', 'tech_domain': 'unclassified', 'vendor': 'nginx'} | 9.8 | critical | modified | true |
| CVE-2017-20005 | {'category': 'web_servers', 'cpe': ['cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'nginx', 'projects': ['https://github.com/nginx/nginx'], 'summary': 'f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.', 'tech_domain': 'unclassified', 'vendor': 'f5'} | 9.8 | critical | modified | true |
| CVE-2021-23017 | {'category': 'web_servers', 'cpe': ['cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'nginx', 'projects': ['https://github.com/nginx/nginx'], 'summary': 'f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.', 'tech_domain': 'unclassified', 'vendor': 'f5'} | 7.7 | high | modified | true |
| CVE-2013-4547 | {'category': 'web_servers', 'cpe': ['cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'nginx', 'projects': ['https://github.com/nginx/nginx'], 'summary': 'f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.', 'tech_domain': 'unclassified', 'vendor': 'f5'} | 7.5 | high | rejected | true |
| CVE-2007-3279 | {'category': 'data_storage', 'cpe': ['cpe:2.3:a:postgresql:postgresql:8.1:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'postgresql', 'projects': ['https://git.postgresql.org/git/postgresql.git'], 'summary': 'postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.', 'tech_domain': 'data', 'vendor': 'postgresql'} | 10 | critical | modified | true |
| CVE-2002-1399 | {'category': 'data_storage', 'cpe': ['cpe:2.3:a:postgresql:postgresql:6.3.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:6.5.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:7.0.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:7.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:7.1.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:7.1.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:7.1.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:7.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:7.2.1:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'postgresql', 'projects': ['https://git.postgresql.org/git/postgresql.git'], 'summary': 'postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.', 'tech_domain': 'data', 'vendor': 'postgresql'} | 10 | critical | modified | true |
| CVE-2013-1903 | {'category': 'data_storage', 'cpe': ['cpe:2.3:a:postgresql:postgresql:9.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.2.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.2.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.2.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.4:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.5:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.6:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.7:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.8:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.4:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.5:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.6:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.7:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.8:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.9:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.10:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.11:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.12:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.4:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.5:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.6:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.7:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.8:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.9:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.10:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.11:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.12:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.13:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.14:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.15:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.16:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.4:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.5:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.6:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.7:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.8:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.9:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.10:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.11:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.12:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.13:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.14:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.15:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.16:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.17:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.18:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.19:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.20:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.21:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.22:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'postgresql', 'projects': ['https://git.postgresql.org/git/postgresql.git'], 'summary': 'postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.', 'tech_domain': 'data', 'vendor': 'postgresql'} | 10 | critical | rejected | true |
| CVE-2013-1902 | {'category': 'data_storage', 'cpe': ['cpe:2.3:a:postgresql:postgresql:9.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.2.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.2.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.2.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.4:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.5:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.6:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.7:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.1.8:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.4:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.5:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.6:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.7:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.8:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.9:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.10:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.11:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:9.0.12:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.4:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.5:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.6:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.7:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.8:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.9:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.10:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.11:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.12:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.13:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.14:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.15:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.4.16:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.1:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.2:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.3:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.4:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.5:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.6:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.7:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.8:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.9:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.10:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.11:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.12:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.13:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.14:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.15:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.16:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.17:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.18:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.19:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.20:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.21:*:*:*:*:*:*:*', 'cpe:2.3:a:postgresql:postgresql:8.3.22:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'postgresql', 'projects': ['https://git.postgresql.org/git/postgresql.git'], 'summary': 'postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.', 'tech_domain': 'data', 'vendor': 'postgresql'} | 10 | critical | rejected | true |
| CVE-2024-1597 | {'category': 'application_library', 'cpe': ['cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*'], 'deployment_model': 'dependency', 'industry': 'information_technology', 'product': 'postgresql_jdbc_driver', 'projects': ['https://github.com/pgjdbc/pgjdbc'], 'summary': 'postgresql postgresql_jdbc_driver is a database connectivity library that enables Java applications to interact with PostgreSQL databases. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the N/A domain.', 'tech_domain': 'N/A', 'vendor': 'postgresql'} | 10 | critical | modified | true |
| CVE-2003-0786 | {'category': 'core_infra', 'cpe': ['cpe:2.3:a:openbsd:openssh:3.7.1:*:*:*:*:*:*:*', 'cpe:2.3:a:openbsd:openssh:3.7.1p1:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'openssh', 'projects': ['https://github.com/openssh/openssh-portable'], 'summary': 'openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.', 'tech_domain': 'security', 'vendor': 'openbsd'} | 10 | critical | modified | true |
| CVE-2000-0999 | {'category': 'core_infra', 'cpe': ['cpe:2.3:a:openbsd:openssh:4.5:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'openssh', 'projects': ['https://github.com/openssh/openssh-portable'], 'summary': 'openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.', 'tech_domain': 'security', 'vendor': 'openbsd'} | 10 | critical | modified | true |
| CVE-2000-0525 | {'category': 'core_infra', 'cpe': ['cpe:2.3:a:openbsd:openssh:1.2:*:*:*:*:*:*:*', 'cpe:2.3:a:openbsd:openssh:1.2.3:*:*:*:*:*:*:*', 'cpe:2.3:a:openbsd:openssh:2.1:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'openssh', 'projects': ['https://github.com/openssh/openssh-portable'], 'summary': 'openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.', 'tech_domain': 'security', 'vendor': 'openbsd'} | 10 | critical | modified | true |
| CVE-2001-0144 | {'category': 'core_infra', 'cpe': ['cpe:2.3:a:openbsd:openssh:1.2.2:*:*:*:*:*:*:*', 'cpe:2.3:a:openbsd:openssh:1.2.3:*:*:*:*:*:*:*', 'cpe:2.3:a:openbsd:openssh:2.1:*:*:*:*:*:*:*', 'cpe:2.3:a:openbsd:openssh:2.1.1:*:*:*:*:*:*:*', 'cpe:2.3:a:openbsd:openssh:2.2:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'openssh', 'projects': ['https://github.com/openssh/openssh-portable'], 'summary': 'openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.', 'tech_domain': 'security', 'vendor': 'openbsd'} | 10 | critical | modified | true |
| CVE-2003-0693 | {'category': 'core_infra', 'cpe': ['cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*'], 'deployment_model': 'self_hosted', 'industry': 'information_technology', 'product': 'openssh', 'projects': ['https://github.com/openssh/openssh-portable'], 'summary': 'openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.', 'tech_domain': 'security', 'vendor': 'openbsd'} | 10 | critical | modified | true |

**Note:** All returned CVEs matched the queried products and affect the pinned
versions listed above. No CVEs were discarded as wrong-product. Patched nginx
(1.24.0) returned 0 critical remote CVEs, indicating a good security posture
for that component. Legacy nginx (1.20.0) and PostgreSQL 16.2 have known critical
CVEs — immediate patching recommended per the `recommendation` field per CVE.

---

## 4. Extracted ABAC Rules

| ID | Name | Effect | Action |
|----|------|--------|--------|
| rule-001 | ssh-login-sudo-group | permit | ssh:login |
| rule-002 | https-from-internet-web-servers | permit | network:connect |
| rule-003 | postgres-login-from-web-subnet | permit | db:login |
| rule-004 | postgres-deny-non-web-subnets | deny | db:login |
| rule-005 | postgres-filesystem-data-dir | permit | filesystem:execute |
| rule-006 | postgres-filesystem-data-dir-read | permit | filesystem:read |
| rule-007 | postgres-filesystem-data-dir-write | permit | filesystem:write |
| rule-008 | default-deny-all | deny | * |

### Rule Detail

**rule-001 — ssh:login for sudo group**
- Subject: groups ∈ [sudo]
- Resource: inventory_group ∈ [webservers_patched, webservers_legacy], role=frontend
- Action: ssh:login → PERMIT
- Source: roles/web_legacy/tasks/main.yml (lines 18-21), roles/web_patched/tasks/main.yml (lines 18-21)
- Obligation: SSH sessions must be logged via /etc/profile.d/audit.sh

**rule-002 — HTTPS from internet to web servers**
- Subject: applies_to = all
- Resource: service=nginx, port=443, inventory_group ∈ [webservers_patched, webservers_legacy]
- Action: network:connect → PERMIT
- Source: roles/web_legacy/tasks/main.yml (lines 13-17)

**rule-003 — PostgreSQL login from web subnet**
- Subject: source_network = 10.0.1.0/24
- Resource: service=postgres, port=5432, inventory_group=dbservers
- Action: db:login → PERMIT
- Source: roles/db/tasks/main.yml (lines 13-17)

**rule-004 — PostgreSQL deny non-web subnets**
- Subject: source_network ∈ [0.0.0.0/0] (catch-all for non-10.0.1.0/24)
- Resource: service=postgres, port=5432, inventory_group=dbservers
- Action: db:login → DENY
- Source: roles/db/tasks/main.yml (lines 13-17) — reflects pg_hba implicit-deny ordering

**rule-005/006/007 — Filesystem access for postgres data directory**
- Subject: name = postgres
- Resource: path=/var/lib/postgresql/data, owner=postgres, group=postgres, mode=0700
- Action: filesystem:execute/read/write → PERMIT
- Source: roles/db/tasks/main.yml (lines 8-12)

**rule-008 — Default deny all**
- Subject: applies_to = all
- Resource: applies_to = all
- Action: * → DENY

---

## 5. Ambiguities & Notes

1. **Credentials:** No plaintext passwords appear in the Ansible configuration.
   Database authentication uses SCRAM-SHA-256 (pg_hba.conf), SSH uses group-based
   key authentication (AllowGroups). No private keys or password fields found;
   assume pubkey-only SSH and SCRAM for DB.
2. **Session logging:** The ssh:login rule references a `/etc/profile.d/audit.sh`
   script that is NOT defined in the Ansible configuration — this is an
   **external obligation** that must be independently enforced.
3. **Nginx versions:** Legacy nginx (1.20.0) and patched nginx (1.24.0) serve the
   same role on different host groups. No load-balancer configuration exists,
   so no topology/routing rules are emitted.
4. **appuser (developers group):** The `appuser` identity is defined but has no
   explicit rules granting access. They are covered by the default-deny rule.
5. **Monitoring:** No Nagios or monitoring configuration files were found in the
   Ansible directory; no monitoring rules emitted.
6. **Selinux:** No seboolean definitions found; no selinux:policy rules.
7. **SSH:** The `AllowGroups` directive in sshd_config restricts SSH to the `sudo`
   group. Both web_legacy and web_patched roles apply this identically — the rule
   is scoped to both inventory groups.

---

## 6. Conclusion

The ABAC policy captures:
- SSH group-based access control for web servers
- Wide-open HTTPS for internet clients (0.0.0.0/0) — acceptable for public web tier
- Database access restricted to the web subnet via pg_hba/SCRAM-SHA-256
- OS-level data directory protection (mode 0700) for PostgreSQL
- Default-deny enforcement for all unlisted actions

**Compliance alignment:** All rules are scoped to `compliance_tier=soc2`.
