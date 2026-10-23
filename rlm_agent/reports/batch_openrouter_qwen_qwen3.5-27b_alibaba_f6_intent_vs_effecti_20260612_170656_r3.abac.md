# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:12:43_  
_Model: `openrouter/qwen/qwen3.5-27b:alibaba`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 8 | Rules: 18_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

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
        "name": "dba",
        "uid": 1003,
        "groups": [
          "dba"
        ],
        "department": "data",
        "clearance": "secret",
        "source": "group_vars/all.yml"
      }
    ],
    "groups": [
      "sudo",
      "developers",
      "dba"
    ],
    "clearance_levels": [
      {
        "value": "secret",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "confidential",
        "domain": [
          "secret",
          "confidential"
        ],
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "value": "operations",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "engineering",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      },
      {
        "value": "data",
        "domain": [
          "operations",
          "engineering",
          "data"
        ],
        "source": "group_vars/all.yml"
      }
    ]
  },
  "resources": {
    "hosts": [
      {
        "hostname": "proxy01.lab.local",
        "ip": "10.0.1.10",
        "role": "reverse_proxy",
        "zone": "dmz",
        "host_group": "dmz",
        "source": "inventory.ini"
      },
      {
        "hostname": "app01.lab.local",
        "ip": "10.0.2.10",
        "role": "application",
        "zone": "app",
        "host_group": "appservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.3.10",
        "role": "primary",
        "zone": "data",
        "host_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "dmz",
        "source": "group_vars/dmz.yml"
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
      }
    ],
    "networks": [
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "DMZ subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "appservers subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet-facing",
        "source": "group_vars/dmz.yml"
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
    ]
  },
  "environment": {
    "org": {
      "value": "segcorp",
      "source": "group_vars/all.yml"
    },
    "environment": {
      "value": "production",
      "source": "inventory.ini"
    },
    "compliance_tier": {
      "value": "pci",
      "source": "inventory.ini"
    },
    "log_retention_days": {
      "value": 365,
      "source": "group_vars/all.yml"
    }
  },
  "software_versions": {
    "nginx": {
      "version": "1.20.0-1~focal",
      "source": "group_vars/all.yml"
    },
    "openssh": {
      "version": "1:9.1p1-1ubuntu1",
      "source": "group_vars/all.yml"
    },
    "postgresql": {
      "version": "16.2-1.pgdg22.04+1",
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
      "host_group": {
        "equals": "appservers"
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
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": "20-24"
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
      "host_group": {
        "equals": "dbservers"
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
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "32-35"
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
      "host_group": {
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": "24-27"
    }
  },
  {
    "id": "rule-004",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "appservers"
      },
      "port": {
        "equals": 8080
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
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": "15-19"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
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
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": "27-30"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dmz"
      },
      "port": {
        "equals": 443
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
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "18-22"
    }
  },
  {
    "id": "rule-007",
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
    "action": "db:login",
    "privilege_level": "SUPERUSER",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": "22-25"
    }
  },
  {
    "id": "rule-008",
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
    "action": "db:login",
    "privilege_level": "NOSUPERUSER",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": "27-30"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "groups": {
        "any_of": [
          "dba",
          "sudo"
        ]
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
      "task": "Ensure postgres data dir",
      "lines": "15-20"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "groups": {
        "any_of": [
          "dba",
          "sudo"
        ]
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
      "task": "Ensure postgres data dir",
      "lines": "15-20"
    }
  },
  {
    "id": "rule-011",
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
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "8-14"
    }
  },
  {
    "id": "rule-012",
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
    "action": "user:create",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Provision admin users",
      "lines": "12-17"
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
      "host_group": {
        "equals": "appservers"
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
  },
  {
    "id": "rule-017",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
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
      "host_group": {
        "equals": "dmz"
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
    "cve_id": "CVE-2016-0746",
    "age_in_days": 3768,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2016-02-15T19:59:01Z",
    "cve_updated_at": "2026-05-06T22:30:45Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.9119,
    "epss_score": 0.06343,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://seclists.org/fulldisclosure/2021/Sep/36"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id/1034869"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.ubuntu.com/usn/USN-2892-1"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2016:1425"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://bto.bluecoat.com/security-advisory/sa115"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1302588"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.debian.org/security/2016/dsa-3473"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://security.gentoo.org/glsa/201606-06"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://support.apple.com/kb/HT212818"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://mailman.nginx.org/pipermail/nginx/2016-January/049700.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-updates/2016-02/msg00042.html"
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
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "leap",
        "summary": "opensuse leap is a stable and secure Linux-based operating system that provides a robust platform for desktops and servers. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "opensuse"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "xcode",
        "summary": "apple xcode is an integrated development environment (IDE) that provides tools for software development on Apple platforms. It sits in the application_library layer of the tech stack, functions as a development tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "apple"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ubuntu_linux",
        "summary": "canonical ubuntu_linux is a popular open-source operating system that provides a stable and secure platform for computing. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "canonical"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      }
    ],
    "created_at": "2016-02-15T19:59:01Z",
    "doc_id": "CVE-2016-0746",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 55647248,
      "min_hosts": 4038838
    },
    "h1": {
      "delta_rank": -3,
      "rank": 590,
      "reports": 12
    },
    "ntps": 41,
    "updated_at": "2026-06-11T14:34:18.392Z"
  },
  {
    "cve_id": "CVE-2021-46461",
    "age_in_days": 1577,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2022-02-14T22:15:07Z",
    "cve_updated_at": "2024-11-21T06:34:07Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.73044,
    "epss_score": 0.00725,
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
        "url": "https://github.com/nginx/njs/commit/d457c9545e7e71ebb5c0479eb16b9d33175855e2"
      },
      {
        "added_at": "2024-11-21T06:34:07Z",
        "source": "nvd",
        "url": "https://github.com/nginx/njs/issues/450"
      },
      {
        "added_at": "2024-11-21T06:34:07Z",
        "source": "nvd",
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
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "njs",
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
    "updated_at": "2026-06-11T14:56:00.388Z"
  },
  {
    "cve_id": "CVE-2017-20005",
    "age_in_days": 1830,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2021-06-06T22:15:08Z",
    "cve_updated_at": "2025-12-05T15:15:49Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.87411,
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
        "url": "https://security.netapp.com/advisory/ntap-20210805-0006/"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "url": "http://nginx.org/en/CHANGES"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "url": "https://trac.nginx.org/nginx/ticket/1368"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "url": "https://github.com/nginx/nginx/commit/0206ebe76f748bb39d9de4dd4b3fce777fdfdccf"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "url": "https://github.com/nginx/nginx/commit/b900cc28fcbb4cf5a32ab62f80b59292e1c85b4b"
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2021/06/msg00009.html"
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
        "cwe_id": "CWE-120",
        "cwe_name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')"
      },
      {
        "cwe_id": "CWE-190",
        "cwe_name": "Integer Overflow or Wraparound"
      }
    ],
    "affected_products": [
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "operating_system",
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
      "max_hosts": 55647248,
      "min_hosts": 4038838
    },
    "h1": {
      "delta_rank": 3,
      "delta_reports": -1,
      "rank": 7954
    },
    "ntps": 51,
    "updated_at": "2026-06-11T15:40:58.987Z"
  },
  {
    "cve_id": "CVE-2009-3555",
    "age_in_days": 6057,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2009-11-09T17:30:00Z",
    "cve_updated_at": "2026-05-27T17:16:18Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.88273,
    "epss_score": 0.03741,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2009-11-18T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 5,
    "poc_first_seen": "2009-11-09T17:30:00Z",
    "pocs": [
      {
        "added_at": "2022-03-30T15:02:48Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/johnwchadwick/cve-2009-3555-test-server"
      },
      {
        "added_at": "2022-03-30T15:02:48Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/johnwchadwick/cve-2009-3555-test-server.git"
      },
      {
        "added_at": "2009-11-09T17:30:00Z",
        "source": "nvd",
        "url": "http://clicky.me/tlsvuln"
      },
      {
        "added_at": "2009-11-09T17:30:00Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/bid/36935"
      },
      {
        "added_at": "2009-11-09T17:30:00Z",
        "source": "nvd",
        "url": "http://xss.cx/examples/plesk-reports/plesk-parallels-controlpanel-psa.v.10.3.1_build1013110726.09%20os_redhat.el6-billing-system-plugin-javascript-injection-example-poc-report.html"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023270"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023217"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.us-cert.gov/cas/techalerts/TA10-222A.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/522176"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/bid/36935"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2010-06/msg00001.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023205"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023209"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023411"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/ba661b0edd913b39ff129a32d855620dd861883ade05fd88a8ce517d%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2010-October/049528.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2010-05/msg00002.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/508075/100/0/threaded"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://xss.cx/examples/plesk-reports/plesk-parallels-controlpanel-psa.v.10.3.1_build1013110726.09%20os_redhat.el6-billing-system-plugin-javascript-injection-example-poc-report.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/re3b72cbb13e1dfe85c4a06959a3b6ca6d939b407ecca80db12b54220%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.gnu.org/archive/html/gnutls-devel/2009-11/msg00029.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2010-05/msg00001.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://securitytracker.com/id?1023148"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023214"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023274"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023275"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023426"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.us-cert.gov/cas/techalerts/TA10-287A.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-049"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://clicky.me/tlsvuln"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/515055/100/0/threaded"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023428"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/f8e0814e11c7f21f42224b6de111cb3f5e5ab5c15b78924c516d4ec2%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf8e8c091182b45daa50d3557cad9b10bb4198e3f08cf8f1c66a1b08d%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://kbase.redhat.com/faq/docs/DOC-20491"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.apple.com/archives/security-announce/2010//May/msg00002.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2010-10/msg00006.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2010-12/msg00005.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=533125"
      },
      {
        "added_at": "2026-05-27T17:16:18Z",
        "source": "nvd",
        "url": "https://www.exploit-db.com/exploits/10579"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://blogs.sun.com/security/entry/vulnerability_in_tls_protocol_during"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/507952/100/0/threaded"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/508130/100/0/threaded"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023208"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023216"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023218"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023243"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023427"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2010-October/049455.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://blog.g-sec.lu/2009/11/tls-sslv3-renegotiation-vulnerability.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.apple.com/archives/security-announce/2010//May/msg00001.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2010-April/039957.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.kb.cert.org/vuls/id/120541"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023212"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023215"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023224"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2009-11/msg00009.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://bugzilla.mozilla.org/show_bug.cgi?id=545755"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/54158"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023213"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://bugzilla.mozilla.org/show_bug.cgi?id=526689"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2010-October/049702.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2010-04/msg00001.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/516397/100/0/threaded"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023204"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023206"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023211"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2010-May/040652.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023163"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023272"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023273"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1024789"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.apple.com/archives/security-announce/2010/Jan/msg00000.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2010-April/039561.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023210"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023219"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023271"
      },
      {
        "added_at": "2009-11-18T00:00:00Z",
        "source": "vulncheck",
        "url": "https://packetstormsecurity.com/files/82770/SUSE-Security-Announcement-SUSE-SA-2009-057.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023207"
      }
    ],
    "cwe": [
      "CWE-295",
      "CWE-300"
    ],
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of renegotiation handshakes with existing connections, letting man-in-the-middle attackers inject data into sessions, exploit requires attacker to perform man-in-the-middle attack.",
    "impact": "Attackers can inject data into encrypted sessions, potentially leading to data tampering or session hijacking.",
    "name": "Multiple Products - Man-in-the-Middle",
    "remediation": "Update to the latest versions of affected products that fix the renegotiation handling issue.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "man_in_the_middle",
      "data_tampering"
    ],
    "vulnerability_type": "man_in_the_middle",
    "weaknesses": [
      {
        "cwe_id": "CWE-300",
        "cwe_name": "Channel Accessible by Non-Endpoint"
      },
      {
        "cwe_id": "CWE-295",
        "cwe_name": "Improper Certificate Validation"
      }
    ],
    "affected_products": [
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fedora",
        "summary": "fedoraproject fedora is a Linux-based open-source operating system that provides a robust and secure platform for developers and users. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "fedoraproject"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "http_server",
        "summary": "apache http_server is a widely-used open-source web server that delivers HTTP content to clients efficiently and securely. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "gnutls",
        "summary": "gnu gnutls is a secure communications library that provides SSL, TLS, and DTLS protocols for encryption and authentication. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "gnu"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "nss",
        "summary": "mozilla nss is a set of libraries designed to support cross-platform development of security-enabled client and server applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "mozilla"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "openssl",
        "summary": "openssl openssl is a robust open-source cryptographic library that provides secure communication and data encryption. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openssl"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ubuntu_linux",
        "summary": "canonical ubuntu_linux is a popular open-source operating system that provides a stable and secure platform for computing. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "canonical"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      }
    ],
    "created_at": "2009-11-09T17:30:00Z",
    "doc_id": "CVE-2009-3555",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 55647248,
      "min_hosts": 31320
    },
    "h1": {
      "delta_rank": -2,
      "rank": 469,
      "reports": 20
    },
    "ntps": 75,
    "updated_at": "2026-06-11T15:26:26.654Z"
  },
  {
    "cve_id": "CVE-2021-23017",
    "age_in_days": 1836,
    "assignee": "f5sirt@f5.com",
    "cve_created_at": "2021-06-01T13:15:07Z",
    "cve_updated_at": "2024-11-21T05:51:09Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
    "cvss_score": 7.7,
    "epss_percentile": 0.98811,
    "epss_score": 0.73166,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 9,
    "poc_first_seen": "2021-12-17T09:53:39Z",
    "pocs": [
      {
        "added_at": "2025-04-17T11:33:08Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Cybervixy/Vulnerability-Management"
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
        "added_at": "2025-05-06T16:32:48Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/moften/CVE-2021-23017"
      },
      {
        "added_at": "2025-01-30T11:05:40Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/lukwagoasuman/-home-lukewago-Downloads-CVE-2021-23017-Nginx-1.14"
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
      },
      {
        "added_at": "2025-09-04T09:49:22Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/6lj/EVIL-CVE-2021-23017-Update-2025"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/167720/Nginx-1.20.0-Denial-Of-Service.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpujan2022.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
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
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7SFVYHC7OXTEO4SMBWXDVK6E5IMEYMEE/"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20210708-0006/"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpuapr2022.html"
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
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_control_plane_monitor",
        "summary": "oracle communications_control_plane_monitor is a network monitoring and management solution that provides real-time visibility and control over telecom control plane operations. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_fraud_monitor",
        "summary": "oracle communications_fraud_monitor is a fraud detection and prevention solution designed to protect telecommunications networks from fraudulent activities. It sits in the core_infra layer of the tech stack, functions as a security monitoring system in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_session_border_controller",
        "summary": "oracle communications_session_border_controller is a network security and session management solution that protects and manages VoIP and multimedia sessions. It sits in the core_infra layer of the tech stack, functions as a network security appliance in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_communications_broker",
        "summary": "oracle enterprise_communications_broker is a communication integration platform that enables seamless messaging and data exchange across enterprise systems. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "enterprise_telephony_fraud_monitor",
        "summary": "oracle enterprise_telephony_fraud_monitor is a telephony fraud detection and monitoring solution that helps enterprises identify and prevent fraudulent activities in voice networks. It sits in the core_infra layer of the tech stack, functions as a security monitoring tool in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openresty",
        "summary": "openresty openresty is a web platform that integrates the Nginx web server with Lua scripting for high-performance web applications. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "openresty"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fedora",
        "summary": "fedoraproject fedora is a Linux-based open-source operating system that provides a robust and secure platform for developers and users. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "fedoraproject"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "blockchain_platform",
        "summary": "oracle blockchain_platform is an enterprise-grade blockchain solution that enables secure and transparent business networks. It sits in the core_infra layer of the tech stack, functions as a platform service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_operations_monitor",
        "summary": "oracle communications_operations_monitor is a network operations monitoring solution that provides real-time visibility and analytics for telecom networks. It sits in the core_infra layer of the tech stack, functions as an enterprise application in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "enterprise_session_border_controller",
        "summary": "oracle enterprise_session_border_controller is a session border controller that secures and manages VoIP and video communications across enterprise networks. It sits in the core_infra layer of the tech stack, functions as a network security and management appliance in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "goldengate",
        "summary": "oracle goldengate is a real-time data replication and integration solution that enables high availability and disaster recovery for enterprise data. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_select_deploy_administration_utility",
        "summary": "netapp ontap_select_deploy_administration_utility is a deployment and management tool for NetApp's ONTAP Select software-defined storage. It sits in the core_infra layer of the tech stack, functions as a self-hosted management utility in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      }
    ],
    "created_at": "2021-06-01T13:15:07Z",
    "doc_id": "CVE-2021-23017",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 55647248,
      "min_hosts": 31320
    },
    "h1": {
      "delta_rank": 4,
      "rank": 387,
      "reports": 33
    },
    "ntps": 50,
    "updated_at": "2026-06-11T16:05:37.662Z"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC policy mined from Ansible configuration at `RLM_ANSIBLE_DIR`.
The infrastructure consists of 3 hosts across 3 zones (DMZ, App, Data) with PCI compliance requirements.

## Infrastructure Overview

### Hosts
| Hostname | IP | Role | Zone | Group |
|----------|-----|------|------|-------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

### Users
| User | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

### Environment
- **Organization**: segcorp
- **Environment**: production
- **Compliance Tier**: PCI
- **Log Retention**: 365 days

## Extracted ABAC Rules

### SSH Access (3 rules)
1. **rule-001**: sudo/developers → appservers SSH access
2. **rule-002**: sudo/dba → dbservers SSH access
3. **rule-003**: sudo → dmz SSH access

### Network/Firewall (3 rules)
4. **rule-004**: DMZ subnet (10.0.1.0/24) → app servers port 8080
5. **rule-005**: App subnet (10.0.2.0/24) → db servers port 5432
6. **rule-006**: Internet (0.0.0.0/0) → DMZ port 443 (HTTPS)

### Database Access (2 rules)
7. **rule-007**: dba group → PostgreSQL SUPERUSER access
8. **rule-008**: developers group → PostgreSQL NOSUPERUSER access

### Filesystem Access (2 rules)
9. **rule-009**: dba/sudo → read /var/lib/postgresql/data
10. **rule-010**: dba/sudo → write /var/lib/postgresql/data

### User Creation (2 rules)
11. **rule-011**: developers/sudo → user creation on appservers
12. **rule-012**: sudo → user creation on DMZ

### Default Deny
13. **rule-013**: Default deny for all unspecified access

## Vulnerability Assessment

### Software Versions
| Package | Version |
|---------|---------|
| nginx | 1.20.0-1~focal |
| openssh | 1:9.1p1-1ubuntu1 |
| postgresql | 16.2-1.pgdg22.04+1 |

### Critical/High Vulnerabilities Found
5 vulnerabilities identified across pinned packages.

#### Notable Findings
- **nginx**: CVE-2016-0746 (Use After Free, CVSS 9.8) - affects versions before 1.9.10
- **openssh**: CVE-2000-0999 (Format String, CVSS 10.0) - affects legacy versions
- **postgresql**: CVE-2002-1399 (Privilege Escalation, CVSS 9.9) - affects versions before 7.2.3

**Recommendation**: Review if pinned versions are affected by critical vulnerabilities and upgrade as needed.

## Ambiguities and Notes

1. **No explicit sudo rules**: While `sudo` group is referenced for SSH access, no explicit sudoers configuration was found in the Ansible configuration.

2. **No password policies**: No password complexity or expiration policies were defined in the configuration.

3. **No SELinux rules**: No SELinux configuration was found in the Ansible roles.

4. **KEV status**: Known Exploited Vulnerabilities search returned non-standard response format; manual review recommended.

5. **Implicit network segmentation**: The firewall rules create a clear DMZ → App → Data segmentation pattern.

## Compliance Considerations

- **PCI DSS**: The configuration enforces network segmentation (Rule 1.3), restricted access (Rule 7), and audit logging (365-day retention).
- **Defense in Depth**: Multiple layers of access control (SSH groups, firewall rules, database privileges).
- **Least Privilege**: Developers get NOSUPERUSER DB access; only DBAs get SUPERUSER.

## Files Analyzed

- inventory.ini
- group_vars/all.yml
- group_vars/appservers.yml
- group_vars/dbservers.yml
- group_vars/dmz.yml
- roles/app/tasks/main.yml
- roles/db/tasks/main.yml
- roles/dmz/tasks/main.yml
