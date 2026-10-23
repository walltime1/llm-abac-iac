# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 17:08:07_  
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
        "level": "secret",
        "source": "group_vars/all.yml"
      },
      {
        "level": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "departments": [
      {
        "name": "operations",
        "source": "group_vars/all.yml"
      },
      {
        "name": "engineering",
        "source": "group_vars/all.yml"
      },
      {
        "name": "data",
        "source": "group_vars/all.yml"
      }
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
        "name": "ssh",
        "port": 22,
        "protocol": "tcp",
        "host_group": "all",
        "source": "group_vars/all.yml"
      },
      {
        "name": "http",
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
        "source": "inventory.ini"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "web_subnet",
        "source": "inventory.ini"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "app_subnet",
        "source": "inventory.ini"
      },
      {
        "cidr": "10.0.3.0/24",
        "zone": "data",
        "label": "db_subnet",
        "source": "inventory.ini"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "any",
        "source": "group_vars/bastion.yml"
      }
    ]
  },
  "environment": {
    "org": {
      "value": "chaincorp",
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
    "default_log_retention_days": {
      "value": 365,
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
          "dba"
        ]
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
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
      "hostname": {
        "equals": "web01.lab.local"
      },
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
      "lines": "20-24"
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
      "hostname": {
        "equals": "app01.lab.local"
      },
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
      "hostname": {
        "equals": "db01.lab.local"
      },
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
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo and dba groups",
      "lines": "24-28"
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
      "hostname": {
        "equals": "bastion01.lab.local"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
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
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      }
    },
    "action": "db:login",
    "privilege": "SUPERUSER",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
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
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "bastion01.lab.local"
      },
      "service": {
        "equals": "ssh"
      },
      "port": 22
    },
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "source": {
      "file": "roles/bastion/tasks/main.yml",
      "task": "Firewall — allow SSH from internet",
      "lines": "8-13"
    }
  },
  {
    "id": "rule-008",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.0.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "web01.lab.local"
      },
      "service": {
        "equals": "http"
      },
      "port": 80
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
      "task": "Firewall — allow HTTP from bastion subnet",
      "lines": "14-19"
    }
  },
  {
    "id": "rule-009",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "service": {
        "equals": "app"
      },
      "port": 8080
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
      "task": "Firewall — allow app port from web subnet",
      "lines": "22-27"
    }
  },
  {
    "id": "rule-010",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": 5432
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
      "lines": "20-23"
    }
  },
  {
    "id": "rule-011",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
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
        "equals": "ssh"
      },
      "port": 22
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
        "equals": "http"
      },
      "port": 80
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
        "equals": "app"
      },
      "port": 8080
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
      "port": 5432
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
    "age_in_days": 9313,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2000-12-11T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.62223,
    "epss_score": 0.00418,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
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
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "created_at": "2000-12-11T05:00:00Z",
    "doc_id": "CVE-2000-0999",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 26254055,
      "min_hosts": 26254055
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 48,
    "updated_at": "2026-06-11T14:05:10.453Z",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2000-0525",
    "age_in_days": 9499,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2000-06-08T04:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.72664,
    "epss_score": 0.00709,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
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
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://archives.neohapsis.com/archives/bugtraq/2000-06/0065.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.openbsd.org/errata.html#uselogin"
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
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "created_at": "2000-06-08T04:00:00Z",
    "doc_id": "CVE-2000-0525",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 26254055,
      "min_hosts": 26254055
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 48,
    "updated_at": "2026-06-11T14:02:36.113Z",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2003-0693",
    "age_in_days": 8298,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2003-09-22T04:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.96475,
    "epss_score": 0.26823,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
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
        "url": "http://www.debian.org/security/2003/dsa-383"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.openssh.com/txt/buffer.adv"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.redhat.com/support/errata/RHSA-2003-280.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A2719"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
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
        "url": "http://marc.info/?l=bugtraq&m=106381409220492&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=106381396120332&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://sunsolve.sun.com/search/document.do?assetkey=1-77-1000620.1-1"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.mandriva.com/security/advisories?name=MDKSA-2003:090"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/13191"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A447"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.cert.org/advisories/CA-2003-24.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://lists.grok.org.uk/pipermail/full-disclosure/2003-September/010135.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.debian.org/security/2003/dsa-382"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/01/3"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://lists.grok.org.uk/pipermail/full-disclosure/2003-September/010146.html"
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
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "created_at": "2003-09-22T04:00:00Z",
    "doc_id": "CVE-2003-0693",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 26254055,
      "min_hosts": 26254055
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 50,
    "updated_at": "2026-06-11T14:34:01.312Z",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2003-0786",
    "age_in_days": 8242,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2003-11-17T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.87174,
    "epss_score": 0.03141,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
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
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "created_at": "2003-11-17T05:00:00Z",
    "doc_id": "CVE-2003-0786",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 26254055,
      "min_hosts": 26254055
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 48,
    "updated_at": "2026-06-11T14:34:07.493Z",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2001-0144",
    "age_in_days": 9222,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2001-03-12T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.98035,
    "epss_score": 0.53307,
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
        "url": "http://www.osvdb.org/795"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/6083"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://razor.bindview.com/publish/advisories/adv_ssh1crc.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.cert.org/advisories/CA-2001-35.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
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
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "core_infra",
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
      "max_hosts": 26254055,
      "min_hosts": 26254055
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 64,
    "updated_at": "2026-06-11T14:04:03.244Z",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade openssh to latest patched version"
  },
  {
    "cve_id": "CVE-2023-38408",
    "age_in_days": 1057,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2023-07-20T03:15:10Z",
    "cve_updated_at": "2024-11-21T08:13:30Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.98468,
    "epss_score": 0.64352,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2023-07-26T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 22,
    "poc_first_seen": "2023-07-20T03:15:10Z",
    "pocs": [
      {
        "added_at": "2024-10-17T13:03:42Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/fazilbaig1/cve_2023_38408_scanner"
      },
      {
        "added_at": "2023-07-20T03:15:10Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/173661/OpenSSH-Forwarded-SSH-Agent-Remote-Code-Execution.html"
      },
      {
        "added_at": "2026-02-10T19:10:40Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/jakovtodorovic/openSSH-agent-forwarding-vulnerability-analysis-CVE-2023-38408"
      },
      {
        "added_at": "2026-01-24T09:27:16Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/xitexploiter96-dot/CVE-2023-38408"
      },
      {
        "added_at": "2025-07-16T18:19:24Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Adel2411/cve-2023-38408"
      },
      {
        "added_at": "2025-04-19T20:09:15Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/TX-One/CVE-2023-38408.git"
      },
      {
        "added_at": "2024-07-17T02:00:31Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/mrtacojr/CVE-2023-38408"
      },
      {
        "added_at": "2024-01-07T03:03:06Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/classic130/CVE-2023-38408"
      },
      {
        "added_at": "2023-11-09T04:34:39Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/LucasPDiniz/CVE-2023-38408"
      },
      {
        "added_at": "2023-07-20T03:15:10Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2023/07/20/1"
      },
      {
        "added_at": "2025-04-19T20:09:15Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:TX-One/CVE-2023-38408.git"
      },
      {
        "added_at": "2025-04-19T20:09:15Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/TX-One/CVE-2023-38408"
      },
      {
        "added_at": "2024-12-15T11:30:46Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Nick-Morbid/cve-2023-38408"
      },
      {
        "added_at": "2023-11-09T04:34:39Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/LucasPDiniz/CVE-2023-38408.git"
      },
      {
        "added_at": "2023-08-09T19:56:07Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:kali-mx/CVE-2023-38408.git"
      },
      {
        "added_at": "2023-08-09T19:56:07Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/kali-mx/CVE-2023-38408.git"
      },
      {
        "added_at": "2026-01-24T09:27:16Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/xitexploiter96-dot/CVE-2023-38408.git"
      },
      {
        "added_at": "2024-02-16T18:20:12Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/wxrdnx/CVE-2023-38408"
      },
      {
        "added_at": "2023-11-09T04:34:39Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:LucasPDiniz/CVE-2023-38408.git"
      },
      {
        "added_at": "2023-08-09T19:56:07Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/kali-mx/CVE-2023-38408"
      },
      {
        "added_at": "2023-07-20T03:15:10Z",
        "source": "nvd",
        "url": "https://www.qualys.com/2023/07/19/cve-2023-38408/rce-openssh-forwarded-ssh-agent.txt"
      },
      {
        "added_at": "2026-04-12T14:08:59Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/nonosticisiguzo-command/nmap-scan-results"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://github.com/openbsd/src/commit/7bc29a9d5cd697290aa056e94ecee6253d3425f8"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://github.com/openbsd/src/commit/f8f5a6b003981bb824329dc987d101977beda7ca"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://news.ycombinator.com/item?id=36790196"
      },
      {
        "added_at": "2025-03-12T00:00:00Z",
        "source": "vulncheck",
        "url": "https://content.kaspersky-labs.com/fm/site-editor/33/3318ec849851138088d24f26d236f469/source/irreport.pdf"
      },
      {
        "added_at": "2024-07-01T00:00:00Z",
        "source": "vulncheck",
        "url": "https://thorcert.notion.site/TTPs-11-Operation-An-Octopus-d875862055ca4b7b815b5e496b219671"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2023/08/msg00021.html"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CEBTJJINE2I3FHAUKKNQWMFGYMLSMWKQ/"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://support.apple.com/kb/HT213940"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/173661/OpenSSH-Forwarded-SSH-Agent-Remote-Code-Execution.html"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2023/07/20/1"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://blog.qualys.com/vulnerabilities-threat-research/2023/07/19/cve-2023-38408-remote-code-execution-in-opensshs-forwarded-ssh-agent"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://security.gentoo.org/glsa/202307-01"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2023/09/22/11"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2023/09/22/9"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20230803-0010/"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://github.com/openbsd/src/commit/f03a4faa55c4ce0818324701dadbf91988d7351d"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://www.openssh.com/security.html"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://www.openssh.com/txt/release-9.3p2"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2023/07/20/2"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://www.qualys.com/2023/07/19/cve-2023-38408/rce-openssh-forwarded-ssh-agent.txt"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://www.vicarius.io/vsociety/posts/exploring-opensshs-agent-forwarding-rce-cve-2023-38408"
      },
      {
        "added_at": "2023-07-26T00:00:00Z",
        "source": "vulncheck",
        "url": "https://sosintel.co.uk/flash-alert-cves-of-note-being-exploited-in-the-wild/"
      },
      {
        "added_at": "2024-11-21T08:13:30Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RAXVQS6ZYTULFAK3TEJHRLKZALJS3AOU/"
      }
    ],
    "cwe": [
      "CWE-428"
    ],
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding agent, exploit requires agent forwarding to attacker-controlled system.",
    "impact": "Attackers can execute arbitrary code remotely by exploiting the search path issue in forwarded ssh-agent, potentially leading to full system compromise.",
    "name": "OpenSSH - Command Injection",
    "remediation": "Update to OpenSSH 9.3p2 or later.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "command_injection",
    "weaknesses": [
      {
        "cwe_id": "CWE-428",
        "cwe_name": "Unquoted Search Path or Element"
      }
    ],
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fedora",
        "summary": "fedoraproject fedora is a Linux-based open-source operating system that provides a robust and secure platform for developers and users. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "fedoraproject"
      }
    ],
    "created_at": "2023-07-20T03:15:10Z",
    "doc_id": "CVE-2023-38408",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 26254055,
      "min_hosts": 31320
    },
    "h1": {
      "delta_rank": -3,
      "rank": 677,
      "reports": 9
    },
    "ntps": 79,
    "updated_at": "2026-06-11T15:59:38.306Z",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade openssh - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2024-6387",
    "age_in_days": 710,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2024-07-01T13:15:06Z",
    "cve_updated_at": "2026-05-12T12:17:20Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 8.1,
    "epss_percentile": 0.98529,
    "epss_score": 0.65792,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2024-07-17T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 100,
    "poc_first_seen": "2024-07-01T13:15:06Z",
    "pocs": [
      {
        "added_at": "2024-07-03T06:08:32Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/sxlmnwb/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T14:09:08Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/particle99/CVE-2024-6387-POC"
      },
      {
        "added_at": "2024-07-02T04:09:44Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/thegenetic/CVE-2024-6387-exploit"
      },
      {
        "added_at": "2024-07-02T02:51:37Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/TAM-K592/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-01T13:15:06Z",
        "source": "nvd",
        "url": "https://www.exploit-db.com/exploits/52269"
      },
      {
        "added_at": "2026-05-21T18:45:31Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/oseasfr/Scanner_CVE_OpenSSH"
      },
      {
        "added_at": "2024-07-14T18:00:49Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/dream434/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-05T11:05:26Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/sardine-web/CVE-2024-6387-template"
      },
      {
        "added_at": "2024-07-04T13:28:53Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/lala-amber/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T12:24:25Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/hssmo/cve-2024-6387_AImade"
      },
      {
        "added_at": "2024-07-15T16:04:57Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/ThatNotEasy/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-09T12:16:44Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/dgourillon/mitigate-CVE-2024-6387"
      },
      {
        "added_at": "2024-07-03T10:26:23Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/harshinsecurity/sentinelssh"
      },
      {
        "added_at": "2024-07-02T13:50:47Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/xristos8574/regreSSHion-nmap-scanner"
      },
      {
        "added_at": "2024-07-02T12:48:27Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/ACHUX21/checker-CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T02:35:24Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/muyuanlove/CVE-2024-6387fixshell"
      },
      {
        "added_at": "2024-08-26T04:40:27Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/HadesNull123/CVE-2024-6387_Check"
      },
      {
        "added_at": "2024-07-09T21:01:15Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/kubota/CVE-2024-6387-Vulnerability-Checker"
      },
      {
        "added_at": "2024-07-03T15:51:16Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/jocker2410/CVE-2024-6387_poc"
      },
      {
        "added_at": "2024-12-19T03:08:19Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/zql-gif/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-11T16:54:41Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/redux-sibi-jose/mitigate_ssh"
      },
      {
        "added_at": "2024-07-04T14:34:21Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/4lxprime/regreSSHive"
      },
      {
        "added_at": "2024-07-02T18:59:54Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/xonoxitron/regreSSHion-checker"
      },
      {
        "added_at": "2024-07-02T17:04:52Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/th3gokul/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T11:08:40Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/zenzue/CVE-2024-6387-Mitigation"
      },
      {
        "added_at": "2024-07-02T07:42:46Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/CiderAndWhisky/regression-scanner"
      },
      {
        "added_at": "2024-07-01T13:15:06Z",
        "source": "nvd",
        "url": "https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt"
      },
      {
        "added_at": "2024-10-22T04:50:10Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/anhvutuan/CVE-2024-6387-poc-1"
      },
      {
        "added_at": "2024-08-28T13:28:08Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/identity-threat-labs/CVE-2024-6387-Vulnerability-Checker"
      },
      {
        "added_at": "2024-07-02T20:35:53Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/edsonjt81/CVE-2024-6387_Check"
      },
      {
        "added_at": "2024-07-01T13:15:06Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/08/2"
      },
      {
        "added_at": "2024-11-24T17:12:26Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/YassDEV221608/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-25T02:32:19Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/prelearn-code/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-15T16:04:57Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Ap0dexMe0/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-04T03:51:16Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/JackSparrowhk/ssh-CVE-2024-6387-poc"
      },
      {
        "added_at": "2024-07-02T18:46:24Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/RickGeex/CVE-2024-6387-Checker"
      },
      {
        "added_at": "2026-03-09T04:35:39Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Remnant-DB/CVE-2024-6387"
      },
      {
        "added_at": "2024-12-19T10:16:45Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/awusan125/test_for6387"
      },
      {
        "added_at": "2024-08-20T09:57:24Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/almogopp/OpenSSH-CVE-2024-6387-Fix"
      },
      {
        "added_at": "2024-07-02T08:19:55Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/paradessia/CVE-2024-6387-nmap"
      },
      {
        "added_at": "2024-07-02T02:54:05Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/teamos-hub/regreSSHion"
      },
      {
        "added_at": "2024-07-01T13:15:06Z",
        "source": "nvd",
        "url": "https://santandersecurityresearch.github.io/blog/sshing_the_masses.html"
      },
      {
        "added_at": "2025-12-08T18:25:18Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Ngagne-Demba-Dia/CVE-2024-6387-corrigee"
      },
      {
        "added_at": "2024-07-09T14:06:02Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/mrmtwoj/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T21:47:02Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/CognisysGroup/CVE-2024-6387-Checker"
      },
      {
        "added_at": "2024-07-02T20:19:12Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/BrandonLynch2402/cve-2024-6387-nuclei-template"
      },
      {
        "added_at": "2024-07-02T16:34:12Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/MrR0b0t19/CVE-2024-6387-Exploit-POC"
      },
      {
        "added_at": "2024-07-02T14:41:43Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/xonoxitron/regreSSHion"
      },
      {
        "added_at": "2024-07-02T11:05:07Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/rumochnaya/openssh-cve-2024-6387.sh"
      },
      {
        "added_at": "2026-03-31T20:32:32Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/kaleth4/CVE-2024-6387"
      },
      {
        "added_at": "2025-09-08T21:08:07Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/moften/regreSSHion-CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T10:34:17Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/daniel-odrinski/CVE-2024-6387-Mitigation-Ansible-Playbook"
      },
      {
        "added_at": "2024-07-02T09:45:04Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/PrincipalAnthony/CVE-2024-6387-Updated-x64bit"
      },
      {
        "added_at": "2024-07-02T02:51:37Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/TAM-K592/CVE-2024-6387.git"
      },
      {
        "added_at": "2024-07-04T03:56:08Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/turbobit/CVE-2024-6387-OpenSSH-Vulnerability-Checker"
      },
      {
        "added_at": "2024-07-02T18:32:46Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/l0n3m4n/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T06:53:35Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/d0rb/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T06:40:09Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/R4Tw1z/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-01T13:15:06Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/04/2"
      },
      {
        "added_at": "2024-07-01T13:15:06Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/10/1"
      },
      {
        "added_at": "2025-09-13T01:46:11Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/OhDamnn/Noregressh"
      },
      {
        "added_at": "2025-01-20T09:38:40Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/AzrDll/CVE-2024-6387"
      },
      {
        "added_at": "2024-08-29T15:00:56Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/identity-threat-labs/Article-RegreSSHion-CVE-2024-6387"
      },
      {
        "added_at": "2024-08-19T16:45:53Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/s1d6point7bugcrowd/CVE-2024-6387-Race-Condition-in-Signal-Handling-for-OpenSSH"
      },
      {
        "added_at": "2024-07-02T21:16:45Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/grupooruss/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T18:30:28Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/n1cks0n/Test_CVE-2024-6387"
      },
      {
        "added_at": "2026-03-30T09:59:03Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Doux-x/CVE-2024-6387-analysis"
      },
      {
        "added_at": "2025-11-25T18:25:37Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/arielrbrdev/redteamlab1"
      },
      {
        "added_at": "2025-01-20T09:38:40Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/kinu404/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-30T06:13:11Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/l-urk/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-09T17:40:19Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/filipi86/CVE-2024-6387-Vulnerability-Checker"
      },
      {
        "added_at": "2024-07-05T21:29:11Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/azurejoga/CVE-2024-6387-how-to-fix"
      },
      {
        "added_at": "2024-07-05T11:18:38Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/imv7/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-05T02:46:57Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/0x4D31/cve-2024-6387_hassh"
      },
      {
        "added_at": "2024-07-04T13:15:54Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/invaderslabs/regreSSHion-CVE-2024-6387-"
      },
      {
        "added_at": "2024-07-01T13:15:06Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/03/11"
      },
      {
        "added_at": "2024-07-01T13:15:06Z",
        "source": "nvd",
        "url": "https://www.vicarius.io/vsociety/posts/regresshion-an-openssh-regression-error-cve-2024-6387"
      },
      {
        "added_at": "2024-08-06T08:12:48Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/X-Projetion/CVE-2023-4596-OpenSSH-Multi-Checker"
      },
      {
        "added_at": "2024-07-08T11:48:15Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/vkaushik-chef/regreSSHion"
      },
      {
        "added_at": "2024-07-04T21:20:26Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/sardine-web/CVE-2024-6387_Check"
      },
      {
        "added_at": "2024-07-04T06:10:56Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/sms2056/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-03T13:21:10Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/t3rry327/cve-2024-6387-poc"
      },
      {
        "added_at": "2024-07-01T13:15:06Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/09/5"
      },
      {
        "added_at": "2026-05-22T08:54:27Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/vuducmanhno100-cloud/CVE-2024-6387"
      },
      {
        "added_at": "2025-07-23T14:04:37Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/xiw1ll/CVE-2024-6387_Checker"
      },
      {
        "added_at": "2024-07-03T08:22:57Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Symbolexe/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T15:13:33Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/dawnl3ss/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T15:13:09Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/no-one-sec/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T12:57:35Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/AiGptCode/ssh_exploiter_CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T11:55:39Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/devarshishimpi/CVE-2024-6387-Check"
      },
      {
        "added_at": "2024-07-10T13:27:23Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/DimaMend/cve-2024-6387-poc"
      },
      {
        "added_at": "2024-07-02T10:05:43Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/SkyGodling/CVE-2024-6387-POC"
      },
      {
        "added_at": "2024-07-02T08:13:23Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/shamo0/CVE-2024-6387_PoC"
      },
      {
        "added_at": "2024-07-02T03:48:37Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Mufti22/CVE-2024-6387-checkher"
      },
      {
        "added_at": "2024-07-02T03:42:35Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/ahlfors/CVE-2024-6387"
      },
      {
        "added_at": "2024-07-02T02:51:37Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:TAM-K592/CVE-2024-6387.git"
      },
      {
        "added_at": "2025-09-26T08:46:42Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/OHHDamnBRO/Noregressh"
      },
      {
        "added_at": "2025-01-04T00:25:33Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/YassDEV221608/CVE-2024-6387_PoC"
      },
      {
        "added_at": "2024-07-31T14:19:19Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/alex14324/ssh_poc2024"
      },
      {
        "added_at": "2024-07-08T11:27:49Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Karmakstylez/CVE-2024-6387"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://forum.vmssoftware.com/viewtopic.php?f=8&t=9132"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://www.freebsd.org/security/advisories/FreeBSD-SA-24:04.openssh.asc"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://www.splunk.com/en_us/blog/security/cve-2024-6387-regresshion-vulnerability.html"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2024:4340"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://seclists.org/fulldisclosure/2024/Jul/19"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/03/1"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://explore.alas.aws.amazon.com/CVE-2024-6387.html"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://github.com/AlmaLinux/updates/issues/629"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://security-tracker.debian.org/tracker/CVE-2024-6387"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://www.theregister.com/2024/07/01/regresshion_openssh/"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://github.com/PowerShell/Win32-OpenSSH/discussions/2248"
      },
      {
        "added_at": "2025-10-14T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.aquasec.com/blog/kaiji-malware-anatomy-persistence-detection/"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://seclists.org/fulldisclosure/2024/Jul/20"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/03/4"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://access.redhat.com/security/cve/CVE-2024-6387"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/23/6"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://lists.almalinux.org/archives/list/announce@lists.almalinux.org/thread/23BF5BMGFVEVUI2WNVAGMLKT557EU7VY/"
      },
      {
        "added_at": "2026-05-12T12:17:20Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/html/ssa-082556.html"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/02/1"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/03/5"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/08/2"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/10/3"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/10/4"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://github.com/openela-main/openssh/commit/e1f438970e5a337a17070a637c1b9e19697cad09"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://packetstorm.news/files/id/190587/"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2024:4479"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/04/2"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/08/3"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/09/2"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://github.com/PowerShell/Win32-OpenSSH/issues/2249"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://github.com/microsoft/azurelinux/issues/9555"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://news.ycombinator.com/item?id=40843778"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://support.apple.com/kb/HT214120"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2024:4484"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/10/1"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/11/3"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://ubuntu.com/security/CVE-2024-6387"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://ubuntu.com/security/notices/USN-6859-1"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://www.suse.com/security/cve/CVE-2024-6387.html"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://www.vicarius.io/vsociety/posts/regresshion-an-openssh-regression-error-cve-2024-6387"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/23/4"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://arstechnica.com/security/2024/07/regresshion-vulnerability-in-openssh-gives-attackers-root-on-linux/"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://sig-security.rocky.page/issues/CVE-2024-6387/"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://github.com/oracle/oracle-linux/issues/149"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://lists.mindrot.org/pipermail/openssh-unix-announce/2024-July/000158.html"
      },
      {
        "added_at": "2026-05-12T12:17:20Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/html/ssa-446545.html"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://github.com/Azure/AKS/issues/4379"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/01/12"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/10/2"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://ftp.netbsd.org/pub/NetBSD/security/advisories/NetBSD-SA2024-002.txt.asc"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://archlinux.org/news/the-sshd-service-needs-to-be-restarted-after-upgrading-to-openssh-98p1/"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2024:4469"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2294604"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://seclists.org/fulldisclosure/2024/Jul/18"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/03/11"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/09/5"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/28/3"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://www.exploit-db.com/exploits/52269"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2024:4389"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2024:4474"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://santandersecurityresearch.github.io/blog/sshing_the_masses.html"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/03/2"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/04/1"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://lists.mindrot.org/pipermail/openssh-unix-dev/2024-July/041431.html"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20240701-0001/"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://stackdiary.com/openssh-race-condition-in-sshd-allows-remote-code-execution/"
      },
      {
        "added_at": "2024-07-17T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.cadosecurity.com/blog/warpscan-cloudflare-warp-abused-to-hijack-cloud-services-blog"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://github.com/rapier1/hpn-ssh/issues/87"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://support.apple.com/kb/HT214118"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://www.akamai.com/blog/security-research/2024-openssh-vulnerability-regression-what-to-know-and-do"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://www.arista.com/en/support/advisories-notices/security-advisory/19904-security-advisory-0100"
      },
      {
        "added_at": "2025-03-12T00:00:00Z",
        "source": "vulncheck",
        "url": "https://content.kaspersky-labs.com/fm/site-editor/33/3318ec849851138088d24f26d236f469/source/irreport.pdf"
      },
      {
        "added_at": "2025-06-07T00:00:00Z",
        "source": "vulncheck",
        "url": "https://app.crowdsec.net/cti/cve-explorer/CVE-2024-6387"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0010"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://support.apple.com/kb/HT214119"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/03/3"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/10/6"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/28/2"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://github.com/zgzhang/cve-2024-6387-poc"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2024:4312"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "https://www.openssh.com/txt/release-9.8"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/01/13"
      },
      {
        "added_at": "2025-04-24T19:15:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/11/1"
      }
    ],
    "cwe": [
      "CWE-364",
      "CWE-362"
    ],
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit requires no authentication.",
    "impact": "Remote attackers can exploit the race condition to cause a denial of service or potentially execute arbitrary code.",
    "name": "OpenSSH - Race Condition",
    "remediation": "Update to the latest version of OpenSSH where this regression is fixed.",
    "requirement_type": "none",
    "severity": "high",
    "vulnerability_impact": [
      "denial_of_service",
      "remote_code_execution"
    ],
    "vulnerability_type": "race_condition",
    "weaknesses": [
      {
        "cwe_id": "CWE-364",
        "cwe_name": "Signal Handler Race Condition"
      },
      {
        "cwe_id": "CWE-362",
        "cwe_name": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"
      }
    ],
    "affected_products": [
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sra_ex_7000_firmware",
        "summary": "sonicwall sra_ex_7000_firmware is a firmware that provides secure remote access capabilities for enterprise networks. It sits in the hardware layer of the tech stack, is deployed as self_hosted, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "sonicwall"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "a70_firmware",
        "summary": "netapp a70_firmware is a firmware component that manages low-level hardware operations for storage systems. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "a400_firmware",
        "summary": "netapp a400_firmware is the embedded firmware that controls the NetApp AFF A400 storage system hardware. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "amazon amazon_linux is a Linux-based operating system optimized for cloud environments that provides a secure, stable, and high-performance platform for applications. It sits in the operating_system layer of the tech stack, is typically deployed as self_hosted, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "amazon_linux",
        "summary": "netapp active_iq_unified_manager is a unified storage management and monitoring solution that provides proactive insights and analytics for storage infrastructure. It sits in the core_infra layer of the tech stack, functions as a self-hosted management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "amazon"
      },
      {
        "category": "data_storage",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "e-series_santricity_os_controller",
        "summary": "netapp ontap is a data management software that provides storage efficiency, data protection, and seamless data access across cloud and on-premises environments. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_tools",
        "summary": "freebsd freebsd is an open-source Unix-like operating system that provides a robust, secure, and high-performance platform for servers and desktops. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "eos",
        "summary": "arista eos is a network operating system that provides programmable, scalable, and reliable network infrastructure for data centers and cloud networks. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "arista"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "c400_firmware",
        "summary": "netapp c400_firmware is the embedded firmware that controls the NetApp C400 storage system hardware, ensuring reliable operation and performance. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "macos",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "apple"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_for_ibm_z_systems_eus",
        "summary": "redhat enterprise_linux_for_power_little_endian is a Linux-based operating system optimized for Power Little Endian architecture that provides a stable and secure platform for enterprise workloads. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_for_power_little_endian",
        "summary": "redhat enterprise_linux_for_power_little_endian_eus is a Linux-based operating system optimized for Power Little Endian architecture that provides a stable and secure platform for enterprise workloads. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sma_6210_firmware",
        "summary": "sonicwall sma_6210_firmware is the embedded firmware for the SonicWall SMA 6210 secure mobile access appliance that provides secure remote access and VPN capabilities. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "sonicwall"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "8300_firmware",
        "summary": "netapp 8300_firmware is a firmware component that controls and manages the hardware operations of the NetApp 8300 storage system. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "c800_firmware",
        "summary": "netapp c800_firmware is the embedded firmware that controls the NetApp C800 storage system hardware, ensuring reliable operation and management of storage resources. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a150_firmware",
        "summary": "netapp a150_firmware is the embedded firmware that controls the hardware operations of the NetApp A150 storage system. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a220_firmware",
        "summary": "netapp a220_firmware is a firmware component that manages low-level hardware operations for the NetApp A220 storage system. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "redhat openshift_container_platform is a comprehensive Kubernetes container orchestration platform that automates deployment, scaling, and management of containerized applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "openbsd"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_eus",
        "summary": "redhat enterprise_linux_for_arm_64 is a robust, enterprise-grade Linux operating system optimized for ARM 64-bit architectures that provides a stable and secure platform for applications. It sits in the operating_system layer of the tech stack, functions as a self-hosted core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_for_arm_64",
        "summary": "redhat enterprise_linux_for_arm_64_eus is a stable, long-term supported Linux operating system optimized for ARM 64-bit architectures. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a250_firmware",
        "summary": "netapp a250_firmware is the embedded firmware that controls the NetApp AFF A250 storage system hardware, ensuring reliable operation and performance. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "c250_firmware",
        "summary": "netapp c250_firmware is a firmware component that manages low-level hardware operations for NetApp storage systems. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "fas2750_firmware",
        "summary": "netapp fas2750_firmware is the embedded firmware that controls the NetApp FAS2750 storage system hardware, enabling storage management and data operations. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_for_arm_64_eus",
        "summary": "redhat enterprise_linux_for_ibm_z_systems is a robust enterprise-grade Linux operating system optimized for IBM Z mainframe systems that provides stability, security, and scalability. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "product": "netbsd",
        "vendor": "netbsd"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "almalinux",
        "summary": "almalinux almalinux is a community-driven, open-source Linux distribution designed as a stable and secure operating system for enterprise environments. It sits in the operating_system layer of the tech stack, is typically deployed as self_hosted, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "almalinux"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "c190_firmware",
        "summary": "netapp c190_firmware is a firmware component that manages low-level hardware operations for NetApp storage systems. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_container_platform",
        "summary": "redhat enterprise_linux is a commercial Linux operating system distribution that provides a stable, secure, and supported platform for enterprise applications. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_for_power_little_endian_eus",
        "summary": "redhat enterprise_linux_server_aus is a Linux-based operating system designed for enterprise-grade server environments that provides stability, security, and performance. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "active_iq_unified_manager",
        "summary": "netapp e-series_santricity_os_controller is a storage management operating system that provides control and monitoring for NetApp E-Series storage arrays. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "freebsd",
        "summary": "netbsd netbsd is a free, open-source, and highly portable Unix-like operating system that supports a wide range of hardware platforms. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "freebsd"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sma_8200v_firmware",
        "summary": "sonicwall sma_8200v_firmware is a firmware for virtualized network security appliances that provides advanced threat protection and secure remote access. It sits in the hardware layer of the tech stack, is deployed as self_hosted virtual appliance firmware, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "sonicwall"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a700s_firmware",
        "summary": "netapp a700s_firmware is a firmware component that controls and manages the hardware operations of the NetApp A700s storage system. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "500f_firmware",
        "summary": "netapp 500f_firmware is the embedded firmware that controls the NetApp AFF A500 storage array hardware, ensuring optimal performance and reliability. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a900_firmware",
        "summary": "netapp a900_firmware is a firmware component that manages low-level hardware operations for the NetApp A900 storage system. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "a9500_firmware",
        "summary": "netapp a9500_firmware is the embedded firmware that controls the NetApp AFF A9500 storage system hardware, enabling storage management and operation. It sits in the hardware layer of the tech stack, is deployed as self_hosted within storage appliances, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "fas2720_firmware",
        "summary": "netapp fas2720_firmware is the embedded firmware that controls the NetApp FAS2720 storage system hardware, enabling storage management and data operations. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "bootstrap_os",
        "summary": "apple macos is a desktop operating system that provides a graphical user interface and core system services for Apple computers. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux",
        "summary": "redhat enterprise_linux_eus is a long-term supported Linux operating system designed for stability and extended maintenance in enterprise environments. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sma_7200_firmware",
        "summary": "sonicwall sma_7200_firmware is a firmware for secure mobile access appliances that provides secure remote access and VPN capabilities. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "sonicwall"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "8700_firmware",
        "summary": "netapp 8700_firmware is a firmware component that manages and controls the hardware operations of NetApp storage systems. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a800_firmware",
        "summary": "netapp a800_firmware is the embedded firmware that controls the hardware operations of the NetApp A800 storage system. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "fas2820_firmware",
        "summary": "netapp fas2820_firmware is the embedded firmware that controls the NetApp FAS2820 storage system hardware, enabling data storage and management functionalities. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_for_ibm_z_systems",
        "summary": "redhat enterprise_linux_for_ibm_z_systems_eus is a Linux-based operating system optimized for IBM Z mainframe systems that provides a stable and secure platform for enterprise workloads. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_aus",
        "summary": "suse linux_enterprise_micro is a lightweight, container-focused operating system designed for cloud-native workloads and edge computing. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "linux_enterprise_micro",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "suse"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "sma_6200_firmware",
        "summary": "sonicwall sma_6200_firmware is a firmware for secure mobile access appliances that provides network security and remote access capabilities. It sits in the hardware layer of the tech stack, functions as a firmware component in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "sonicwall"
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
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sma_7210_firmware",
        "summary": "sonicwall sma_7210_firmware is a firmware for the SMA 7210 secure mobile access appliance that provides secure remote access and VPN capabilities. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "sonicwall"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "a1k_firmware",
        "summary": "netapp a1k_firmware is a firmware component that controls and manages the hardware operations of NetApp storage devices. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "a90_firmware",
        "summary": "netapp a90_firmware is the embedded firmware that controls the hardware operations of NetApp A90 storage systems. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap",
        "summary": "netapp ontap_select_deploy_administration_utility is a deployment and management tool for NetApp's ONTAP Select software-defined storage. It sits in the core_infra layer of the tech stack, functions as a self-hosted management utility in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_select_deploy_administration_utility",
        "summary": "netapp ontap_tools is a suite of management and automation utilities designed to optimize NetApp ONTAP storage systems. It sits in the core_infra layer of the tech stack, functions as a self-hosted management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      }
    ],
    "created_at": "2024-07-01T13:15:06Z",
    "doc_id": "CVE-2024-6387",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 26254055,
      "min_hosts": 2157
    },
    "h1": {
      "delta_rank": 1,
      "rank": 114,
      "reports": 24
    },
    "ntps": 69,
    "updated_at": "2026-06-11T16:11:38.05Z",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade openssh - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2007-4752",
    "age_in_days": 6847,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2007-09-12T01:17:00Z",
    "cve_updated_at": "2026-04-23T00:35:47Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
    "cvss_score": 7.5,
    "epss_percentile": 0.82664,
    "epss_score": 0.01693,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2008-08-22T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.vupen.com/english/advisories/2007/3156"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://www.redhat.com/archives/fedora-package-announce/2007-October/msg00214.html"
      },
      {
        "added_at": "2008-08-22T00:00:00Z",
        "source": "vulncheck",
        "url": "https://access.redhat.com/errata/RHSA-2008:0855.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://securityreason.com/securityalert/3126"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://support.avaya.com/elmodocs2/security/ASA-2008-399.htm"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/483748/100/200/threaded"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/36637"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.apple.com/archives/security-announce/2008/Mar/msg00001.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.debian.org/security/2008/dsa-1576"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.ubuntu.com/usn/usn-566-1"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.vupen.com/english/advisories/2008/0924/references"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://secunia.com/advisories/30249"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://security.gentoo.org/glsa/glsa-200711-02.xml"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=280471"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A10809"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://issues.rpath.com/browse/RPL-1706"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://bugs.gentoo.org/show_bug.cgi?id=191321"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://secunia.com/advisories/29420"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://secunia.com/advisories/32241"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.redhat.com/support/errata/RHSA-2008-0855.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://docs.info.apple.com/article.html?artnum=307562"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01271085"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2007-10/msg00008.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://secunia.com/advisories/27399"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/479760/100/0/threaded"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.vupen.com/english/advisories/2008/2821"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A5599"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://secunia.com/advisories/31575"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.mandriva.com/security/advisories?name=MDKSA-2007:236"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/bid/25628"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.openssh.com/txt/release-4.7"
      }
    ],
    "cwe": [
      "CWE-20"
    ],
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipulate cookie creation.",
    "impact": "Attackers can escalate privileges by tricking X clients into being trusted, potentially leading to unauthorized access or control.",
    "name": "OpenSSH - Privilege Escalation",
    "remediation": "Update to OpenSSH 4.7 or later.",
    "requirement_type": "none",
    "severity": "high",
    "vulnerability_impact": [
      "privilege_escalation"
    ],
    "vulnerability_type": "broken_access_control",
    "weaknesses": [
      {
        "cwe_id": "CWE-20",
        "cwe_name": "Improper Input Validation"
      }
    ],
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      }
    ],
    "created_at": "2007-09-12T01:17:00Z",
    "doc_id": "CVE-2007-4752",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 26254055,
      "min_hosts": 26254055
    },
    "h1": {
      "delta_rank": 19,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 57,
    "updated_at": "2026-06-11T14:30:41.337Z",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade openssh - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2019-6109",
    "age_in_days": 2687,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2019-01-31T18:29:00Z",
    "cve_updated_at": "2026-05-28T19:16:34Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "cvss_score": 6.8,
    "epss_percentile": 0.93117,
    "epss_score": 0.09738,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2020-07-19T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-412672.pdf"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://security.gentoo.org/glsa/201903-16"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://usn.ubuntu.com/3885-1/"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/W3YVQ2BPTOVDCFDVNC2GGF5P5ISFG37G/"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20190213-0001/"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://www.debian.org/security/2019/dsa-4387"
      },
      {
        "added_at": "2023-02-14T00:00:00Z",
        "source": "vulncheck",
        "url": "https://info.securin.io/hubfs/Securin%20Ransomware%20Report%202023.pdf"
      },
      {
        "added_at": "2020-10-30T00:00:00Z",
        "source": "vulncheck",
        "url": "https://cybersecurity.bd.com/bulletins-and-patches/ryuk-ransomware"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2019:3702"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://cvsweb.openbsd.org/src/usr.bin/ssh/progressmeter.c"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://cvsweb.openbsd.org/src/usr.bin/ssh/scp.c"
      },
      {
        "added_at": "2020-11-02T00:00:00Z",
        "source": "vulncheck",
        "url": "https://cybersecurityworks.com/blog/ransomware/ryuk-raising-the-temperature-in-healthcare.html"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2019/03/msg00030.html"
      }
    ],
    "cwe": [
      "CWE-116"
    ],
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to manipulate client output, exploit requires man-in-the-middle position.",
    "impact": "Attackers can manipulate client output to hide transferred files, potentially misleading users or obscuring malicious activity.",
    "name": "OpenSSH - Output Manipulation",
    "remediation": "Update to the latest version of OpenSSH where this issue is fixed.",
    "requirement_type": "none",
    "severity": "medium",
    "vulnerability_impact": [
      "man_in_the_middle"
    ],
    "vulnerability_type": "undefined",
    "weaknesses": [
      {
        "cwe_id": "CWE-116",
        "cwe_name": "Improper Encoding or Escaping of Output"
      }
    ],
    "affected_products": [
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "scalance_x204rna_eec_firmware",
        "summary": "siemens scalance_x204rna_eec_firmware is a specialized firmware that manages industrial Ethernet switches for secure and reliable network communication. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m12-1_firmware",
        "summary": "fujitsu m12-1_firmware is a device firmware that controls and manages hardware operations for Fujitsu devices. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "winscp",
        "summary": "winscp winscp is a free and open-source SFTP, FTP, WebDAV, and SCP client that facilitates secure file transfers between local and remote computers. It sits in the application_library layer of the tech stack, functions as a self-hosted client tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "winscp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
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
        "product": "enterprise_linux_server_tus",
        "summary": "redhat enterprise_linux_server_tus is a Linux-based operating system designed for enterprise environments that provides a stable and secure platform for running applications and services. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m10-4s_firmware",
        "summary": "fujitsu m10-4s_firmware is a firmware component that controls and manages hardware operations for Fujitsu's M10-4S systems. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m12-2_firmware",
        "summary": "fujitsu m12-2_firmware is a firmware component that controls low-level hardware functions for the M12-2 system. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m12-2s_firmware",
        "summary": "fujitsu m12-2s_firmware is a device firmware that controls and manages hardware operations for the M12-2S system. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_select_deploy",
        "summary": "netapp ontap_select_deploy is a software-defined storage solution that enables deployment of enterprise-grade storage services on commodity hardware. It sits in the data_storage layer of the tech stack, functions as a self-hosted storage platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "data_storage",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "storage_automation_store",
        "summary": "netapp storage_automation_store is a storage automation solution that optimizes data management and storage operations. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "scalance_x204rna_firmware",
        "summary": "siemens scalance_x204rna_firmware is a firmware that manages industrial network switches to ensure reliable and secure communication in automation environments. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m10-1_firmware",
        "summary": "fujitsu m10-1_firmware is a hardware firmware component that controls and manages the low-level operations of Fujitsu's M10-1 server systems. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "m10-4_firmware",
        "summary": "fujitsu m10-4_firmware is a firmware component that manages low-level hardware control and system initialization for Fujitsu's M10-4 server systems. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fujitsu"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "element_software",
        "summary": "netapp element_software is a storage management software that provides scalable and high-performance data storage solutions. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux",
        "summary": "redhat enterprise_linux is a commercial Linux operating system distribution that provides a stable, secure, and supported platform for enterprise applications. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_eus",
        "summary": "redhat enterprise_linux_eus is a long-term supported Linux operating system designed for stability and extended maintenance in enterprise environments. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_aus",
        "summary": "redhat enterprise_linux_server_aus is a Linux-based operating system designed for enterprise-grade server environments that provides stability, security, and performance. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      }
    ],
    "created_at": "2019-01-31T18:29:00Z",
    "doc_id": "CVE-2019-6109",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 26254055,
      "min_hosts": 31320
    },
    "h1": {
      "delta_rank": -1,
      "rank": 824,
      "reports": 6
    },
    "ntps": 54,
    "updated_at": "2026-06-11T14:59:25.099Z",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade openssh - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2019-6110",
    "age_in_days": 2687,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2019-01-31T18:29:00Z",
    "cve_updated_at": "2025-12-18T15:15:47Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "cvss_score": 6.8,
    "epss_percentile": 0.98202,
    "epss_score": 0.57569,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2020-07-19T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 1,
    "poc_first_seen": "2019-01-31T18:29:00Z",
    "pocs": [
      {
        "added_at": "2019-01-31T18:29:00Z",
        "source": "nvd",
        "url": "https://www.exploit-db.com/exploits/46193/"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://cvsweb.openbsd.org/src/usr.bin/ssh/scp.c"
      },
      {
        "added_at": "2023-02-14T00:00:00Z",
        "source": "vulncheck",
        "url": "https://info.securin.io/hubfs/Securin%20Ransomware%20Report%202023.pdf"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-412672.pdf"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://security.gentoo.org/glsa/201903-16"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20190213-0001/"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://www.exploit-db.com/exploits/46193/"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://cvsweb.openbsd.org/src/usr.bin/ssh/progressmeter.c"
      },
      {
        "added_at": "2020-11-02T00:00:00Z",
        "source": "vulncheck",
        "url": "https://cybersecurityworks.com/blog/ransomware/ryuk-raising-the-temperature-in-healthcare.html"
      },
      {
        "added_at": "2024-11-21T04:45:57Z",
        "source": "nvd",
        "url": "https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt"
      }
    ],
    "cwe": [
      "CWE-838"
    ],
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, exploit requires man-in-the-middle position.",
    "impact": "Attackers can manipulate client output to hide malicious activity or mislead users during file transfers.",
    "name": "OpenSSH - Client Output Manipulation",
    "remediation": "Update to the latest version of OpenSSH where this issue is fixed.",
    "requirement_type": "none",
    "severity": "medium",
    "vulnerability_impact": [
      "man_in_the_middle"
    ],
    "vulnerability_type": "undefined",
    "weaknesses": [
      {
        "cwe_id": "CWE-838",
        "cwe_name": "Inappropriate Encoding for Output Context"
      }
    ],
    "affected_products": [
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "element_software",
        "summary": "netapp element_software is a storage management software that provides scalable and high-performance data storage solutions. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_select_deploy",
        "summary": "netapp ontap_select_deploy is a software-defined storage solution that enables deployment of enterprise-grade storage services on commodity hardware. It sits in the data_storage layer of the tech stack, functions as a self-hosted storage platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "data_storage",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "storage_automation_store",
        "summary": "netapp storage_automation_store is a storage automation solution that optimizes data management and storage operations. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "scalance_x204rna_firmware",
        "summary": "siemens scalance_x204rna_firmware is a firmware that manages industrial network switches to ensure reliable and secure communication in automation environments. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "scalance_x204rna_eec_firmware",
        "summary": "siemens scalance_x204rna_eec_firmware is a specialized firmware that manages industrial Ethernet switches for secure and reliable network communication. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openssh",
        "summary": "openbsd openssh is a secure shell (SSH) protocol suite that provides encrypted communication and secure remote login capabilities. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "openbsd"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "winscp",
        "summary": "winscp winscp is a free and open-source SFTP, FTP, WebDAV, and SCP client that facilitates secure file transfers between local and remote computers. It sits in the application_library layer of the tech stack, functions as a self-hosted client tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "winscp"
      }
    ],
    "created_at": "2019-01-31T18:29:00Z",
    "doc_id": "CVE-2019-6110",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 26254055,
      "min_hosts": 26254055
    },
    "h1": {
      "delta_rank": -1,
      "rank": 824,
      "reports": 6
    },
    "ntps": 70,
    "updated_at": "2026-06-11T16:00:15.391Z",
    "product": "openssh",
    "pinned_version": "1:9.1p1-1ubuntu1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade openssh - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-1999-0067",
    "age_in_days": 11039,
    "assignee": "cve@mitre.org",
    "cve_created_at": "1996-03-20T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.99402,
    "epss_score": 0.85831,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.cert.org/advisories/CA-1996-06.html"
      }
    ],
    "cwe": [
      "CWE-78"
    ],
    "description": "phf CGI program contains a remote command execution caused by unsanitized shell metacharacters, letting attackers execute arbitrary commands remotely, exploit requires sending crafted input.",
    "impact": "Attackers can execute arbitrary commands on the server, potentially leading to full system compromise.",
    "name": "phf CGI - Command Injection",
    "remediation": "Sanitize input to remove shell metacharacters and update to the latest version of the CGI program.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "command_injection",
    "weaknesses": [
      {
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
      }
    ],
    "affected_products": [
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
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ncsa_httpd",
        "summary": "ncsa ncsa_httpd is a web server software that serves HTTP requests and delivers web content. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "ncsa"
      }
    ],
    "created_at": "1996-03-20T05:00:00Z",
    "doc_id": "CVE-1999-0067",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 13958685,
      "min_hosts": 13958685
    },
    "h1": {
      "rank": 2540,
      "reports": 1
    },
    "ntps": 46,
    "updated_at": "2026-06-10T13:34:12.954Z",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-1999-0926",
    "age_in_days": 9778,
    "assignee": "cve@mitre.org",
    "cve_created_at": "1999-09-03T04:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.92385,
    "epss_score": 0.08184,
    "is_oss": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 1,
    "poc_first_seen": "1999-09-03T04:00:00Z",
    "pocs": [
      {
        "added_at": "1999-09-03T04:00:00Z",
        "source": "nvd",
        "url": "http://archives.neohapsis.com/archives/bugtraq/1998_3/0742.html"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://archives.neohapsis.com/archives/bugtraq/1998_3/0742.html"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "Apache contains a denial of service caused by handling a large number of MIME headers, letting remote attackers cause service disruption, exploit requires sending numerous MIME headers.",
    "impact": "Attackers can cause Apache server to become unresponsive or crash, leading to service denial.",
    "name": "Apache - Denial of Service",
    "remediation": "Update to the latest version of Apache that addresses this issue or apply relevant patches.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "denial_of_service"
    ],
    "vulnerability_type": "denial_of_service",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "http_server",
        "summary": "apache http_server is a widely-used open-source web server that delivers HTTP content to clients efficiently and securely. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      }
    ],
    "created_at": "1999-09-03T04:00:00Z",
    "doc_id": "CVE-1999-0926",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 13925027,
      "min_hosts": 13925027
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 48,
    "updated_at": "2026-06-11T14:00:18.609Z",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-1999-1199",
    "age_in_days": 10170,
    "assignee": "cve@mitre.org",
    "cve_created_at": "1998-08-07T04:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.90063,
    "epss_score": 0.05121,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.redhat.com/support/errata/rh51-errata-general.html#apache"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r9f93cf6dde308d42a9c807784e8102600d0397f5f834890708bf6920%40%3Ccvs.httpd.apache.org%3E"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf2f0f3611f937cf6cfb3b4fe4a67f69885855126110e1e3f2fb2728e%40%3Ccvs.httpd.apache.org%3E"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=90252779826784&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=90276683825862&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=90286768232093&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r5419c9ba0951ef73a655362403d12bb8d10fab38274deb3f005816f5%40%3Ccvs.httpd.apache.org%3E"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf6449464fd8b7437704c55f88361b66f12d5b5f90bcce66af4be4ba9%40%3Ccvs.httpd.apache.org%3E"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=90280517007869&w=2"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "Apache WWW server 1.3.1 and earlier contains a denial of service caused by resource exhaustion via a large number of MIME headers with the same name, letting remote attackers cause resource exhaustion, exploit requires sending numerous headers.",
    "impact": "Attackers can cause resource exhaustion leading to denial of service, potentially crashing or slowing down the server.",
    "name": "Apache WWW Server - Denial of Service",
    "remediation": "Update to the latest version of Apache WWW server.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "denial_of_service"
    ],
    "vulnerability_type": "denial_of_service",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      }
    ],
    "affected_products": [
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "http_server",
        "summary": "apache http_server is a widely-used open-source web server that delivers HTTP content to clients efficiently and securely. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      }
    ],
    "created_at": "1998-08-07T04:00:00Z",
    "doc_id": "CVE-1999-1199",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 13925027,
      "min_hosts": 13925027
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 38,
    "updated_at": "2026-06-11T14:01:00.237Z",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-2013-2250",
    "age_in_days": 4682,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-08-15T16:55:09Z",
    "cve_updated_at": "2026-04-29T01:13:23Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.90797,
    "epss_score": 0.05894,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://secunia.com/advisories/53910"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/bid/61369"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/85875"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://ofbiz.apache.org/download.html#vulnerabilities"
      }
    ],
    "cwe": [
      "CWE-20"
    ],
    "description": "Apache Open For Business Project (OFBiz) versions 10.04.01 through 10.04.05, 11.04.01 through 11.04.02, and 12.04.01 contain a remote code execution caused by unsanitized JUEL metacharacters in parameters, letting attackers execute arbitrary UEL functions via nested expressions, exploit requires sending crafted parameters.",
    "impact": "Attackers can execute arbitrary UEL functions, potentially leading to remote code execution and full system compromise.",
    "name": "Apache OFBiz - Expression Language Injection",
    "remediation": "Update to the latest version where the vulnerability is fixed or apply security patches addressing expression language injection.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "expression_language_injection",
    "weaknesses": [
      {
        "cwe_id": "CWE-20",
        "cwe_name": "Improper Input Validation"
      }
    ],
    "affected_products": [
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ofbiz",
        "summary": "apache ofbiz is an open-source enterprise resource planning (ERP) and e-commerce platform that provides a suite of business applications for managing operations. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "apache"
      }
    ],
    "created_at": "2013-08-15T16:55:09Z",
    "doc_id": "CVE-2013-2250",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 151272,
      "min_hosts": 151272
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-06-11T14:12:36.494Z",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1777",
    "age_in_days": 4717,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-07-11T22:55:00Z",
    "cve_updated_at": "2026-04-29T01:13:23Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.92429,
    "epss_score": 0.08279,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "https://issues.apache.org/jira/browse/GERONIMO-6477"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://geronimo.apache.org/30x-security-report.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www-01.ibm.com/support/docview.wss?uid=swg21643282"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://archives.neohapsis.com/archives/bugtraq/2013-07/0008.html"
      }
    ],
    "cwe": [
      "CWE-94"
    ],
    "description": "Apache Geronimo 3.x before 3.0.1, used in IBM WebSphere Application Server Community Edition 3.0.0.3, contains a remote code execution caused by improper RMI classloader implementation in JMX Remoting, letting remote attackers execute arbitrary code via crafted serialized objects, exploit requires network access to JMX connector.",
    "impact": "Remote attackers can execute arbitrary code on the server, potentially leading to full system compromise.",
    "name": "Apache Geronimo - Remote Code Execution",
    "remediation": "Update to Apache Geronimo 3.0.1 or later version.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "insecure_deserialization",
    "weaknesses": [
      {
        "cwe_id": "CWE-94",
        "cwe_name": "Improper Control of Generation of Code ('Code Injection')"
      }
    ],
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "geronimo",
        "summary": "apache geronimo is an open-source Java EE application server that provides a runtime environment for deploying and managing enterprise Java applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted middleware server in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "apache"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "websphere_application_server",
        "summary": "ibm websphere_application_server is a robust application server that hosts and manages Java-based web applications. It sits in the core_infra layer of the tech stack, functions as a middleware platform in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "ibm"
      }
    ],
    "created_at": "2013-07-11T22:55:00Z",
    "doc_id": "CVE-2013-1777",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 90,
      "min_hosts": 90
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 38,
    "updated_at": "2026-06-11T14:13:30.717Z",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade apache to latest patched version"
  },
  {
    "cve_id": "CVE-2023-46604",
    "age_in_days": 958,
    "assignee": "security@apache.org",
    "cve_created_at": "2023-10-27T15:15:14Z",
    "cve_updated_at": "2025-11-04T16:41:16Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",
    "cvss_score": 10,
    "epss_percentile": 0.99988,
    "epss_score": 0.94436,
    "is_kev": true,
    "is_oss": true,
    "is_poc": true,
    "is_remote": true,
    "is_template": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2023-11-02T00:00:00Z",
        "due_date": "2023-11-23T00:00:00Z",
        "known_ransomware_campaign_use": true,
        "source": "cisa"
      },
      {
        "added_date": "2023-11-02T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 87,
    "poc_first_seen": "2023-10-26T03:25:05Z",
    "pocs": [
      {
        "added_at": "2025-02-27T02:49:18Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:skrkcb2/CVE-2023-46604.git"
      },
      {
        "added_at": "2026-05-02T16:07:03Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/trnguyen03/activemq-ids-ips-lab"
      },
      {
        "added_at": "2026-03-15T05:28:30Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/sangrok-jeon/CVE-2023-46604-Analysis"
      },
      {
        "added_at": "2025-11-15T19:31:03Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/pavanaa4k/CVE-2023-46604-LAB"
      },
      {
        "added_at": "2023-11-04T11:58:21Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/evkl1d/CVE-2023-46604.git"
      },
      {
        "added_at": "2023-11-03T22:06:09Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ"
      },
      {
        "added_at": "2026-04-30T04:38:32Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Navya240/intel471-threat-hunting-cve-2023-46604"
      },
      {
        "added_at": "2026-03-18T18:33:24Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/jbogdanov/activemq-cve-playground"
      },
      {
        "added_at": "2024-10-16T03:31:13Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:cuanh2333/CVE-2023-46604.git"
      },
      {
        "added_at": "2023-12-30T20:02:19Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/tomasmussi/activemq-cve-2023-46604"
      },
      {
        "added_at": "2023-12-16T13:50:58Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/dcm2406/CVE-2023-46604"
      },
      {
        "added_at": "2023-11-20T11:57:24Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/nitzanoligo/CVE-2023-46604-demo.git"
      },
      {
        "added_at": "2023-11-12T11:26:46Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell.git"
      },
      {
        "added_at": "2023-10-26T03:25:05Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/trganda/ActiveMQ-RCE"
      },
      {
        "added_at": "2023-11-18T12:51:03Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:NKeshawarz/CVE-2023-46604-RCE.git"
      },
      {
        "added_at": "2024-05-31T00:38:47Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/pulentoski/CVE-2023-46604"
      },
      {
        "added_at": "2023-11-20T02:24:47Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:minhangxiaohui/ActiveMQ_CVE-2023-46604.git"
      },
      {
        "added_at": "2023-11-03T22:06:09Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ.git"
      },
      {
        "added_at": "2023-11-03T22:06:09Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ.git"
      },
      {
        "added_at": "2025-02-27T02:49:18Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/skrkcb2/CVE-2023-46604"
      },
      {
        "added_at": "2023-10-27T15:15:14Z",
        "source": "nvd",
        "url": "https://packetstormsecurity.com/files/175676/Apache-ActiveMQ-Unauthenticated-Remote-Code-Execution.html"
      },
      {
        "added_at": "2026-04-20T02:38:50Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Catherines77/ActiveMQ-EXPtools"
      },
      {
        "added_at": "2023-12-23T08:41:01Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/Mudoleto/Broker_ApacheMQ.git"
      },
      {
        "added_at": "2024-05-31T00:38:47Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:pulentoski/CVE-2023-46604.git"
      },
      {
        "added_at": "2024-04-26T11:42:57Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/thinkycx/activemq-rce-cve-2023-46604"
      },
      {
        "added_at": "2023-12-09T19:19:03Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/mrpentst/CVE-2023-46604"
      },
      {
        "added_at": "2023-12-09T19:19:03Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/mrpentst/CVE-2023-46604.git"
      },
      {
        "added_at": "2023-11-20T11:57:24Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/nitzanoligo/CVE-2023-46604-demo"
      },
      {
        "added_at": "2023-11-15T19:11:01Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/vjayant93/CVE-2023-46604-POC"
      },
      {
        "added_at": "2023-11-12T11:26:46Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell"
      },
      {
        "added_at": "2025-05-04T14:42:01Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/CCIEVoice2009/CVE-2023-46604"
      },
      {
        "added_at": "2024-03-05T07:09:21Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/Arlenhiack/ActiveMQ-RCE-Exploit.git"
      },
      {
        "added_at": "2023-11-20T02:24:47Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/minhangxiaohui/ActiveMQ_CVE-2023-46604.git"
      },
      {
        "added_at": "2023-11-18T12:51:03Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/NKeshawarz/CVE-2023-46604-RCE.git"
      },
      {
        "added_at": "2023-10-27T12:22:43Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/ImuSpirit/ActiveMQ_RCE_Pro_Max"
      },
      {
        "added_at": "2023-10-26T03:25:05Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:trganda/ActiveMQ-RCE.git"
      },
      {
        "added_at": "2026-06-06T05:17:40Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/REGGYRAIDER/CVE-2023-46604-RCE.git"
      },
      {
        "added_at": "2024-01-09T03:18:19Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/hh-hunter/cve-2023-46604"
      },
      {
        "added_at": "2023-11-18T12:51:03Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/NKeshawarz/CVE-2023-46604-RCE"
      },
      {
        "added_at": "2023-11-15T19:11:01Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/vjayant93/CVE-2023-46604-POC.git"
      },
      {
        "added_at": "2024-04-17T13:10:34Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:vulncheck-oss/cve-2023-46604.git"
      },
      {
        "added_at": "2024-04-17T13:10:34Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/vulncheck-oss/cve-2023-46604"
      },
      {
        "added_at": "2024-03-05T07:09:21Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:Arlenhiack/ActiveMQ-RCE-Exploit.git"
      },
      {
        "added_at": "2023-12-07T08:02:53Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:dcm2406/CVELab.git"
      },
      {
        "added_at": "2025-02-27T02:49:18Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/skrkcb2/CVE-2023-46604.git"
      },
      {
        "added_at": "2026-06-06T05:17:40Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/REGGYRAIDER/CVE-2023-46604-RCE"
      },
      {
        "added_at": "2026-05-01T08:30:07Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/KlaasStessens/CVE-2023-46604"
      },
      {
        "added_at": "2026-01-04T12:35:24Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/RockyDesigne/SSP-Assignment-3-RCEYouLater"
      },
      {
        "added_at": "2026-06-12T12:48:15Z",
        "source": "metasploit",
        "url": "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/apache_activemq_rce_cve_2023_46604.rb"
      },
      {
        "added_at": "2024-10-16T03:31:13Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/cuanh2333/CVE-2023-46604.git"
      },
      {
        "added_at": "2023-11-09T11:27:20Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/h3x3h0g/ActiveMQ-RCE-CVE-2023-46604-Write-up"
      },
      {
        "added_at": "2023-11-04T11:58:21Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:evkl1d/CVE-2023-46604.git"
      },
      {
        "added_at": "2023-11-04T11:58:21Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/evkl1d/CVE-2023-46604"
      },
      {
        "added_at": "2025-05-04T14:42:01Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/CCIEVoice2009/CVE-2023-46604.git"
      },
      {
        "added_at": "2023-12-07T08:02:53Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/dcm2406/CVELab.git"
      },
      {
        "added_at": "2023-11-16T02:36:07Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/LiritoShawshark/CVE-2023-46604_ActiveMQ_RCE_Recurrence"
      },
      {
        "added_at": "2023-11-08T07:48:00Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/justdoit-cai/CVE-2023-46604-Apache-ActiveMQ-RCE-exp.git"
      },
      {
        "added_at": "2023-10-26T03:25:05Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/trganda/ActiveMQ-RCE.git"
      },
      {
        "added_at": "2026-03-30T20:45:04Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/mkdemir/activemq-lockbit-analysis"
      },
      {
        "added_at": "2025-05-04T14:42:01Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:CCIEVoice2009/CVE-2023-46604.git"
      },
      {
        "added_at": "2024-10-16T03:31:13Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/cuanh2333/CVE-2023-46604"
      },
      {
        "added_at": "2024-05-29T14:56:41Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/mranv/honeypot.rs"
      },
      {
        "added_at": "2024-05-29T14:56:41Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/mranv/honeypot.rs.git"
      },
      {
        "added_at": "2024-04-17T13:10:34Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/vulncheck-oss/cve-2023-46604.git"
      },
      {
        "added_at": "2023-12-23T08:41:01Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Mudoleto/Broker_ApacheMQ"
      },
      {
        "added_at": "2023-12-09T19:19:03Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:mrpentst/CVE-2023-46604.git"
      },
      {
        "added_at": "2024-02-14T18:39:49Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/stegano5/ExploitScript-CVE-2023-46604.git"
      },
      {
        "added_at": "2023-12-16T13:50:58Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:dcm2406/CVE-2023-46604.git"
      },
      {
        "added_at": "2023-11-20T11:57:24Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:nitzanoligo/CVE-2023-46604-demo.git"
      },
      {
        "added_at": "2023-11-08T07:48:00Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:justdoit-cai/CVE-2023-46604-Apache-ActiveMQ-RCE-exp.git"
      },
      {
        "added_at": "2023-10-27T05:57:21Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:X1r0z/ActiveMQ-RCE.git"
      },
      {
        "added_at": "2023-10-27T05:57:21Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/X1r0z/ActiveMQ-RCE"
      },
      {
        "added_at": "2024-05-31T00:38:47Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/pulentoski/CVE-2023-46604.git"
      },
      {
        "added_at": "2024-05-29T14:56:41Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:mranv/honeypot.rs.git"
      },
      {
        "added_at": "2024-02-14T18:39:49Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:stegano5/ExploitScript-CVE-2023-46604.git"
      },
      {
        "added_at": "2023-12-07T08:02:53Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/dcm2406/CVE-Lab"
      },
      {
        "added_at": "2023-11-12T11:26:46Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell.git"
      },
      {
        "added_at": "2023-12-23T08:41:01Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:Mudoleto/Broker_ApacheMQ.git"
      },
      {
        "added_at": "2023-12-16T13:50:58Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/dcm2406/CVE-2023-46604.git"
      },
      {
        "added_at": "2023-11-20T02:24:47Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/minhangxiaohui/ActiveMQ_CVE-2023-46604"
      },
      {
        "added_at": "2023-11-15T19:11:01Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:vjayant93/CVE-2023-46604-POC.git"
      },
      {
        "added_at": "2023-11-08T07:48:00Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/justdoit-cai/CVE-2023-46604-Apache-ActiveMQ-RCE-exp"
      },
      {
        "added_at": "2023-10-27T05:57:21Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/X1r0z/ActiveMQ-RCE.git"
      },
      {
        "added_at": "2025-09-08T21:03:58Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/vaishnavucv/Project-Vuln-Detection-N-Mitigation_101"
      },
      {
        "added_at": "2024-03-05T07:09:21Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Arlenhiack/ActiveMQ-RCE-Exploit"
      },
      {
        "added_at": "2023-11-20T07:19:40Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/CrackerCat/ActiveMQ_RCE_Pro_Max"
      },
      {
        "added_at": "2024-02-14T18:39:49Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/stegano5/ExploitScript-CVE-2023-46604"
      }
    ],
    "vuln_status": "confirmed",
    "citations": [
      {
        "added_at": "2025-03-07T17:08:15Z",
        "source": "nvd",
        "url": "http://seclists.org/fulldisclosure/2024/Apr/18"
      },
      {
        "added_at": "2025-03-07T17:08:15Z",
        "source": "nvd",
        "url": "https://www.openwall.com/lists/oss-security/2023/10/27/5"
      },
      {
        "added_at": "2026-06-03T07:20:38Z",
        "source": "nuclei_template",
        "url": "https://paper.seebug.org/3058/"
      },
      {
        "added_at": "2026-01-20T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.loginsoft.com/reports/annually/vulnerability-intelligence-report-2025"
      },
      {
        "added_at": "2026-01-14T00:00:00Z",
        "source": "vulncheck",
        "url": "https://sed-cms.broadcom.com/sites/default/files/2026-01/RWN-2026-WP100_1.pdf"
      },
      {
        "added_at": "2025-03-07T17:08:15Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2023/11/msg00013.html"
      },
      {
        "added_at": "2026-06-03T07:20:38Z",
        "source": "nuclei_template",
        "url": "https://github.com/X1r0z/ActiveMQ-RCE"
      },
      {
        "added_at": "2026-05-04T00:00:00Z",
        "source": "vulncheck",
        "url": "https://api.vulncheck.com/v3/index/vulncheck-canaries?cve=CVE-2023-46604&date=2026-05-04"
      },
      {
        "added_at": "2026-03-11T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.bitsight.com/blog/rondodox-botnet-infrastructure-analysis"
      },
      {
        "added_at": "2026-02-23T00:00:00Z",
        "source": "vulncheck",
        "url": "https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/"
      },
      {
        "added_at": "2026-01-08T00:00:00Z",
        "source": "vulncheck",
        "url": "https://aws.amazon.com/blogs/security/real-time-malware-defense-leveraging-aws-network-firewall-active-threat-defense/"
      },
      {
        "added_at": "2025-10-28T00:00:00Z",
        "source": "vulncheck",
        "url": "https://asec.ahnlab.com/en/90811/"
      },
      {
        "added_at": "2025-03-07T17:08:15Z",
        "source": "nvd",
        "url": "https://packetstormsecurity.com/files/175676/Apache-ActiveMQ-Unauthenticated-Remote-Code-Execution.html"
      },
      {
        "added_at": "2025-03-07T17:08:15Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20231110-0010/"
      },
      {
        "added_at": "2026-06-03T07:20:38Z",
        "source": "nuclei_template",
        "url": "http://www.openwall.com/lists/oss-security/2023/10/27/5"
      },
      {
        "added_at": "2026-05-07T00:00:00Z",
        "source": "vulncheck",
        "url": "https://securelist.com/vulnerabilities-and-exploits-in-q1-2026/119733/"
      },
      {
        "added_at": "2025-10-21T19:20:27Z",
        "source": "nvd",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-46604"
      },
      {
        "added_at": "2025-11-03T22:16:28Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2024/10/msg00027.html"
      },
      {
        "added_at": "2026-06-03T07:20:38Z",
        "source": "nuclei_template",
        "url": "https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt"
      },
      {
        "added_at": "2026-06-03T07:20:38Z",
        "source": "nuclei_template",
        "url": "https://attackerkb.com/topics/IHsgZDE3tS/cve-2023-46604/rapid7-analysis?referrer=etrblog"
      },
      {
        "added_at": "2026-03-26T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.vulncheck.com/blog/return-of-the-kinsing"
      },
      {
        "added_at": "2026-03-05T00:00:00Z",
        "source": "vulncheck",
        "url": "https://medium.com/@nshcthreatrecon/weekly-threat-intelligence-report-3-mar-2026-e50cc830efc4"
      }
    ],
    "cwe": [
      "CWE-502"
    ],
    "description": "Apache ActiveMQ contains a remote code execution caused by manipulation of serialized class types in the OpenWire protocol, letting remote attackers execute arbitrary shell commands, exploit requires network access.",
    "impact": "Remote attackers can execute arbitrary shell commands on the broker, potentially leading to full system compromise.",
    "name": "Apache ActiveMQ - Remote Code Execution",
    "remediation": "Upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "insecure_deserialization",
    "weaknesses": [
      {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data"
      }
    ],
    "category": "cve",
    "ref": "projectdiscovery/nuclei-templates:2768ab1b32e0",
    "release_tag": "v9.7.2",
    "is_pdteam": true,
    "filename": "CVE-2023-46604.yaml",
    "uri": "javascript/cves/2023/CVE-2023-46604.yaml",
    "author": [
      "ice3man",
      "mzack9999",
      "pdresearch"
    ],
    "metadata": {
      "max-request": 1,
      "product": "activemq",
      "shodan-query": [
        "product:\"ActiveMQ OpenWire Transport\"",
        "cpe:\"cpe:2.3:a:apache:activemq\"",
        "product:\"activemq openwire transport\""
      ],
      "vendor": "apache",
      "verified": true
    },
    "tags": [
      "cve",
      "cve2023",
      "network",
      "rce",
      "apache",
      "activemq",
      "deserialization",
      "js",
      "kev",
      "vkev",
      "vuln"
    ],
    "type": "javascript",
    "id": "CVE-2023-46604",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "activemq",
        "summary": "apache activemq is an open-source message broker that facilitates communication between distributed applications through messaging protocols. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "apache"
      },
      {
        "category": "core_infra",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "activemq_legacy_openwire_module",
        "summary": "apache activemq_legacy_openwire_module is a legacy protocol module that enables communication using the OpenWire protocol for Apache ActiveMQ messaging broker. It sits in the core_infra layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "e-series_santricity_unified_manager",
        "summary": "netapp e-series_santricity_unified_manager is a storage management software that provides unified monitoring and management for NetApp E-Series storage systems. It sits in the data_storage layer of the tech stack, functions as a self-hosted management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "e-series_santricity_web_services_proxy",
        "summary": "netapp e-series_santricity_web_services_proxy is a management and monitoring software proxy that facilitates communication with NetApp E-Series storage systems. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "app_plugins",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "santricity_storage_plugin",
        "summary": "netapp santricity_storage_plugin is a software plugin that integrates storage management capabilities for NetApp SANtricity storage systems. It sits in the app_plugins layer of the tech stack, functions as a plugin in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      }
    ],
    "created_at": "2023-10-27T15:15:14Z",
    "doc_id": "CVE-2023-46604",
    "doc_type": "cve_template",
    "exposure": {
      "max_hosts": 4038838,
      "min_hosts": 83700
    },
    "h1": {
      "rank": 2534,
      "reports": 1
    },
    "ntps": 85,
    "updated_at": "2026-06-12T12:48:44.41Z",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade apache - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2021-44228",
    "age_in_days": 1645,
    "assignee": "security@apache.org",
    "cve_created_at": "2021-12-10T10:15:09Z",
    "cve_updated_at": "2026-02-20T16:15:59Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 10,
    "epss_percentile": 0.99964,
    "epss_score": 0.94358,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "is_template": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2021-12-10T00:00:00Z",
        "due_date": "2021-12-24T00:00:00Z",
        "known_ransomware_campaign_use": true,
        "source": "cisa"
      },
      {
        "added_date": "2021-12-06T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 100,
    "poc_first_seen": "2021-12-10T10:15:09Z",
    "pocs": [
      {
        "added_at": "2021-12-10T10:15:09Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165261/Apache-Log4j2-2.14.1-Information-Disclosure.html"
      },
      {
        "added_at": "2021-12-10T10:15:09Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165673/UniFi-Network-Application-Unauthenticated-Log4Shell-Remote-Code-Execution.html"
      },
      {
        "added_at": "2026-03-22T07:38:42Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Saru1718/THM---Solar-exploiting-Log-4j"
      },
      {
        "added_at": "2026-02-26T18:39:00Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/zaryouhashraf/CVE-2021-44228"
      },
      {
        "added_at": "2026-02-05T19:41:28Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/agylabs/log4shell-remediation"
      },
      {
        "added_at": "2025-10-28T08:07:49Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:Mintimate/log4j2-bugmaker.git"
      },
      {
        "added_at": "2025-10-05T16:27:02Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/d4ngkh04w/CVE-2021-44228-Apache-Log4j"
      },
      {
        "added_at": "2025-09-09T15:59:25Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/moften/Log4Shell.git"
      },
      {
        "added_at": "2021-12-10T10:15:09Z",
        "source": "nvd",
        "url": "http://seclists.org/fulldisclosure/2022/Dec/2"
      },
      {
        "added_at": "2026-06-12T13:48:37Z",
        "source": "metasploit",
        "url": "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/ubiquiti_unifi_log4shell.rb"
      },
      {
        "added_at": "2026-04-22T19:05:01Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/pinaraltinok/Log4Shell-Attack"
      },
      {
        "added_at": "2025-09-09T15:59:25Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/moften/Log4Shell"
      },
      {
        "added_at": "2025-07-10T21:42:08Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:fabioeletto/hka-seminar-log4shell.git"
      },
      {
        "added_at": "2025-06-21T07:23:15Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/x1ongsec/CVE-2021-44228-Log4j-JNDI"
      },
      {
        "added_at": "2026-03-26T02:54:32Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/danieljosmariyan7254/TryHackMe-Solar-exploiting-log4j-"
      },
      {
        "added_at": "2026-01-14T21:18:59Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:JoseMariaMicoli/Log4Shell-PoC.git"
      },
      {
        "added_at": "2026-03-22T16:45:21Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Lavanya2085/solar-exploiting-log4j"
      },
      {
        "added_at": "2021-12-10T10:15:09Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165371/VMware-Security-Advisory-2021-0028.4.html"
      },
      {
        "added_at": "2021-12-10T10:15:09Z",
        "source": "nvd",
        "url": "https://www.nu11secur1ty.com/2021/12/cve-2021-44228.html"
      },
      {
        "added_at": "2026-06-04T23:42:19Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/horrister/log4shell-cve-2021-44228"
      },
      {
        "added_at": "2026-05-31T23:20:17Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/C00LN3T/Log4ShellAuditor.git"
      },
      {
        "added_at": "2025-11-05T15:47:47Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Ashwesker/Ashwesker-CVE-2021-44228"
      },
      {
        "added_at": "2026-05-30T11:22:48Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/jomjosh17/Log4Shell-CVE-2021-44228-"
      },
      {
        "added_at": "2026-05-12T00:33:47Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/vutiendat323/log4Shell-CVE-2021-44228"
      },
      {
        "added_at": "2026-05-02T05:17:53Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/sajanapamuditha/Cyber-Attack-Simulation-"
      },
      {
        "added_at": "2026-04-10T05:24:43Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/joaovicdev/EXPLOIT-CVE-2021-44228"
      },
      {
        "added_at": "2025-09-29T13:53:19Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:arabindadora/log4shell.git"
      },
      {
        "added_at": "2025-09-09T15:59:25Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:moften/Log4Shell.git"
      },
      {
        "added_at": "2025-07-10T21:42:08Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/fabioeletto/hka-seminar-log4shell"
      },
      {
        "added_at": "2025-03-12T01:01:47Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/tpdlshdmlrkfmcla/Log4shell"
      },
      {
        "added_at": "2026-06-12T13:48:37Z",
        "source": "metasploit",
        "url": "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/mobileiron_core_log4shell.rb"
      },
      {
        "added_at": "2026-05-05T06:59:35Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/FacundoMfernandez/pentesting-obioba"
      },
      {
        "added_at": "2026-04-28T09:07:54Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/tieupham267/log4shell-coraza.git"
      },
      {
        "added_at": "2025-12-20T16:08:19Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/dbwlsdnr95/CVE-2021-44228"
      },
      {
        "added_at": "2025-08-04T00:10:15Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Sorrence/CVE-2021-44228"
      },
      {
        "added_at": "2025-03-27T00:10:24Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/timothyjxhn/DeliberatelyVulnerableWebApp"
      },
      {
        "added_at": "2021-12-10T10:15:09Z",
        "source": "nvd",
        "url": "https://twitter.com/kurtseifried/status/1469345530182455296"
      },
      {
        "added_at": "2026-05-12T00:33:47Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/vutiendat323/CVE-2021-44228_Log4Shell"
      },
      {
        "added_at": "2026-04-09T18:01:53Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/jdormannn/SecureOps-Lab"
      },
      {
        "added_at": "2025-10-05T16:27:02Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:d4ngkh04w/CVE-2021-44228-Apache-Log4j.git"
      },
      {
        "added_at": "2025-09-29T13:53:19Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/arabindadora/log4shell.git"
      },
      {
        "added_at": "2025-08-04T00:10:15Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:Sorrence/CVE-2021-44228.git"
      },
      {
        "added_at": "2025-07-11T05:55:21Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/cuijiung/log4j-CVE-2021-44228"
      },
      {
        "added_at": "2025-11-05T15:47:47Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Ashwesker/Blackash-CVE-2021-44228"
      },
      {
        "added_at": "2025-10-05T16:27:02Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/d4ngkh04w/CVE-2021-44228-Apache-Log4j2"
      },
      {
        "added_at": "2026-06-03T14:14:26Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/bhimsekhar/vulnerable-java-app"
      },
      {
        "added_at": "2026-05-31T23:20:17Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/C00LN3T/Log4ShellAuditor"
      },
      {
        "added_at": "2026-04-27T22:35:05Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/kaleth4/CVE-2021-44228"
      },
      {
        "added_at": "2026-03-22T16:30:09Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/lathika-3006/Solar-exploiting-log-4j"
      },
      {
        "added_at": "2026-01-14T21:18:59Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/JoseMariaMicoli/Log4Shell-PoC.git"
      },
      {
        "added_at": "2025-11-18T09:26:42Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/PCMKUIT/CVE-2021-44228---Log4Shell-Analysis"
      },
      {
        "added_at": "2025-08-04T00:10:15Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/Sorrence/CVE-2021-44228.git"
      },
      {
        "added_at": "2025-05-08T07:52:54Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Fauzan-Aldi/Log4j-_Vulnerability"
      },
      {
        "added_at": "2021-12-10T10:15:09Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165532/Log4Shell-HTTP-Header-Injection.html"
      },
      {
        "added_at": "2026-05-02T05:51:52Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/neilc1964techned/craready-test-java-vulns"
      },
      {
        "added_at": "2026-01-14T21:18:59Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/JoseMariaMicoli/Log4Shell-PoC"
      },
      {
        "added_at": "2025-04-14T18:14:49Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:khaidtraivch/CVE-2021-44228-Log4Shell-.git"
      },
      {
        "added_at": "2025-03-12T01:01:47Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:user20252228/Log4shell.git"
      },
      {
        "added_at": "2026-06-04T23:42:19Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/horrister/log4shell-cve-2021-44228.git"
      },
      {
        "added_at": "2025-07-10T21:42:08Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/fabioeletto/hka-seminar-log4shell.git"
      },
      {
        "added_at": "2025-04-14T18:14:49Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/khaidtraivch/CVE-2021-44228-Log4Shell-.git"
      },
      {
        "added_at": "2026-04-28T09:07:54Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/tieupham267/log4shell-coraza"
      },
      {
        "added_at": "2025-12-20T16:08:19Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/dbwlsdnr95/CVE-2021-44228-log4shell"
      },
      {
        "added_at": "2026-03-15T04:21:21Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Codepumpking/log4shell-poc"
      },
      {
        "added_at": "2021-12-10T10:15:09Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165642/VMware-vCenter-Server-Unauthenticated-Log4Shell-JNDI-Injection-Remote-Code-Execution.html"
      },
      {
        "added_at": "2021-12-10T10:15:09Z",
        "source": "nvd",
        "url": "https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-44228"
      },
      {
        "added_at": "2026-06-12T13:48:37Z",
        "source": "metasploit",
        "url": "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/log4shell_header_injection.rb"
      },
      {
        "added_at": "2026-06-09T11:38:00Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/hmxh123/Log4Shell-Vulnerability-Replication"
      },
      {
        "added_at": "2025-12-05T17:25:39Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/DrHaitham/Log4Shell-CVE-2021-44228"
      },
      {
        "added_at": "2021-12-10T10:15:09Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165270/Apache-Log4j2-2.14.1-Remote-Code-Execution.html"
      },
      {
        "added_at": "2026-04-19T14:40:29Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/davindersingh74569-lang/HTB-Unified-Writeup"
      },
      {
        "added_at": "2026-02-26T18:39:00Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/0xBlackash/CVE-2021-44228"
      },
      {
        "added_at": "2025-11-05T15:47:47Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/B1ack4sh/Blackash-CVE-2021-44228"
      },
      {
        "added_at": "2025-11-05T15:47:47Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/Ashwesker/Blackash-CVE-2021-44228.git"
      },
      {
        "added_at": "2025-10-28T08:07:49Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Mintimate/log4j2-bugmaker"
      },
      {
        "added_at": "2025-09-27T11:26:58Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/KamalideenAK/Microsoft-Defender-for-Endpoint-Deployment-on-Windows-10-11-device"
      },
      {
        "added_at": "2025-05-27T04:23:26Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:SerpilRivas/log4shell-homework9.git"
      },
      {
        "added_at": "2026-05-05T06:59:35Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/FacundoMfernandez/-pentesting-obioba"
      },
      {
        "added_at": "2025-04-14T18:14:49Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/khaidtraivch/CVE-2021-44228-Log4Shell-"
      },
      {
        "added_at": "2026-06-12T13:48:37Z",
        "source": "metasploit",
        "url": "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/vmware_vcenter_log4shell.rb"
      },
      {
        "added_at": "2026-05-31T23:20:17Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/C00LN3T/SpringAudit"
      },
      {
        "added_at": "2026-05-26T13:35:36Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/zoubir-sahnoun/log4shell-poc-maven"
      },
      {
        "added_at": "2026-05-16T01:52:21Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/aaronm-sysdig/log4j-vuln-demo"
      },
      {
        "added_at": "2026-02-26T18:39:00Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/0xAshwesker/CVE-2021-44228"
      },
      {
        "added_at": "2025-11-16T18:41:14Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/mgueye3/Log4Shell"
      },
      {
        "added_at": "2025-11-05T15:47:47Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:Ashwesker/Blackash-CVE-2021-44228.git"
      },
      {
        "added_at": "2025-10-05T16:27:02Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/d4ngkh04w/CVE-2021-44228-Apache-Log4j.git"
      },
      {
        "added_at": "2026-04-10T05:24:43Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/joaovicdev/EXPLOIT-CVE-2021-44228.git"
      },
      {
        "added_at": "2026-03-17T13:45:04Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/wmohamed2033/wmohamed2033.github.io"
      },
      {
        "added_at": "2026-03-15T04:21:21Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/Codepumpking/log4shell-poc.git"
      },
      {
        "added_at": "2025-09-29T13:53:19Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/arabindadora/log4shell"
      },
      {
        "added_at": "2025-05-27T04:23:26Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/SerpilRivas/log4shell-homework9"
      },
      {
        "added_at": "2025-05-27T04:23:26Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/SerpilRivas/log4shell-homework9.git"
      },
      {
        "added_at": "2025-03-12T01:01:47Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/user20252228/Log4shell.git"
      },
      {
        "added_at": "2021-12-10T10:15:09Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/167917/MobileIron-Log4Shell-Remote-Command-Execution.html"
      },
      {
        "added_at": "2026-05-23T01:24:46Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/felisha-elmer/Sandbox-Challenge-Log4Shell-CVE-2021-44228-"
      },
      {
        "added_at": "2026-05-18T00:59:16Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/MAFO-sec/mi-laboratorio-log4shell"
      },
      {
        "added_at": "2025-12-14T19:57:59Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Loliverte/Log4j-Vulnerability"
      },
      {
        "added_at": "2025-10-28T08:07:49Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/Mintimate/log4j2-bugmaker.git"
      },
      {
        "added_at": "2025-07-25T04:32:54Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Alan-coder-eng/log4j-cve-2021-44228-"
      }
    ],
    "vuln_status": "confirmed",
    "citations": [
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165371/VMware-Security-Advisory-2021-0028.4.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-714170.pdf"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2021/12/msg00007.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpujan2022.html"
      },
      {
        "added_at": "2026-03-16T00:00:00Z",
        "source": "vulncheck",
        "url": "https://horizon3.ai/wp-content/uploads/2026/03/Iranian_APT_TTP_Report_2026.pdf"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165282/Log4j-Payload-Generator.html"
      },
      {
        "added_at": "2026-05-27T00:54:38Z",
        "source": "nuclei_template",
        "url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165270/Apache-Log4j2-2.14.1-Remote-Code-Execution.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2021/12/10/1"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2021/12/10/2"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165260/VMware-Security-Advisory-2021-0028.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165306/L4sh-Log4j-Remote-Code-Execution.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165532/Log4Shell-HTTP-Header-Injection.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165642/VMware-vCenter-Server-Unauthenticated-Log4Shell-JNDI-Injection-Remote-Code-Execution.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/171626/AD-Manager-Plus-7122-Remote-Code-Execution.html"
      },
      {
        "added_at": "2026-05-27T00:54:38Z",
        "source": "nuclei_template",
        "url": "https://logging.apache.org/log4j/2.x/security.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://support.apple.com/kb/HT213189"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165261/Apache-Log4j2-2.14.1-Information-Disclosure.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://seclists.org/fulldisclosure/2022/Mar/23"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2021/12/14/4"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://www.kb.cert.org/vuls/id/930724"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://www.nu11secur1ty.com/2021/12/cve-2021-44228.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://github.com/cisagov/log4j-affected-db"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0032"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M5CSVUNV4HWZZXGOKNSK6L7RPM7BOKIB/"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2021/12/10/3"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://www.bentley.com/en/common-vulnerability-exposure/be-2022-0001"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00646.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpuapr2022.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://seclists.org/fulldisclosure/2022/Dec/2"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20211210-0007/"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://www.debian.org/security/2021/dsa-5020"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165307/Log4j-Remote-Code-Execution-Word-Bypassing.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VU57UJDCFIASIO35GC55JMKSRXJMCDFM/"
      },
      {
        "added_at": "2026-05-27T00:54:38Z",
        "source": "nuclei_template",
        "url": "https://gist.github.com/bugbountynights/dde69038573db1c12705edb39f9a704a"
      },
      {
        "added_at": "2026-04-09T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.cloudsek.com/blog/kitten-had-the-map-all-along-raising-gcc-tensions-the-pre-positioning-map"
      },
      {
        "added_at": "2026-06-04T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.stormshield.com/news/current-cyberattack-trends-variations-honeypots/"
      },
      {
        "added_at": "2026-03-31T00:00:00Z",
        "source": "vulncheck",
        "url": "https://fortiguard.fortinet.com/outbreak-alert/iran-linked-cyber-attacks"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/167917/MobileIron-Log4Shell-Remote-Command-Execution.html"
      },
      {
        "added_at": "2026-05-27T00:54:38Z",
        "source": "nuclei_template",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
      },
      {
        "added_at": "2026-05-27T00:54:38Z",
        "source": "nuclei_template",
        "url": "https://www.lunasec.io/docs/blog/log4j-zero-day/"
      },
      {
        "added_at": "2026-03-13T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.sophos.com/en-us/blog/initial-access-techniques-used-by-iran-based-threat-actors"
      },
      {
        "added_at": "2026-03-06T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.picussecurity.com/resource/iranian-threat-actors-what-defenders-need-to-know"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165281/Log4j2-Log4Shell-Regexes.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2021/12/13/1"
      },
      {
        "added_at": "2026-06-11T00:00:00Z",
        "source": "vulncheck",
        "url": "https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/map/?day=2026-06-11&host_type=src&vulnerability=cve-2021-44228"
      },
      {
        "added_at": "2026-05-07T00:00:00Z",
        "source": "vulncheck",
        "url": "https://securelist.com/vulnerabilities-and-exploits-in-q1-2026/119733/"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165673/UniFi-Network-Application-Unauthenticated-Log4Shell-Remote-Code-Execution.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/167794/Open-Xchange-App-Suite-7.10.x-Cross-Site-Scripting-Command-Injection.html"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://seclists.org/fulldisclosure/2022/Jul/11"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2021/12/13/2"
      },
      {
        "added_at": "2026-05-29T00:00:00Z",
        "source": "vulncheck",
        "url": "https://api.vulncheck.com/v3/index/vulncheck-canaries?cve=CVE-2021-44228&date=2026-05-29"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-661247.pdf"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-44228"
      },
      {
        "added_at": "2025-10-21T19:19:26Z",
        "source": "nvd",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-44228"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2021/12/15/3"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-397453.pdf"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-479842.pdf"
      },
      {
        "added_at": "2026-03-23T00:00:00Z",
        "source": "vulncheck",
        "url": "https://storage.ghost.io/c/af/a0/afa04ee3-414f-4481-8d23-7e7c146f192e/content/files/2026/03/2025YiR-report.pdf"
      },
      {
        "added_at": "2025-04-03T20:53:22Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html"
      }
    ],
    "cwe": [
      "CWE-20",
      "CWE-917"
    ],
    "description": "Apache Log4j2 <=2.14.1 contains a remote code execution caused by unprotected JNDI features in configuration, log messages, and parameters, letting attackers control LDAP and other JNDI endpoints to execute arbitrary code, exploit requires attacker-controlled log messages or parameters.",
    "impact": "Attackers can execute arbitrary code remotely by controlling log messages, leading to full system compromise.",
    "name": "Apache Log4j2 - JNDI Injection",
    "remediation": "Update to Log4j2 version 2.15.0 or later to disable JNDI lookups by default.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "jndi_injection",
    "weaknesses": [
      {
        "cwe_id": "CWE-20",
        "cwe_name": "Improper Input Validation"
      },
      {
        "cwe_id": "CWE-917",
        "cwe_name": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')"
      }
    ],
    "category": "cve",
    "ref": "projectdiscovery/nuclei-templates:33fbe539302e",
    "release_tag": "v8.7.1",
    "is_pdteam": true,
    "filename": "CVE-2021-44228.yaml",
    "uri": "http/cves/2021/CVE-2021-44228.yaml",
    "author": [
      "melbadry9",
      "dhiyaneshdk",
      "daffainfo",
      "anon-artist",
      "0xceba",
      "tea",
      "j4vaovo"
    ],
    "metadata": {
      "max-request": 2,
      "product": "log4j",
      "vendor": "apache"
    },
    "tags": [
      "cve2021",
      "cve",
      "rce",
      "oast",
      "log4j",
      "injection",
      "kev",
      "apache",
      "vkev",
      "vuln"
    ],
    "type": "http",
    "id": "CVE-2021-44228",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "paging_server",
        "summary": "cisco sd-wan_vmanage is a centralized network management system that provides orchestration and monitoring for SD-WAN deployments. It sits in the core_infra layer of the tech stack, functions as a self-hosted network management platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "energy_utilities",
        "product": "head-end_system_universal_device_integration_system",
        "summary": "siemens head-end_system_universal_device_integration_system is a device integration and management system that collects and processes data from various field devices in utility networks. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure component in the software supply chain, and—within the energy_utilities industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "6bk1602-0aa12-0tp0_firmware",
        "summary": "siemens 6bk1602-0aa12-0tp0_firmware is a firmware component designed for industrial automation hardware that controls and manages device operations. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "energy_utilities",
        "product": "sppa-t3000_ses3000_firmware",
        "summary": "siemens sppa-t3000_ses3000_firmware is a firmware component that controls and manages power plant turbine systems. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the energy_utilities industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "energy_utilities",
        "product": "energy_engage",
        "summary": "siemens energy_engage is a digital energy management platform that optimizes energy consumption and sustainability for utilities and enterprises. It sits in the core_infra layer of the tech stack, functions as a software service in the software supply chain, and—within the energy_utilities industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "navigator",
        "summary": "siemens navigator is a digital operations platform that provides data-driven insights and analytics for industrial processes. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the industrial_control industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "cyber_vision_sensor_management_extension",
        "summary": "cisco data_center_network_manager is a network management software that provides centralized control and automation for data center networks. It sits in the core_infra layer of the tech stack, functions as an enterprise application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "cyber_vision",
        "summary": "cisco dna_spaces_connector is a connectivity and integration tool that enables location-based services and analytics by connecting devices to Cisco DNA Spaces platform. It sits in the core_infra layer of the tech stack, functions as a service connector in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "network_dashboard_fabric_controller",
        "summary": "cisco ucs_central_software is a centralized management software that simplifies and automates data center infrastructure management. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "advanced_malware_protection_virtual_private_cloud_appliance",
        "summary": "cisco advanced_malware_protection_virtual_private_cloud_appliance is a cloud-based security solution that provides advanced malware detection and prevention for virtual private cloud environments. It sits in the core_infra layer of the tech stack, functions as a security appliance in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "broadworks",
        "summary": "cisco business_process_automation is a platform designed to automate and optimize business workflows and processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "network_assurance_engine",
        "summary": "cisco network_services_orchestrator is a network automation and orchestration platform that simplifies the management of complex network services. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "virtualized_infrastructure_manager",
        "summary": "cisco wan_automation_engine is a network automation and orchestration solution that simplifies WAN management and optimizes network performance. It sits in the core_infra layer of the tech stack, functions as a self-hosted network management platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "firepower_threat_defense",
        "summary": "cisco network_dashboard_fabric_controller is a network fabric management and orchestration tool that simplifies the deployment and monitoring of network fabrics. It sits in the core_infra layer of the tech stack, functions as a self-hosted network controller in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "cloud_insights",
        "summary": "netapp cloud_insights is an infrastructure monitoring and optimization tool that provides visibility into cloud and on-premises environments. It sits in the core_infra layer of the tech stack, functions as a software-as-a-service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "energy_utilities",
        "product": "energyip",
        "summary": "siemens energyip is an advanced energy data management and analytics platform that optimizes utility operations and grid management. It sits in the core_infra layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the energy_utilities industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "energy_utilities",
        "product": "energyip_prepay",
        "summary": "siemens energyip_prepay is a prepaid energy management solution that enables utilities to manage and monitor prepaid electricity consumption. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the energy_utilities industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "industrial_control",
        "product": "logo\\!_soft_comfort",
        "summary": "siemens logo!_soft_comfort is a programming software tool designed for configuring and simulating Siemens LOGO! logic modules used in automation. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "snapcenter",
        "summary": "netapp snapcenter is a centralized data protection and management software that simplifies backup, recovery, and cloning of enterprise data. It sits in the data_storage layer of the tech stack, functions as a core infrastructure tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "unified_contact_center_enterprise",
        "summary": "cisco unified_customer_voice_portal is a customer interaction management solution that enables voice self-service and call routing for contact centers. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ucs_central_software",
        "summary": "cisco unified_computing_system is a data center server and network infrastructure platform that integrates computing, networking, and storage resources. It sits in the hardware layer of the tech stack, functions as a self-hosted infrastructure solution in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "log4j",
        "summary": "apache log4j is a Java-based logging utility that provides flexible and reliable logging capabilities for applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "industrial_edge_management_hub",
        "summary": "siemens industrial_edge_management_hub is an edge computing platform that enables management and orchestration of industrial edge applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure platform in the software supply chain, and—within the industrial_control industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "manufacturing",
        "product": "solid_edge_cam_pro",
        "summary": "siemens solid_edge_cam_pro is a computer-aided manufacturing (CAM) software that provides advanced machining and manufacturing solutions. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "synchro",
        "summary": "percussion rhythmyx is a web content management system that enables organizations to create, manage, and deliver digital content across multiple channels. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "bentley"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "solidfire_\\&_hci_storage_node",
        "summary": "netapp solidfire_&_hci_storage_node is a high-performance storage solution that provides scalable and reliable storage infrastructure for hyper-converged environments. It sits in the data_storage layer of the tech stack, functions as a self-hosted storage system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "network_insights_for_data_center",
        "summary": "cisco unified_communications_manager_im_&_presence_service is a real-time messaging and presence platform that enables enterprise communication and collaboration. It sits in the core_infra layer of the tech stack, functions as a communication service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "video_surveillance_manager",
        "summary": "snowsoftware vm_access_proxy is a secure access proxy solution that facilitates controlled and monitored access to virtual machines. It sits in the core_infra layer of the tech stack, functions as a security infrastructure component in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "siveillance_control_pro",
        "summary": "siemens siveillance_control_pro is a security management system that integrates video surveillance and access control for enhanced facility security. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "common_services_platform_collector",
        "summary": "cisco connected_mobile_experiences is a mobile network analytics and optimization solution that enhances user experience and network performance. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "identity_services_engine",
        "summary": "cisco integrated_management_controller_supervisor is a hardware management controller that provides out-of-band management and monitoring for Cisco servers. It sits in the hardware layer of the tech stack, functions as a hardware management component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nexus_dashboard",
        "summary": "cisco nexus_insights is a network analytics and monitoring solution that provides real-time insights to optimize data center performance. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "workload_optimization_manager",
        "summary": "cisco unified_workforce_optimization is a workforce management and optimization solution that enhances employee productivity and operational efficiency. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "synchro_4d",
        "summary": "apple xcode is an integrated development environment (IDE) that provides tools for software development on Apple platforms. It sits in the application_library layer of the tech stack, functions as a development tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "bentley"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "6bk1602-0aa22-0tp0_firmware",
        "summary": "siemens 6bk1602-0aa22-0tp0_firmware is a firmware component that controls and manages industrial automation hardware. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
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
        "industry": "telecommunications",
        "product": "automated_subsea_tuning",
        "summary": "cisco broadworks is a cloud-based unified communications platform that delivers voice, video, and collaboration services. It sits in the core_infra layer of the tech stack, functions as a self-hosted or SaaS communication service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "contact_center_domain_manager",
        "summary": "cisco contact_center_management_portal is a web-based management interface that enables administrators to configure and monitor contact center operations. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the telecommunications industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "crosswork_network_controller",
        "summary": "cisco crosswork_optimization_engine is a network optimization and automation platform that enhances operational efficiency and service quality. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "finesse",
        "summary": "cisco fog_director is an edge computing management platform that enables deployment and orchestration of applications at the network edge. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure management tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "sd-wan_vmanage",
        "summary": "cisco ucs_central is a centralized management solution that simplifies and automates data center infrastructure management. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "crosswork_zero_touch_provisioning",
        "summary": "cisco customer_experience_cloud_agent is a cloud-based customer experience management solution that helps businesses monitor and improve customer interactions. It sits in the enterprise layer of the tech stack, functions as a software-as-a-service in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "iot_operations_dashboard",
        "summary": "cisco network_assurance_engine is a network analytics and assurance platform that provides continuous verification and troubleshooting for enterprise networks. It sits in the core_infra layer of the tech stack, functions as a self-hosted network management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "prime_service_catalog",
        "summary": "cisco smart_phy is a programmable physical layer solution that enhances network performance and flexibility. It sits in the hardware layer of the tech stack, functions as a self-hosted infrastructure component in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "unclassified",
        "product": "unified_intelligence_center",
        "summary": "cisco video_surveillance_operations_manager is a centralized video surveillance management system that enables monitoring and control of security cameras and video data. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "unified_sip_proxy",
        "summary": "cisco fxos is a network operating system that provides a unified software platform for managing Cisco's network hardware devices. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "dna_spaces_connector",
        "summary": "cisco mobility_services_engine is a network services platform that provides location-based services and analytics for wireless networks. It sits in the core_infra layer of the tech stack, functions as a self-hosted network service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_insight",
        "summary": "netapp oncommand_insight is an infrastructure analytics and monitoring solution that provides visibility and optimization for storage and data center resources. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ucs_central",
        "summary": "cisco unified_communications_manager is a call control and session management platform that enables enterprise voice, video, messaging, and mobility services. It sits in the core_infra layer of the tech stack, functions as an enterprise communication system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "mobility_services_engine",
        "summary": "cisco network_insights_for_data_center is a network analytics and assurance solution that provides visibility and insights into data center network performance and security. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "mendix",
        "summary": "siemens mendix is a low-code application development platform that enables rapid creation and deployment of enterprise applications. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "secure_device_onboard",
        "summary": "intel secure_device_onboard is a secure provisioning solution that simplifies device onboarding and authentication for IoT devices. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "intel"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "contact_center_management_portal",
        "summary": "cisco crosswork_data_gateway is a network data integration and analytics platform that enables real-time data collection and processing for network operations. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "manufacturing",
        "product": "vm_access_proxy",
        "summary": "bentley synchro_4d is a construction project management and 4D scheduling software that enhances project visualization and coordination. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "snowsoftware"
      },
      {
        "category": "enterprise",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "intersight_virtual_appliance",
        "summary": "cisco iot_operations_dashboard is a centralized management platform that provides monitoring and operational insights for IoT devices and networks. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "unified_communications_manager_im_and_presence_service",
        "summary": "cisco unified_contact_center_express is a customer contact center solution that enables efficient management of customer interactions across multiple channels. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "vesys",
        "summary": "siemens vesys is an engineering software solution that supports the design and analysis of electrical systems. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "desigo_cc_advanced_reports",
        "summary": "siemens desigo_cc_advanced_reports is an advanced reporting tool designed for building management and automation systems that enhances data analysis and operational insights. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "e-car_operation_center",
        "summary": "siemens e-car_operation_center is a management and monitoring system designed for electric vehicle operations that optimizes fleet performance and charging infrastructure. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "siveillance_vantage",
        "summary": "siemens siveillance_vantage is a comprehensive video management system that enables real-time surveillance and security monitoring. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "genomics_kernel_library",
        "summary": "intel genomics_kernel_library is a specialized software library that provides optimized computational kernels for genomic data processing. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "intel"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "oneapi_sample_browser",
        "summary": "intel oneapi_sample_browser is a sample code browser that helps developers explore and learn oneAPI programming models and libraries. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "intel"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "cloudcenter_workload_manager",
        "summary": "cisco common_services_platform_collector is a data collection and telemetry agent that gathers and forwards operational data for network and infrastructure monitoring. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "connected_mobile_experiences",
        "summary": "cisco contact_center_domain_manager is a contact center management solution that optimizes customer interaction workflows and resource allocation. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "dna_center",
        "summary": "cisco dna_spaces is a location-based services platform that provides analytics and insights for physical spaces. It sits in the core_infra layer of the tech stack, functions as a software-as-a-service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "6bk1602-0aa52-0tp0_firmware",
        "summary": "siemens 6bk1602-0aa52-0tp0_firmware is a firmware component designed to control and manage industrial automation hardware. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "siveillance_command",
        "summary": "siemens siveillance_command is a security management system that integrates and controls video surveillance and access control devices. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "business_process_automation",
        "summary": "cisco cloud_connect is a cloud networking solution that enables secure and optimized connectivity between enterprise networks and cloud environments. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "emergency_responder",
        "summary": "cisco enterprise_chat_and_email is a unified communication platform that integrates chat and email services for enterprise collaboration. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "network_services_orchestrator",
        "summary": "cisco nexus_dashboard is a network management and analytics platform that provides centralized visibility and automation for data center networks. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "smart_phy",
        "summary": "cisco ucs_director is a data center automation and orchestration platform that simplifies management of physical and virtual infrastructure. It sits in the core_infra layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "optical_network_controller",
        "summary": "cisco packaged_contact_center_enterprise is a comprehensive contact center solution that enables efficient customer interaction management. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "industrial_edge_management",
        "summary": "siemens industrial_edge_management is an edge computing platform that enables real-time data processing and management for industrial environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure platform in the software supply chain, and—within the industrial_control industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "manufacturing",
        "product": "solid_edge_harness_design",
        "summary": "siemens solid_edge_harness_design is a specialized CAD software for designing electrical wiring harnesses that enhances the accuracy and efficiency of electrical system layouts. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "solidfire_enterprise_sds",
        "summary": "netapp solidfire_enterprise_sds is a software-defined storage solution that delivers scalable and high-performance block storage for enterprise applications. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "cloud_connect",
        "summary": "cisco cloudcenter is a cloud management platform that enables deployment and governance of applications across multiple cloud environments. It sits in the core_infra layer of the tech stack, functions as a platform service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "nexus_insights",
        "summary": "cisco optical_network_controller is a network management software that controls and optimizes optical transport networks. It sits in the core_infra layer of the tech stack, functions as a self-hosted network controller in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "virtualized_voice_browser",
        "summary": "cisco webex_meetings_server is an on-premises video conferencing and collaboration platform that enables secure and scalable virtual meetings. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "wan_automation_engine",
        "summary": "cisco workload_optimization_manager is an infrastructure management solution that optimizes workload placement and resource utilization across hybrid cloud environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted management platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "webex_meetings_server",
        "summary": "cisco unified_sip_proxy is a session initiation protocol (SIP) proxy server that manages and routes SIP signaling for voice and video communications. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "unified_contact_center_express",
        "summary": "cisco unified_intelligence_center is an analytics and reporting platform that provides unified insights across Cisco collaboration products. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "manufacturing",
        "product": "capital",
        "summary": "siemens capital is an electronic design automation (EDA) software suite that enables the design and management of complex electrical systems. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "unclassified",
        "product": "xpedition_package_integrator",
        "summary": "siemens xpedition_package_integrator is an electronic design automation tool that facilitates package design and integration for semiconductor devices. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "cloudcenter",
        "summary": "cisco cloudcenter_cost_optimizer is a cloud cost management and optimization tool that helps organizations reduce and control cloud spending. It sits in the core_infra layer of the tech stack, functions as a self-hosted or SaaS service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "packaged_contact_center_enterprise",
        "summary": "cisco prime_service_catalog is an IT service management solution that enables organizations to create, manage, and deliver IT services efficiently. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "unified_workforce_optimization",
        "summary": "cisco cloudcenter_suite is a hybrid cloud management platform that enables deployment and governance of applications across multiple cloud environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted and SaaS hybrid platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "desigo_cc_info_center",
        "summary": "siemens desigo_cc_info_center is a building management and automation platform that integrates various building systems for centralized control and monitoring. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "siveillance_viewpoint",
        "summary": "siemens siveillance_viewpoint is a video management software that provides centralized monitoring and control for security systems. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "datacenter_manager",
        "summary": "intel datacenter_manager is a data center infrastructure management software that optimizes and monitors data center operations and hardware performance. It sits in the core_infra layer of the tech stack, functions as a self-hosted management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "intel"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "industrial_control",
        "product": "customer_experience_cloud_agent",
        "summary": "cisco cyber_vision_sensor_management_extension is an extension module that enhances sensor management capabilities for industrial cybersecurity. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the industrial_control industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "6bk1602-0aa42-0tp0_firmware",
        "summary": "siemens 6bk1602-0aa42-0tp0_firmware is a firmware component designed to control and operate industrial automation hardware. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "data_center_network_manager",
        "summary": "cisco dna_center is a network management and automation platform that simplifies enterprise network operations and enhances security. It sits in the core_infra layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ucs_director",
        "summary": "cisco unified_communications_manager_im_and_presence_service is a real-time messaging and presence service that enables instant communication and collaboration within enterprise networks. It sits in the core_infra layer of the tech stack, functions as a communication service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "unified_contact_center_management_portal",
        "summary": "snowsoftware snow_commander is a software asset management solution that provides visibility and control over software usage and licenses. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "brocade_san_navigator",
        "summary": "netapp brocade_san_navigator is a storage area network (SAN) management software that provides monitoring and configuration capabilities for Brocade SAN switches. It sits in the core_infra layer of the tech stack, functions as an enterprise application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "crosswork_optimization_engine",
        "summary": "cisco crosswork_platform_infrastructure is a network automation and assurance platform that optimizes and simplifies network operations. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "evolved_programmable_network_manager",
        "summary": "cisco finesse is a contact center agent desktop software that provides a customizable and efficient interface for customer service representatives. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "unified_communications_manager",
        "summary": "cisco unified_contact_center_enterprise is a comprehensive contact center solution that manages customer interactions across multiple channels. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "unified_communications_manager_im_\\&_presence_service",
        "summary": "cisco unified_contact_center_management_portal is a centralized management portal for contact center operations that enables efficient administration and monitoring of customer service environments. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "cloudcenter_suite_admin",
        "summary": "cisco cloudcenter_workload_manager is a cloud management platform that automates deployment and governance of workloads across multiple cloud environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted and SaaS hybrid platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "manufacturing",
        "product": "opcenter_intelligence",
        "summary": "siemens opcenter_intelligence is a manufacturing operations management software that provides advanced analytics and insights to optimize production processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "computer_vision_annotation_tool",
        "summary": "intel computer_vision_annotation_tool is a software application designed to facilitate the annotation of images and videos for computer vision model training. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "intel"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fog_director",
        "summary": "cisco identity_services_engine is a network access control and policy management solution that provides secure access and threat protection for enterprise networks. It sits in the core_infra layer of the tech stack, functions as a security platform in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "virtual_topology_system",
        "summary": "cisco virtualized_voice_browser is a software platform that enables voice application hosting and management in virtualized environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "cloudcenter_suite",
        "summary": "cisco cx_cloud_agent is a cloud-based agent software that facilitates customer experience management and analytics. It sits in the core_infra layer of the tech stack, functions as a service agent in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "cx_cloud_agent",
        "summary": "cisco dna_spaces is a location-based services platform that provides analytics and insights for physical spaces to enhance user experiences and operational efficiency. It sits in the core_infra layer of the tech stack, functions as a software-as-a-service platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "active_iq_unified_manager",
        "summary": "netapp active_iq_unified_manager is a unified storage management and monitoring solution that provides proactive insights and analytics for storage infrastructure. It sits in the core_infra layer of the tech stack, functions as a self-hosted management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fxos",
        "summary": "cisco crosswork_network_automation is a network automation and assurance platform that simplifies and optimizes network operations. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "snow_commander",
        "summary": "bentley synchro is a construction project management and scheduling software that enhances planning and execution of construction projects. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "snowsoftware"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "energy_utilities",
        "product": "sentron_powermanager",
        "summary": "siemens sentron_powermanager is an energy management software that monitors and optimizes power consumption and distribution. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the energy_utilities industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "energy_utilities",
        "product": "spectrum_power_4",
        "summary": "siemens spectrum_power_4 is an advanced energy management system that optimizes power grid operations and enhances grid reliability. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the energy_utilities industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "manufacturing",
        "product": "teamcenter",
        "summary": "siemens teamcenter is a product lifecycle management (PLM) software that helps organizations manage product data and processes across the lifecycle. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "video_surveillance_operations_manager",
        "summary": "cisco virtualized_infrastructure_manager is a network virtualization and infrastructure management solution that enables orchestration and control of virtualized resources. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure management tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "product": "xcode",
        "vendor": "apple"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "operation_scheduler",
        "summary": "siemens operation_scheduler is an industrial control software that manages and schedules manufacturing and production operations. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "manufacturing",
        "product": "xpedition_enterprise",
        "summary": "siemens xpedition_enterprise is an advanced electronic design automation (EDA) software suite that enables PCB design and manufacturing optimization. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_chat_and_email",
        "summary": "cisco evolved_programmable_network_manager is a network management and orchestration solution that automates and optimizes network operations. It sits in the core_infra layer of the tech stack, functions as an enterprise application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "unity_connection",
        "summary": "cisco virtual_topology_system is a network topology visualization and management solution that provides real-time network insights and control. It sits in the core_infra layer of the tech stack, functions as a self-hosted network management system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "email_security",
        "summary": "sonicwall email_security is an email protection solution that safeguards organizations from spam, phishing, and malware attacks. It sits in the core_infra layer of the tech stack, functions as a security service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "sonicwall"
      },
      {
        "category": "data_storage",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "cloud_manager",
        "summary": "netapp cloud_manager is a cloud data services management platform that simplifies data storage and management across hybrid and multi-cloud environments. It sits in the data_storage layer of the tech stack, functions as a self-hosted and SaaS hybrid solution in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "netapp"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "manufacturing",
        "product": "nx",
        "summary": "siemens nx is an advanced computer-aided design (CAD) and manufacturing software that enables product engineering and digital twin creation. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "6bk1602-0aa32-0tp0_firmware",
        "summary": "siemens 6bk1602-0aa32-0tp0_firmware is a firmware component that controls and manages industrial automation hardware. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "dna_spaces\\",
        "summary": "cisco emergency_responder is a location-aware emergency call management system that enhances public safety by accurately identifying caller locations. It sits in the core_infra layer of the tech stack, functions as an enterprise communication solution in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "unclassified",
        "product": "unified_computing_system",
        "summary": "cisco video_surveillance_manager is a video management system that enables centralized monitoring and control of surveillance cameras. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "product": "rhythmyx",
        "vendor": "percussion"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "industrial_control",
        "product": "mindsphere",
        "summary": "siemens mindsphere is an industrial IoT platform that connects products, plants, systems, and machines to harness data for analytics and optimization. It sits in the core_infra layer of the tech stack, functions as a software platform in the software supply chain, and—within the industrial_control industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "system_studio",
        "summary": "intel system_studio is an integrated development environment (IDE) designed to optimize embedded and IoT applications. It sits in the application_library layer of the tech stack, functions as a development tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "intel"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "cloudcenter_cost_optimizer",
        "summary": "cisco cloudcenter_suite_admin is an administrative tool for managing cloud deployments and optimizing application delivery across hybrid environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted management platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "crosswork_platform_infrastructure",
        "summary": "cisco crosswork_zero_touch_provisioning is a network automation solution that enables automated device provisioning and configuration. It sits in the core_infra layer of the tech stack, functions as a self-hosted network automation tool in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "integrated_management_controller_supervisor",
        "summary": "cisco intersight_virtual_appliance is a virtualized management solution that provides infrastructure monitoring and automation for data centers. It sits in the core_infra layer of the tech stack, functions as a self-hosted management appliance in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "unified_customer_voice_portal",
        "summary": "cisco unity_connection is a unified messaging and voicemail system that integrates voice, email, and fax communications for enterprises. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "crosswork_network_automation",
        "summary": "cisco cyber_vision is an industrial cybersecurity solution that provides real-time visibility and threat detection for operational technology networks. It sits in the core_infra layer of the tech stack, functions as a security platform in the software supply chain, and—within the industrial_control industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "sipass_integrated",
        "summary": "siemens sipass_integrated is an access control system that manages physical security and access permissions for facilities. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "siveillance_identity",
        "summary": "siemens siveillance_identity is a security management system that provides identity and access control solutions for physical security environments. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "industrial_control",
        "product": "comos",
        "summary": "siemens comos is an integrated software solution for plant engineering and operations that enhances collaboration and lifecycle management. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "gma-manager",
        "summary": "siemens gma-manager is a software solution designed for managing and optimizing industrial automation processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "siguard_dsa",
        "summary": "siemens siguard_dsa is a digital security appliance designed to protect industrial control systems from cyber threats. It sits in the core_infra layer of the tech stack, functions as a security appliance in the software supply chain, and—within the industrial_control industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "cloud_secure_agent",
        "summary": "netapp cloud_secure_agent is a security agent that protects data and workloads in cloud environments. It sits in the core_infra layer of the tech stack, functions as a security tool in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "crosswork_data_gateway",
        "summary": "cisco crosswork_network_controller is a network automation and assurance platform that optimizes and manages complex network operations. It sits in the core_infra layer of the tech stack, functions as a self-hosted network management solution in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "cisco"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "dna_spaces",
        "summary": "cisco firepower_threat_defense is a network security solution that provides advanced threat protection and firewall capabilities. It sits in the core_infra layer of the tech stack, functions as a security appliance in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "cisco"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "energy_utilities",
        "product": "spectrum_power_7",
        "summary": "siemens spectrum_power_7 is an advanced energy management system that optimizes power grid operations and enhances grid reliability. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the energy_utilities industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_tools",
        "summary": "netapp ontap_tools is a suite of management and automation utilities designed to optimize NetApp ONTAP storage systems. It sits in the core_infra layer of the tech stack, functions as a self-hosted management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      }
    ],
    "created_at": "2021-12-10T10:15:09Z",
    "doc_id": "CVE-2021-44228",
    "doc_type": "cve_template",
    "exposure": {
      "max_hosts": 4402130,
      "min_hosts": 26
    },
    "h1": {
      "delta_rank": -1,
      "rank": 139,
      "reports": 679
    },
    "ntps": 75,
    "updated_at": "2026-06-12T13:48:47.527Z",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade apache - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2010-0219",
    "age_in_days": 5715,
    "assignee": "cret@cert.org",
    "cve_created_at": "2010-10-18T17:00:03Z",
    "cve_updated_at": "2026-04-29T01:13:23Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.99804,
    "epss_score": 0.93155,
    "is_kev": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "is_template": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2023-11-15T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 6,
    "poc_first_seen": "2010-10-18T17:00:03Z",
    "pocs": [
      {
        "added_at": "2010-10-18T17:00:03Z",
        "source": "nvd",
        "url": "http://spl0it.org/files/talks/source_barcelona10/Hacking%20SAP%20BusinessObjects.pdf"
      },
      {
        "added_at": "2010-10-18T17:00:03Z",
        "source": "nvd",
        "url": "http://www.rapid7.com/security-center/advisories/R7-0037.jsp"
      },
      {
        "added_at": "2026-06-12T13:48:37Z",
        "source": "metasploit",
        "url": "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/axis2_deployer.rb"
      },
      {
        "added_at": "2024-07-28T14:10:52Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:veritas-rt/CVE-2010-0219.git"
      },
      {
        "added_at": "2024-07-28T14:10:52Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/veritas-rt/CVE-2010-0219"
      },
      {
        "added_at": "2024-07-28T14:10:52Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/veritas-rt/CVE-2010-0219.git"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2026-06-08T04:13:35Z",
        "source": "nuclei_template",
        "url": "https://knowledge.broadcom.com/external/article/13994/vulnerability-axis2-default-administrato.html"
      },
      {
        "added_at": "2026-06-11T00:00:00Z",
        "source": "vulncheck",
        "url": "https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/map/?day=2026-06-11&host_type=src&vulnerability=cve-2010-0219"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1024929"
      },
      {
        "added_at": "2026-06-08T04:13:35Z",
        "source": "nuclei_template",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2010-0219"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.exploit-db.com/exploits/15869"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://spl0it.org/files/talks/source_barcelona10/Hacking%20SAP%20BusinessObjects.pdf"
      },
      {
        "added_at": "2026-06-08T04:13:35Z",
        "source": "nuclei_template",
        "url": "http://www.rapid7.com/security-center/advisories/R7-0037.jsp"
      },
      {
        "added_at": "2026-06-08T04:13:35Z",
        "source": "nuclei_template",
        "url": "http://www.vupen.com/english/advisories/2010/2673"
      },
      {
        "added_at": "2026-06-08T04:13:35Z",
        "source": "nuclei_template",
        "url": "http://retrogod.altervista.org/9sg_ca_d2d.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.osvdb.org/70233"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "https://kb.juniper.net/KB27373"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://secunia.com/advisories/41799"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.kb.cert.org/vuls/id/989719"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "https://service.sap.com/sap/support/notes/1432881"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://secunia.com/advisories/42763"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/514284/100/0/threaded"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/62523"
      }
    ],
    "cwe": [
      "CWE-255"
    ],
    "description": "Apache Axis2 in various products contains a default password 'axis2' for the admin account, causing a security weakness that allows remote attackers to execute arbitrary code by uploading crafted web services, exploit requires remote access.",
    "impact": "Remote attackers can execute arbitrary code on affected systems by exploiting the default credentials.",
    "name": "Apache Axis2 - Broken Authentication",
    "remediation": "Change default password from 'axis2' to a strong, unique password and apply the latest security patches.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "broken_authentication",
    "weaknesses": [
      {
        "cwe_id": "CWE-255"
      }
    ],
    "category": "cve",
    "ref": "projectdiscovery/nuclei-templates:5776c47894d3",
    "release_tag": "v8.1.1",
    "filename": "CVE-2010-0219.yaml",
    "uri": "http/cves/2010/CVE-2010-0219.yaml",
    "author": [
      "pikpikcu"
    ],
    "metadata": {
      "fofa-query": "body=\"apache axis\"",
      "max-request": 2,
      "product": "axis2",
      "shodan-query": [
        "http.html:\"Apache Axis\"",
        "http.html:\"apache axis\""
      ],
      "vendor": "apache"
    },
    "tags": [
      "cve",
      "cve2010",
      "axis",
      "apache",
      "default-login",
      "axis2",
      "vkev",
      "vuln"
    ],
    "type": "http",
    "id": "CVE-2010-0219",
    "affected_products": [
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "axis2",
        "summary": "apache axis2 is a web services engine that facilitates the creation and consumption of SOAP and RESTful web services. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "apache"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "businessobjects",
        "summary": "sap businessobjects is a business intelligence suite that provides reporting, analysis, and data visualization tools. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "sap"
      }
    ],
    "created_at": "2010-10-18T17:00:03Z",
    "doc_id": "CVE-2010-0219",
    "doc_type": "cve_template",
    "exposure": {
      "max_hosts": 13,
      "min_hosts": 13
    },
    "h1": {
      "delta_rank": -1,
      "rank": 824,
      "reports": 6
    },
    "ntps": 75,
    "updated_at": "2026-06-12T13:48:49.329Z",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade apache - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2016-15057",
    "age_in_days": 136,
    "assignee": "security@apache.org",
    "cve_created_at": "2026-01-26T12:15:46Z",
    "cve_updated_at": "2026-01-27T20:29:50Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 9.9,
    "epss_percentile": 0.96875,
    "epss_score": 0.31155,
    "is_auth": true,
    "is_kev": true,
    "is_oss": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2026-01-26T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "vuln_status": "confirmed",
    "citations": [
      {
        "added_at": "2026-01-26T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.vulncheck.com/advisories/apache-continuum-code-execution-via-saveinstallation-action"
      },
      {
        "added_at": "2026-01-26T12:15:46Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread/hbvf1ztqw2kv51khvzm5nk3mml3nm4z1"
      },
      {
        "added_at": "2026-01-26T19:16:08Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2026/01/26/1"
      }
    ],
    "cwe": [
      "CWE-77"
    ],
    "description": "Apache Continuum contains a command injection caused by improper neutralization of special elements in REST API, letting attackers with API access execute arbitrary commands remotely, exploit requires REST API access.",
    "impact": "Attackers with REST API access can execute arbitrary commands on the server, potentially leading to full system compromise.",
    "name": "Apache Continuum - Command Injection",
    "remediation": "No fix available as the project is retired; users should restrict access to trusted users or find an alternative.",
    "requirement_type": "undefined",
    "requirements": "Attacker needs access to the REST API",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "command_injection",
    "weaknesses": [
      {
        "cwe_id": "CWE-77",
        "cwe_name": "Improper Neutralization of Special Elements used in a Command ('Command Injection')"
      }
    ],
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "continuum",
        "summary": "apache continuum is a continuous integration server that automates the build and testing process for software projects. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "apache"
      }
    ],
    "created_at": "2026-01-26T12:15:46Z",
    "doc_id": "CVE-2016-15057",
    "doc_type": "cve",
    "exposure": {},
    "ntps": 52,
    "updated_at": "2026-06-11T14:34:40.202Z",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade apache - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2016-3427",
    "age_in_days": 3694,
    "assignee": "secalert_us@oracle.com",
    "cve_created_at": "2016-04-21T11:00:21Z",
    "cve_updated_at": "2026-04-22T13:41:41Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.99816,
    "epss_score": 0.93287,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2023-05-12T00:00:00Z",
        "due_date": "2023-06-02T00:00:00Z",
        "source": "cisa"
      },
      {
        "added_date": "2023-05-12T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "vuln_status": "confirmed",
    "citations": [
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00022.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00027.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00058.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00021.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00040.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/845312a10aabbe2c499fca94003881d2c79fc993d85f34c1f5c77424%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/b5e3f51d28cd5d9b1809f56594f2cf63dcd6a90429e16ea9f83bbedc%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00009.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00026.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00059.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00061.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/6af47120905aa7d8fe12f42e8ff2284fb338ba141d3b77b8c7cb61b3%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/88855876c33f2f9c532ffb75bfee570ccf0b17ffa77493745af9a17a%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2023-12-18T00:00:00Z",
        "source": "vulncheck",
        "url": "https://thedfirreport.com/2023/12/18/lets-opendir-some-presents-an-analysis-of-a-persistent-actors-activity/"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://rhn.redhat.com/errata/RHSA-2016-0650.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/343558d982879bf88ec20dbf707f8c11255f8e219e81d45c4f8d0551%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/388a323769f1dff84c9ec905455aa73fbcb20338e3c7eb131457f708%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/39ae1f0bd5867c15755a6f959b271ade1aea04ccdc3b2e639dcd903b%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/b84ad1258a89de5c9c853c7f2d3ad77e5b8b2930be9e132d5cef6b95%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-10-21T19:16:41Z",
        "source": "nvd",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2016-3427"
      },
      {
        "added_at": "2024-05-06T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.fortinet.com/content/dam/fortinet/assets/threat-reports/threat-landscape-report-2h-2023.pdf"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00039.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/37220405a377c0182d2afdbc36461c4783b2930fbeae3a17f1333113%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r03c597a64de790ba42c167efacfa23300c3d6c9fe589ab87fe02859c%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00012.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00067.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://rhn.redhat.com/errata/RHSA-2016-0675.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://rhn.redhat.com/errata/RHSA-2016-0676.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/3d19773b4cf0377db62d1e9328bf9160bf1819f04f988315086931d7%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/b8a1bf18155b552dcf9a928ba808cbadad84c236d85eab3033662cfb%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00006.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-06/msg00002.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://rhn.redhat.com/errata/RHSA-2016-0651.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r587e50b86c1a96ee301f751d50294072d142fd6dc08a8987ae9f3a9b%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00042.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://rhn.redhat.com/errata/RHSA-2016-0677.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.oracle.com/technetwork/topics/security/linuxbulletinapr2016-2952096.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r9136ff5b13e4f1941360b5a309efee2c114a14855578c3a2cbe5d19c%40%3Cdev.tomcat.apache.org%3E"
      }
    ],
    "cwe": [
      "NVD-CWE-noinfo",
      "CWE-284"
    ],
    "description": "Oracle Java SE 6u113, 7u99, 8u77; Java SE Embedded 8u77; and JRockit R28.3.9 contain an unspecified vulnerability related to JMX, letting remote attackers impact confidentiality, integrity, and availability, exploit requires remote network access.",
    "impact": "Attackers can compromise confidentiality, integrity, and availability of affected systems remotely.",
    "name": "Oracle Java SE - Undefined",
    "remediation": "Update to the latest available version of Java SE and JRockit.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "information_disclosure",
      "data_tampering",
      "denial_of_service"
    ],
    "vulnerability_type": "undefined",
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-noinfo"
      },
      {
        "cwe_id": "CWE-284",
        "cwe_name": "Improper Access Control"
      }
    ],
    "affected_products": [
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "linux",
        "summary": "oracle linux is an enterprise-grade operating system that provides a secure and stable platform for applications and infrastructure. It sits in the operating_system layer of the tech stack, functions as a core system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "app_plugins",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "e-series_santricity_management_plug-ins",
        "summary": "netapp e-series_santricity_management_plug-ins are management plugins that provide monitoring and management capabilities for NetApp E-Series storage systems. They sit in the app_plugins layer of the tech stack, function as extensions in the software supply chain, and—within the information_technology industry—serve the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_balance",
        "summary": "netapp oncommand_balance is a storage resource management and optimization tool that helps balance workloads across storage systems. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_cloud_manager",
        "summary": "netapp oncommand_cloud_manager is a cloud data management platform that simplifies storage provisioning and data protection across hybrid cloud environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted management service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_unified_manager",
        "summary": "netapp oncommand_unified_manager is a storage management software that provides centralized monitoring and management of storage systems. It sits in the data_storage layer of the tech stack, functions as an enterprise application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "satellite",
        "summary": "redhat satellite is a systems management solution that automates the deployment, configuration, and maintenance of Red Hat infrastructure. It sits in the core_infra layer of the tech stack, functions as a self-hosted management platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openstack_cloud",
        "summary": "suse openstack_cloud is an open-source cloud computing platform that enables the deployment and management of private and public clouds. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "suse"
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
        "product": "enterprise_linux_server_tus",
        "summary": "redhat enterprise_linux_server_tus is a Linux-based operating system designed for enterprise environments that provides a stable and secure platform for running applications and services. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "linux_enterprise_software_development_kit",
        "summary": "suse linux_enterprise_software_development_kit is a comprehensive development toolkit that provides tools and libraries for building enterprise-grade Linux applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "suse"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_report",
        "summary": "netapp oncommand_report is a reporting and analytics tool designed to provide insights into storage infrastructure performance and capacity. It sits in the core_infra layer of the tech stack, functions as a self-hosted management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_workflow_automation",
        "summary": "netapp oncommand_workflow_automation is an IT automation and orchestration software that simplifies and automates storage and data management workflows. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_desktop",
        "summary": "redhat enterprise_linux_desktop is a robust Linux-based operating system designed for desktop environments that provides stability and security for enterprise users. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "manager_proxy",
        "summary": "suse manager_proxy is a proxy server component that extends the SUSE Manager infrastructure by managing client connections and content delivery. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "suse"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "jdk",
        "summary": "oracle jdk is a development kit that provides tools and libraries for building Java applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "vasa_provider_for_clustered_data_ontap",
        "summary": "netapp vasa_provider_for_clustered_data_ontap is a storage management integration solution that provides VMware vSphere with storage awareness and management capabilities for clustered Data ONTAP systems. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "cassandra",
        "summary": "apache cassandra is a distributed NoSQL database designed for handling large amounts of data across many commodity servers with high availability. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "apache"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_eus",
        "summary": "redhat enterprise_linux_server_eus is a long-term supported Linux operating system designed for stability and security in enterprise environments. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
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
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "jre",
        "summary": "oracle jre is a runtime environment that provides the necessary libraries and components to run Java applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "e-series_santricity_storage_manager",
        "summary": "netapp e-series_santricity_storage_manager is a storage management software that provides monitoring and configuration for NetApp E-Series storage systems. It sits in the data_storage layer of the tech stack, functions as a core infrastructure tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_insight",
        "summary": "netapp oncommand_insight is an infrastructure analytics and monitoring solution that provides visibility and optimization for storage and data center resources. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_performance_manager",
        "summary": "netapp oncommand_performance_manager is a storage performance monitoring and analytics tool that helps optimize storage infrastructure. It sits in the data_storage layer of the tech stack, functions as a self-hosted management solution in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_aus",
        "summary": "redhat enterprise_linux_server_aus is a Linux-based operating system designed for enterprise-grade server environments that provides stability, security, and performance. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "manager",
        "summary": "suse manager is a systems management solution that automates Linux server lifecycle management and configuration. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure management tool in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "suse"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "linux_enterprise_server",
        "summary": "suse linux_enterprise_server is a robust enterprise-grade operating system that provides a stable and secure platform for servers and applications. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "suse"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_shift",
        "summary": "netapp oncommand_shift is a data management and migration tool that simplifies the movement and management of data across storage environments. It sits in the data_storage layer of the tech stack, functions as a self-hosted software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "storagegrid",
        "summary": "netapp storagegrid is a scalable object storage solution that manages large amounts of unstructured data with high durability and availability. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "linux_enterprise_module_for_legacy",
        "summary": "suse linux_enterprise_module_for_legacy is a compatibility module that provides legacy software support for SUSE Linux Enterprise systems. It sits in the operating_system layer of the tech stack, functions as a self-hosted module in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "suse"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "opensuse",
        "summary": "opensuse opensuse is a Linux-based open source operating system that provides a stable and versatile platform for various computing needs. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "opensuse"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "e-series_santricity_web_services",
        "summary": "netapp e-series_santricity_web_services is a management software suite that provides web-based monitoring and configuration for NetApp E-Series storage systems. It sits in the core_infra layer of the tech stack, functions as a self-hosted management service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_eus",
        "summary": "redhat enterprise_linux_eus is a long-term supported Linux operating system designed for stability and extended maintenance in enterprise environments. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server",
        "summary": "redhat enterprise_linux_server is a robust and secure operating system designed for enterprise environments that provides a stable platform for applications and services. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "linux_enterprise_desktop",
        "summary": "suse linux_enterprise_desktop is a Linux-based operating system designed for enterprise desktop environments that provides stability, security, and productivity tools. It sits in the operating_system layer of the tech stack, functions as an operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "suse"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jrockit",
        "summary": "oracle jrockit is a Java Virtual Machine (JVM) designed to optimize Java application performance and reliability. It sits in the core_infra layer of the tech stack, functions as a runtime environment in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "oracle"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "virtual_storage_console",
        "summary": "netapp virtual_storage_console is a management software that simplifies storage provisioning and data protection for VMware environments. It sits in the data_storage layer of the tech stack, functions as a self-hosted management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_workstation",
        "summary": "redhat enterprise_linux_workstation is a robust operating system designed for workstation environments that provides stability, security, and performance for professional users. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      }
    ],
    "created_at": "2016-04-21T11:00:21Z",
    "doc_id": "CVE-2016-3427",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 17143153,
      "min_hosts": 34
    },
    "h1": {
      "rank": 1257,
      "reports": 3
    },
    "ntps": 75,
    "updated_at": "2026-06-02T15:32:36.677Z",
    "product": "apache",
    "pinned_version": "2.4.49-1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade apache - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2022-23305",
    "age_in_days": 1604,
    "assignee": "security@apache.org",
    "cve_created_at": "2022-01-18T16:15:08Z",
    "cve_updated_at": "2026-05-27T14:16:36Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.92993,
    "epss_score": 0.09452,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 3,
    "poc_first_seen": "2021-12-14T22:27:14Z",
    "pocs": [
      {
        "added_at": "2022-01-21T05:07:59Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/AlphabugX/CVE-2022-RCE"
      },
      {
        "added_at": "2021-12-14T22:27:14Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/HynekPetrak/log4shell-finder"
      },
      {
        "added_at": "2023-07-24T18:52:15Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/tkomlodi/CVE-2022-23305_POC"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T06:48:22Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread/pt6lh3pbsvxqlwlp4c5l798dv2hkc85y"
      },
      {
        "added_at": "2024-11-21T06:48:22Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20220217-0007/"
      },
      {
        "added_at": "2024-11-21T06:48:22Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpuapr2022.html"
      },
      {
        "added_at": "2024-11-21T06:48:22Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpujul2022.html"
      },
      {
        "added_at": "2024-11-21T06:48:22Z",
        "source": "nvd",
        "url": "https://logging.apache.org/log4j/1.2/index.html"
      },
      {
        "added_at": "2024-11-21T06:48:22Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2022/01/18/4"
      }
    ],
    "cwe": [
      "CWE-89"
    ],
    "description": "Log4j 1.2.x JDBCAppender accepts SQL statements with pattern converters, allowing attackers to manipulate SQL queries via crafted log messages, exploit requires specific JDBCAppender configuration.",
    "impact": "Attackers can execute arbitrary SQL queries through manipulated log messages, potentially leading to data leakage or database compromise.",
    "name": "Log4j - SQL Injection",
    "remediation": "Upgrade to Log4j 2.0-beta8 or later, which supports parameterized queries and enhances security.",
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
        "category": "enterprise",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "e-business_suite_cloud_manager_and_cloud_backup_module",
        "summary": "oracle e-business_suite_cloud_manager_and_cloud_backup_module is a cloud management and backup solution designed to optimize and protect Oracle E-Business Suite environments. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "e-business_suite_information_discovery",
        "summary": "oracle e-business_suite_information_discovery is an enterprise analytics and business intelligence tool that provides insights and data discovery capabilities for business processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "identity_manager_connector",
        "summary": "oracle identity_manager_connector is a software component that integrates identity management systems to streamline user provisioning and access control. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "tuxedo",
        "summary": "oracle tuxedo is a middleware platform that manages distributed transaction processing and application server services. It sits in the core_infra layer of the tech stack, functions as a core infrastructure service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "log4j",
        "summary": "apache log4j is a Java-based logging utility that provides flexible and reliable logging capabilities for applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "brocade_sannav",
        "summary": "broadcom brocade_sannav is a network management software designed to optimize and monitor SAN (Storage Area Network) environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "broadcom"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "reload4j",
        "summary": "qos reload4j is a logging library that provides reliable and flexible logging capabilities for Java applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "qos"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "advanced_supply_chain_planning",
        "summary": "oracle advanced_supply_chain_planning is an enterprise software solution that optimizes and manages supply chain operations for businesses. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "undefined",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "communications_eagle_ftp_table_base_retrieval",
        "summary": "oracle communications_eagle_ftp_table_base_retrieval is a specialized component likely used for retrieving FTP table data within Oracle's Communications Eagle suite. It sits in the undefined layer of the tech stack, functions as an unknown type in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_network_integrity",
        "summary": "oracle communications_network_integrity is a network integrity solution that ensures the security and reliability of telecommunications networks. It sits in the core_infra layer of the tech stack, functions as a security product in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_offline_mediation_controller",
        "summary": "oracle communications_offline_mediation_controller is a mediation and data processing solution that collects, processes, and transforms offline communication data for billing and analytics. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "financial_services",
        "product": "financial_services_revenue_management_and_billing_analytics",
        "summary": "oracle financial_services_revenue_management_and_billing_analytics is an analytics and billing management solution designed to optimize revenue processes in financial services. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "business_intelligence",
        "summary": "oracle business_intelligence is a comprehensive analytics and reporting platform that enables organizations to make data-driven decisions. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "data_storage",
        "deployment_model": "hybrid",
        "industry": "healthcare",
        "product": "healthcare_foundation",
        "summary": "oracle healthcare_foundation is a healthcare data platform that integrates and manages clinical and operational data to improve patient outcomes. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the healthcare industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "hyperion_data_relationship_management",
        "summary": "oracle hyperion_data_relationship_management is a master data management solution that centralizes and governs enterprise data relationships for improved accuracy and compliance. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "cli",
        "industry": "information_technology",
        "product": "jdeveloper",
        "summary": "oracle jdeveloper is an integrated development environment (IDE) that facilitates application development with comprehensive tools and features. It sits in the application_library layer of the tech stack, functions as a devtool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "middleware_common_libraries_and_tools",
        "summary": "oracle middleware_common_libraries_and_tools is a set of reusable software components and utilities that support middleware applications and integration. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "weblogic_server",
        "summary": "oracle weblogic_server is a Java EE application server that enables deployment and management of enterprise applications. It sits in the core_infra layer of the tech stack, functions as a middleware platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_instant_messaging_server",
        "summary": "oracle communications_instant_messaging_server is a real-time messaging server that enables instant communication across enterprise networks. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_manager_base_platform",
        "summary": "oracle enterprise_manager_base_platform is an IT management software that provides comprehensive monitoring and management of enterprise IT environments. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "financial_services",
        "product": "hyperion_infrastructure_technology",
        "summary": "oracle hyperion_infrastructure_technology is a financial performance management platform that provides infrastructure for enterprise planning, budgeting, and forecasting. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "identity_management_suite",
        "summary": "oracle identity_management_suite is a comprehensive identity and access management solution that secures user authentication and authorization across enterprise systems. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "mysql_enterprise_monitor",
        "summary": "oracle mysql_enterprise_monitor is a database monitoring and management tool that provides real-time performance insights and alerts for MySQL databases. It sits in the core_infra layer of the tech stack, functions as a self-hosted monitoring service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "retail_extract_transform_and_load",
        "summary": "oracle retail_extract_transform_and_load is a data integration and processing tool designed to extract, transform, and load retail data efficiently. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "snapmanager",
        "summary": "netapp snapmanager is a data management software that simplifies backup and recovery for enterprise storage systems. It sits in the data_storage layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "business_process_management_suite",
        "summary": "oracle business_process_management_suite is a comprehensive business process management platform that enables organizations to model, automate, and optimize workflows. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_messaging_server",
        "summary": "oracle communications_messaging_server is a scalable messaging platform that provides email and collaboration services for telecom operators. It sits in the core_infra layer of the tech stack, functions as a self-hosted communication server in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_unified_inventory_management",
        "summary": "oracle communications_unified_inventory_management is a network inventory management solution that provides unified visibility and control over telecom assets. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the telecommunications industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      }
    ],
    "created_at": "2022-01-18T16:15:08Z",
    "doc_id": "CVE-2022-23305",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 942013,
      "min_hosts": 88
    },
    "h1": {
      "delta_rank": 14,
      "delta_reports": -1,
      "rank": 7968
    },
    "ntps": 55,
    "updated_at": "2026-06-11T15:31:16.299Z",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to latest patched version"
  },
  {
    "cve_id": "CVE-2020-9493",
    "age_in_days": 1821,
    "assignee": "security@apache.org",
    "cve_created_at": "2021-06-16T08:15:06Z",
    "cve_updated_at": "2024-11-21T05:40:46Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.5772,
    "epss_score": 0.00348,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T05:40:46Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r50d389c613ba6062a26aa57e163c09bfee4ff2d95d67331d75265b83%40%3Cannounce.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T05:40:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2021/06/16/1"
      },
      {
        "added_at": "2024-11-21T05:40:46Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2022/01/18/5"
      },
      {
        "added_at": "2024-11-21T05:40:46Z",
        "source": "nvd",
        "url": "https://www.openwall.com/lists/oss-security/2021/06/16/1"
      }
    ],
    "cwe": [
      "CWE-502"
    ],
    "description": "Apache Chainsaw < 2.1.0 contains an insecure deserialization caused by improper handling of serialized data, letting attackers execute malicious code, exploit requires attacker to send crafted serialized data.",
    "impact": "Attackers can execute arbitrary code remotely, potentially leading to full system compromise.",
    "name": "Apache Chainsaw - Insecure Deserialization",
    "remediation": "Update to version 2.1.0 or later.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "insecure_deserialization",
    "weaknesses": [
      {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data"
      }
    ],
    "affected_products": [
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "chainsaw",
        "summary": "apache chainsaw is a graphical log viewer tool that helps developers analyze and visualize log files for troubleshooting and debugging. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "apache"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "log4j",
        "summary": "apache log4j is a Java-based logging utility that provides flexible and reliable logging capabilities for applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "reload4j",
        "summary": "qos reload4j is a logging library that provides reliable and flexible logging capabilities for Java applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "qos"
      }
    ],
    "created_at": "2021-06-16T08:15:06Z",
    "doc_id": "CVE-2020-9493",
    "doc_type": "cve",
    "exposure": {},
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 40,
    "updated_at": "2026-06-11T15:49:17.306Z",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to latest patched version"
  },
  {
    "cve_id": "CVE-2019-17571",
    "age_in_days": 2364,
    "assignee": "security@apache.org",
    "cve_created_at": "2019-12-20T17:15:11Z",
    "cve_updated_at": "2026-05-28T19:16:31Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.96636,
    "epss_score": 0.28502,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "poc_count": 3,
    "poc_first_seen": "2019-12-25T16:46:11Z",
    "pocs": [
      {
        "added_at": "2021-12-14T22:27:14Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/HynekPetrak/log4shell-finder"
      },
      {
        "added_at": "2020-07-16T04:01:40Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Al1ex/CVE-2019-17571"
      },
      {
        "added_at": "2019-12-25T16:46:11Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/shadow-horse/CVE-2019-17571"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r909b8e3a36913944d3b7bafe9635d4ca84f8f0e2cd146a1784f667c2%40%3Cissues.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/ra18a903f785aed9403aea38bc6f36844a056283c00dcfc6936b6318c%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rdec0d8ac1f03e6905b0de2df1d5fcdb98b94556e4f6cccf7519fdb26%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf2567488cfc9212b42e34c6393cfa1c14e30e4838b98dda84d71041f%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/277b4b5c2b0e06a825ccec565fa65bd671f35a4d58e3e2ec5d0618e1%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r3c575cabc7386e646fb12cb82b0b38ae5a6ade8a800f827107824495%40%3Cjira.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/479471e6debd608c837b9815b76eab24676657d4444fcfd5ef96d6e6%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r1b7734dfdfd938640f2f5fb6f4231a267145c71ed60cc7faa1cbac07%40%3Ccommon-issues.hadoop.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/44491fb9cc19acc901f7cff34acb7376619f15638439416e3e14761c%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r26244f9f7d9a8a27a092eb0b2a0ca9395e88fcde8b5edaeca7ce569c%40%3Ccommon-issues.hadoop.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7%40%3Cdev.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rd0e44e8ef71eeaaa3cf3d1b8b41eb25894372e2995ec908ce7624d26%40%3Ccommits.pulsar.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r4ac89cbecd9e298ae9fafb5afda6fa77ac75c78d1ac957837e066c4e%40%3Cuser.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r18f1c010b554a3a2d761e8ffffd8674fd4747bcbcf16c643d708318c%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r2ff63f210842a3c5e42f03a35d8f3a345134d073c80a04077341c211%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r3bf7b982dfa0779f8a71f843d2aa6b4184a53e6be7f149ee079387fd%40%3Cdev.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r7bcdc710857725c311b856c0b82cee6207178af5dcde1bd43d289826%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r8d78a0fbb56d505461e29868d1026e98c402e6a568c13a6da67896a2%40%3Cdev.jena.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r90c23eb8c82835fa82df85ae5e88c81fd9241e20a22971b0fb8f2c34%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rca24a281000fb681d7e26e5c031a21eb4b0593a7735f781b53dae4e2%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r1b103833cb5bc8466e24ff0ecc5e75b45a705334ab6a444e64e840a0%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r8e3f7da12bf5750b0a02e69a78a61073a2ac950eed7451ce70a65177%40%3Ccommits.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rbc45eb0f53fd6242af3e666c2189464f848a851d408289840cecc6e3%40%3Ccommits.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7%40%3Cusers.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r9d0d03f2e7d9e13c68b530f81d02b0fec33133edcf27330d8089fcfb%40%3Cissues.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rc1eaed7f7d774d5d02f66e49baced31e04827a1293d61a70bd003ca7%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rd5dbeee4808c0f2b9b51479b50de3cc6adb1072c332a200d9107f13e%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf77f79699c8d7e430c14cf480f12ed1297e6e8cf2ed379a425941e80%40%3Cpluto-dev.portals.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://www.debian.org/security/2020/dsa-4686"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r189aaeaad897f7d6b96f7c43a8ef2dfb9f6e9f8c1cc9ad182ce9b9ae%40%3Cjira.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r3784834e80df2f284577a5596340fb84346c91a2dea6a073e65e3397%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r48efc7cb5aeb4e1f67aaa06fb4b5479a5635d12f07d0b93fc2d08809%40%3Ccommits.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r6b45a2fcc8e98ac93a179183dbb7f340027bdb8e3ab393418076b153%40%3Ccommon-issues.hadoop.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/ra54fa49be3e773d99ccc9c2a422311cf77e3ecd3b8594ee93043a6b1%40%3Cdev.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rbd19de368abf0764e4383ec44d527bc9870176f488a494f09a40500d%40%3Ccommon-dev.hadoop.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rc628307962ae1b8cc2d21b8e4b7dd6d7755b2dd52fa56a151a27e4fd%40%3Cissues.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r52a5129df402352adc34d052bab9234c8ef63596306506a89fdc7328%40%3Cusers.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r61590890edcc64140e0c606954b29a063c3d08a2b41d447256d51a78%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/reaf6b996f74f12b4557bc221abe88f58270ac583942fa41293c61f94%40%3Cpluto-scm.portals.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/564f03b4e9511fcba29c68fc0299372dadbdb002718fa8edcc4325e4%40%3Cjira.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r8a1cfd4705258c106e488091fcec85f194c82f2bbde6bd151e201870%40%3Cjira.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rc17d8491beee51607693019857e41e769795366b85be00aa2f4b3159%40%3Cnotifications.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r48d5019bd42e0770f7e5351e420a63a41ff1f16924942442c6aff6a8%40%3Ccommits.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r746fbc3fc13aee292ae6851f7a5080f592fa3a67b983c6887cdb1fc5%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rd6254837403e8cbfc7018baa9be29705f3f06bd007c83708f9a97679%40%3Cissues.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf53eeefb7e7e524deaacb9f8671cbf01b8a253e865fb94e7656722c0%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20200110-0001/"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r71e26f9c2d5826c6f95ad60f7d052d75e1e70b0d2dd853db6fc26d5f%40%3Cjira.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r9dc2505651788ac668299774d9e7af4dc616be2f56fdc684d1170882%40%3Cusers.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r9fb3238cfc3222f2392ca6517353aadae18f76866157318ac562e706%40%3Ccommon-issues.hadoop.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00022.html"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpuapr2020.html"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/ra9611a8431cb62369bce8909d7645597e1dd45c24b448836b1e54940%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rbdf18e39428b5c80fc35113470198b1fe53b287a76a46b0f8780b5fd%40%3Cdev.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r5c084578b3e3b40bd903c9d9e525097421bcd88178e672f612102eb2%40%3Cjira.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r9d2e28e71f91ba0b6f4114c8ecd96e2b1f7e0d06bdf8eb768c183aa9%40%3Ccommon-issues.hadoop.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rda4849c6823dd3e83c7a356eb883180811d5c28359fe46865fd151c3%40%3Cusers.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rdb7ddf28807e27c7801f6e56a0dfb31092d34c61bdd4fa2de9182119%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf1b434e11834a4449cd7addb69ed0aef0923112b5938182b363a968c%40%3Cnotifications.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/752ec92cd1e334a639e79bfbd689a4ec2c6579ec5bb41b53ffdf358d%40%3Cdev.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r05755112a8c164abc1004bb44f198b1e3d8ca3d546a8f13ebd3aa05f%40%3Cissues.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r2ce8d26154bea939536e6cf27ed02d3192bf5c5d04df885a80fe89b3%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r3543ead2317dcd3306f69ee37b07dd383dbba6e2f47ff11eb55879ad%40%3Cusers.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpuApr2021.html"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpuapr2022.html"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r107c8737db39ec9ec4f4e7147b249e29be79170b9ef4b80528105a2d%40%3Cdev.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r3a85514a518f3080ab1fc2652cfe122c2ccf67cfb32356acb1b08fe8%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r4b25538be50126194cc646836c718b1a4d8f71bd9c912af5b59134ad%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r594411f4bddebaf48a4c70266d0b7849e0d82bb72826f61b3a35bba7%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r696507338dd5f44efc23d98cafe30f217cf3ba78e77ed1324c7a5179%40%3Cjira.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rb1b29aee737e1c37fe1d48528cb0febac4f5deed51f5412e6fdfe2bf%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r6d34da5a0ca17ab08179a30c971446c7421af0e96f6d60867eabfc52%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r8890b8f18f1de821595792b58b968a89692a255bc20d86d395270740%40%3Ccommits.druid.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/raedd12dc24412b3780432bf202a2618a21a727788543e5337a458ead%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rd3a9511eebab60e23f224841390a3f8cd5358cff605c5f7042171e47%40%3Cdev.tinkerpop.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/re8c21ed9dd218c217d242ffa90778428e446b082b5e1c29f567e8374%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r3d666e4e8905157f3c046d31398b04f2bfd4519e31f266de108c6919%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc%40%3Cdev.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r681b4432d0605f327b68b9f8a42662993e699d04614de4851c35ffd1%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r7a1acc95373105169bd44df710c2f462cad31fb805364d2958a5ee03%40%3Cjira.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r7f462c69d5ded4c0223e014d95a3496690423c5f6f05c09e2f2a407a%40%3Cjira.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r944183c871594fe9a555b8519a7c945bbcf6714d72461aa6c929028f%40%3Cissues.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf9c19bcc2f7a98a880fa3e3456c003d331812b55836b34ef648063c9%40%3Cjira.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2020/01/msg00008.html"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpujul2020.html"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc%40%3Cusers.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r8244fd0831db894d5e89911ded9c72196d395a90ae655414d23ed0dd%40%3Cusers.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r8418a0dff1729f19cf1024937e23a2db4c0f94f2794a423f5c10e8e7%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r8c392ca48bb7e50754e4bc05865e9731b23d568d18a520fe3d8c1f75%40%3Ccommon-issues.hadoop.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rfdf65fa675c64a64459817344e0e6c44d51ee264beea6e5851fb60dc%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/6114ce566200d76e3cc45c521a62c2c5a4eac15738248f58a99f622c%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r13d4b5c60ff63f3c4fab51d6ff266655be503b8a1884e2f2fab67c3a%40%3Ccommon-issues.hadoop.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpujul2022.html"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/8ab32b4c9f1826f20add7c40be08909de9f58a89dc1de9c09953f5ac%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rec34b1cccf907898e7cb36051ffac3ccf1ea89d0b261a2a3b3fb267f%40%3Ccommits.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rcd71280585425dad7e232f239c5709e425efdd0d3de4a92f808a4767%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r2721aba31a8562639c4b937150897e24f78f747cdbda8641c0f659fe%40%3Cusers.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/eea03d504b36e8f870e8321d908e1def1addda16adda04327fe7c125%40%3Cdev.logging.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://usn.ubuntu.com/4495-1/"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r8c6300245c0bcef095e9f07b48157e2c6471df0816db3408fcf1d748%40%3Ccommon-issues.hadoop.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r2756fd570b6709d55a61831ca028405bcb3e312175a60bc5d911c81f%40%3Cjira.kafka.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r6aec6b8f70167fa325fb98b3b5c9ce0ffaed026e697b69b85ac24628%40%3Cissues.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rb3c94619728c8f8c176d8e175e0a1086ca737ecdfcd5a2214bb768bc%40%3Ccommits.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/re36da78e4f3955ba6c1c373a2ab85a4deb215ca74b85fcd66142fea1%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r3cf50d05ce8cec8c09392624b7bae750e7643dae60ef2438641ee015%40%3Cissues.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rd7805c1bf9388968508c6c8f84588773216e560055ddcc813d19f347%40%3Ccommon-issues.hadoop.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rd882ab6b642fe59cbbe94dc02bd197342058208f482e57b537940a4b%40%3Cpluto-dev.portals.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rdf2a0d94c3b5b523aeff7741ae71347415276062811b687f30ea6573%40%3Ccommits.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r6236b5f8646d48af8b66d5050f288304016840788e508c883356fe0e%40%3Clog4j-user.logging.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r356d57d6225f91fdc30f8b0a2bed229d1ece55e16e552878c5fa809a%40%3Cissues.zookeeper.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r9a9e3b42cd5d1c4536a14ef04f75048dec8e2740ac6a138ea912177f%40%3Cpluto-dev.portals.apache.org%3E"
      },
      {
        "added_at": "2024-11-21T04:32:33Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/ra38785cfc0e7f17f8e24bebf775dd032c033fadcaea29e5bc9fffc60%40%3Cdev.tika.apache.org%3E"
      }
    ],
    "cwe": [
      "CWE-502"
    ],
    "description": "Log4j 1.2 up to 1.2.17 contains a insecure deserialization caused by SocketServer class, letting remote attackers execute arbitrary code when listening to untrusted network traffic for log data, exploit requires listening to untrusted network traffic.",
    "impact": "Remote attackers can execute arbitrary code on the server, leading to full system compromise.",
    "name": "Log4j - Insecure Deserialization",
    "remediation": "Update to the latest version of Log4j 1.2 or upgrade to Log4j 2.x.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "insecure_deserialization",
    "weaknesses": [
      {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data"
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
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_system_manager",
        "summary": "netapp oncommand_system_manager is a storage management software that provides centralized control and monitoring of NetApp storage systems. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_network_integrity",
        "summary": "oracle communications_network_integrity is a network integrity solution that ensures the security and reliability of telecommunications networks. It sits in the core_infra layer of the tech stack, functions as a security product in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "endeca_information_discovery_studio",
        "summary": "oracle endeca_information_discovery_studio is an enterprise data discovery and analytics platform that enables users to explore and analyze complex data sets. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "retail_service_backbone",
        "summary": "oracle retail_service_backbone is an integration platform designed to connect and streamline retail systems and services. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "primavera_gateway",
        "summary": "oracle primavera_gateway is an integration middleware that facilitates data exchange between Primavera P6 and other enterprise systems. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "bookkeeper",
        "summary": "apache bookkeeper is a distributed log storage service that provides reliable and scalable write-ahead logging for distributed systems. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "apache"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "financial_services",
        "product": "financial_services_lending_and_leasing",
        "summary": "oracle financial_services_lending_and_leasing is a comprehensive lending and leasing management software that automates loan origination, servicing, and compliance processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the business_apps domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "mysql_enterprise_monitor",
        "summary": "oracle mysql_enterprise_monitor is a database monitoring and management tool that provides real-time performance insights and alerts for MySQL databases. It sits in the core_infra layer of the tech stack, functions as a self-hosted monitoring service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "rapid_planning",
        "summary": "oracle rapid_planning is a cloud-based enterprise planning and budgeting software that enables organizations to streamline financial planning processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
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
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_workflow_automation",
        "summary": "netapp oncommand_workflow_automation is an IT automation and orchestration software that simplifies and automates storage and data management workflows. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "netapp"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "application_testing_suite",
        "summary": "oracle application_testing_suite is an integrated testing solution that automates functional, regression, and load testing for enterprise applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the qa domain.",
        "tech_domain": "qa",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "retail_extract_transform_and_load",
        "summary": "oracle retail_extract_transform_and_load is a data integration and processing tool designed to extract, transform, and load retail data efficiently. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "weblogic_server",
        "summary": "oracle weblogic_server is a Java EE application server that enables deployment and management of enterprise applications. It sits in the core_infra layer of the tech stack, functions as a middleware platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "log4j",
        "summary": "apache log4j is a Java-based logging utility that provides flexible and reliable logging capabilities for applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      }
    ],
    "created_at": "2019-12-20T17:15:11Z",
    "doc_id": "CVE-2019-17571",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 15993979,
      "min_hosts": 942013
    },
    "h1": {
      "rank": 2534,
      "reports": 1
    },
    "ntps": 62,
    "updated_at": "2026-06-11T15:59:49.137Z",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to latest patched version"
  },
  {
    "cve_id": "CVE-2017-5645",
    "age_in_days": 3342,
    "assignee": "security@apache.org",
    "cve_created_at": "2017-04-17T21:59:00Z",
    "cve_updated_at": "2026-05-13T00:24:29Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.99886,
    "epss_score": 0.93917,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "is_template": true,
    "poc_count": 2,
    "poc_first_seen": "2017-08-04T01:12:47Z",
    "pocs": [
      {
        "added_at": "2021-12-14T22:27:14Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/HynekPetrak/log4shell-finder"
      },
      {
        "added_at": "2017-08-04T01:12:47Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/pimps/CVE-2017-5645"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html"
      },
      {
        "added_at": "2026-06-12T04:15:55Z",
        "source": "nuclei_template",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2017-5645"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:2635"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:2636"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/ra38785cfc0e7f17f8e24bebf775dd032c033fadcaea29e5bc9fffc60%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf2567488cfc9212b42e34c6393cfa1c14e30e4838b98dda84d71041f%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:2888"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/8ab32b4c9f1826f20add7c40be08909de9f58a89dc1de9c09953f5ac%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rc1eaed7f7d774d5d02f66e49baced31e04827a1293d61a70bd003ca7%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf1bbc0ea4a9f014cf94df9a12a6477d24a27f52741dbc87f2fd52ff2%40%3Cissues.geode.apache.org%3E"
      },
      {
        "added_at": "2026-06-12T04:15:55Z",
        "source": "nuclei_template",
        "url": "http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:2637"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:3400"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/277b4b5c2b0e06a825ccec565fa65bd671f35a4d58e3e2ec5d0618e1%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/e8fb7d76a244ee997ba4b217d6171227f7c2521af8c7c5b16cba27bc%40%3Cdev.logging.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r3d666e4e8905157f3c046d31398b04f2bfd4519e31f266de108c6919%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r9d5c1b558a15d374bd5abd2d3ae3ca7e50e796a0efdcf91e9c5b4cdd%40%3Cgithub.beam.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://issues.apache.org/jira/browse/LOG4J2-1863"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/6114ce566200d76e3cc45c521a62c2c5a4eac15738248f58a99f622c%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r7bcdc710857725c311b856c0b82cee6207178af5dcde1bd43d289826%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rdbd579dc223f06af826d7de340218ee2f80d8b43fa7e4decb2a63f44%40%3Cgithub.beam.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:1417"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:3399"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20180726-0002/"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/9317fd092b257a0815434b116a8af8daea6e920b6673f4fd5583d5fe%40%3Ccommits.druid.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rca24a281000fb681d7e26e5c031a21eb4b0593a7735f781b53dae4e2%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/eea03d504b36e8f870e8321d908e1def1addda16adda04327fe7c125%40%3Cdev.logging.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r681b4432d0605f327b68b9f8a42662993e699d04614de4851c35ffd1%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/raedd12dc24412b3780432bf202a2618a21a727788543e5337a458ead%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2026-06-12T04:15:55Z",
        "source": "nuclei_template",
        "url": "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:1801"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:2809"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2019:1545"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r3a85514a518f3080ab1fc2652cfe122c2ccf67cfb32356acb1b08fe8%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/re8c21ed9dd218c217d242ffa90778428e446b082b5e1c29f567e8374%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2026-06-12T04:15:55Z",
        "source": "nuclei_template",
        "url": "http://www.openwall.com/lists/oss-security/2019/12/19/2"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:3244"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r2ce8d26154bea939536e6cf27ed02d3192bf5c5d04df885a80fe89b3%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rd5dbeee4808c0f2b9b51479b50de3cc6adb1072c332a200d9107f13e%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "http://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:2633"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r1b103833cb5bc8466e24ff0ecc5e75b45a705334ab6a444e64e840a0%40%3Cissues.bookkeeper.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r61590890edcc64140e0c606954b29a063c3d08a2b41d447256d51a78%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/bid/97702"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/0dcca05274d20ef2d72584edcf8c917bbb13dbbd7eb35cae909d02e9%40%3Cdev.logging.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/44491fb9cc19acc901f7cff34acb7376619f15638439416e3e14761c%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r0831e2e52a390758ce39a6193f82c11c295175adce6e6307de28c287%40%3Cissues.beam.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r2ff63f210842a3c5e42f03a35d8f3a345134d073c80a04077341c211%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rb1b29aee737e1c37fe1d48528cb0febac4f5deed51f5412e6fdfe2bf%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:2889"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r4b25538be50126194cc646836c718b1a4d8f71bd9c912af5b59134ad%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r94b5aae09c4bcff5d06cf641be17b00bd83ba7e10cad737bf16a1b8f%40%3Cgithub.beam.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rdec0d8ac1f03e6905b0de2df1d5fcdb98b94556e4f6cccf7519fdb26%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:2811"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rbfa7a0742be4981a3f9356a23d0e1a5f2e1eabde32a1a3d8e41420f8%40%3Cgithub.beam.apache.org%3E"
      },
      {
        "added_at": "2026-06-12T04:15:55Z",
        "source": "nuclei_template",
        "url": "https://github.com/vulhub/vulhub/tree/master/log4j/CVE-2017-5645"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id/1040200"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:2423"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/479471e6debd608c837b9815b76eab24676657d4444fcfd5ef96d6e6%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r23369fd603eb6d62d3b883a0a28d12052dcbd1d6d531137124cd7f83%40%3Cgithub.beam.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/ra9a682bc0a8dff1c5cefdef31c7c25f096d9121207cf2d74e2fc563d%40%3Ccommits.logging.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:2638"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:2808"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:2810"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rcbb79023a7c8494cb389cd3d95420fa9e0d531ece0b780b8c1f99422%40%3Ccommits.doris.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2017:1802"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/84cc4266238e057b95eb95dfd8b29d46a2592e7672c12c92f68b2917%40%3Cannounce.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r746fbc3fc13aee292ae6851f7a5080f592fa3a67b983c6887cdb1fc5%40%3Cdev.tika.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id/1041294"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r18f1c010b554a3a2d761e8ffffd8674fd4747bcbcf16c643d708318c%40%3Cissues.activemq.apache.org%3E"
      },
      {
        "added_at": "2025-04-20T01:37:25Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r3784834e80df2f284577a5596340fb84346c91a2dea6a073e65e3397%40%3Cissues.activemq.apache.org%3E"
      }
    ],
    "cwe": [
      "CWE-502"
    ],
    "description": "Apache Log4j 2.x before 2.8.2 contains a remote code execution caused by deserialization of crafted binary payloads received via TCP or UDP socket servers, letting attackers execute arbitrary code remotely, exploit requires sending malicious payloads over network.",
    "impact": "Attackers can execute arbitrary code remotely by sending malicious payloads, leading to full system compromise.",
    "name": "Apache Log4j - Remote Code Execution",
    "remediation": "Update to Log4j 2.8.2 or later.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "insecure_deserialization",
    "weaknesses": [
      {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data"
      }
    ],
    "category": "cve",
    "ref": "projectdiscovery/nuclei-templates:2c4c9867bfbd",
    "release_tag": "v9.5.1",
    "is_pdteam": true,
    "filename": "CVE-2017-5645.yaml",
    "uri": "network/cves/2017/CVE-2017-5645.yaml",
    "author": [
      "princechaddha"
    ],
    "metadata": {
      "max-request": 2,
      "product": "log4j",
      "vendor": "apache"
    },
    "tags": [
      "cve",
      "cve2017",
      "network",
      "vulhub",
      "apache",
      "log4j",
      "rce",
      "deserialization",
      "oast",
      "tcp",
      "vuln"
    ],
    "type": "tcp",
    "id": "CVE-2017-5645",
    "affected_products": [
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "retail_service_backbone",
        "summary": "oracle soa_suite is a comprehensive service-oriented architecture platform that enables integration and orchestration of business services. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "service_level_manager",
        "summary": "netapp service_level_manager is a storage management software that automates and optimizes storage service levels across hybrid cloud environments. It sits in the data_storage layer of the tech stack, functions as a core infrastructure service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "configuration_manager",
        "summary": "oracle endeca_information_discovery_studio is an enterprise data discovery and analytics platform that enables users to explore and analyze complex data sets. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "financial_services",
        "product": "financial_services_profitability_management",
        "summary": "oracle financial_services_regulatory_reporting_with_agilereporter is a regulatory reporting solution designed to streamline compliance and reporting processes for financial institutions. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the business_apps domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "primavera_gateway",
        "summary": "oracle retail_advanced_inventory_planning is an inventory optimization and demand forecasting solution that helps retailers improve stock availability and reduce costs. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "rapid_planning",
        "summary": "oracle retail_clearance_optimization_engine is a retail analytics and optimization solution that helps retailers maximize clearance sales and inventory turnover. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_workstation",
        "summary": "redhat enterprise_linux_workstation is a robust operating system designed for workstation environments that provides stability, security, and performance for professional users. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "financial_services",
        "product": "enterprise_manager_for_peoplesoft",
        "summary": "oracle financial_services_analytical_applications_infrastructure is a comprehensive analytics platform that supports financial services applications with data processing and insights. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure component in the software supply chain, and—within the financial_services industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "financial_services",
        "product": "financial_services_behavior_detection_platform",
        "summary": "oracle financial_services_hedge_management_and_ifrs_valuations is a financial risk management and accounting solution that helps organizations comply with IFRS standards and manage hedge accounting. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "mysql_enterprise_monitor",
        "summary": "oracle policy_automation is a business rules and decision automation software that enables organizations to automate complex policies and regulations. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_aus",
        "summary": "redhat enterprise_linux_server_aus is a Linux-based operating system designed for enterprise-grade server environments that provides stability, security, and performance. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "bi_publisher",
        "summary": "oracle bi_publisher is a reporting and document generation tool that enables the creation, management, and delivery of highly formatted reports and documents. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "flexcube_investor_servicing",
        "summary": "oracle fusion_middleware_mapviewer is a web-based mapping and visualization tool that enables integration of geographic data into applications. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "retail_extract_transform_and_load",
        "summary": "oracle retail_open_commerce_platform is a comprehensive retail commerce solution that enables seamless omnichannel shopping experiences. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_tus",
        "summary": "redhat enterprise_linux_server_tus is a Linux-based operating system designed for enterprise environments that provides a stable and secure platform for running applications and services. It sits in the operating_system layer of the tech stack, functions as a self-hosted operating system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "log4j",
        "summary": "apache log4j is a Java-based logging utility that provides flexible and reliable logging capabilities for applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "endeca_information_discovery_studio",
        "summary": "oracle enterprise_data_quality is a data quality management solution that helps organizations cleanse, match, and monitor data to ensure accuracy and consistency. It sits in the data_storage layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "peoplesoft_enterprise_fin_install",
        "summary": "oracle policy_automation_connector_for_siebel is an integration tool that connects Oracle Policy Automation with Siebel CRM to automate decision-making processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "policy_automation_for_mobile_devices",
        "summary": "oracle rapid_planning is a cloud-based enterprise planning and budgeting software that enables organizations to streamline financial planning processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "retail_open_commerce_platform",
        "summary": "oracle retail_service_backbone is an integration platform designed to connect and streamline retail systems and services. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "product": "weblogic_server",
        "vendor": "oracle"
      },
      {
        "category": "data_storage",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "storage_automation_store",
        "summary": "netapp storage_automation_store is a storage automation solution that optimizes data management and storage operations. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_webrtc_session_controller",
        "summary": "oracle communications_webrtc_session_controller is a real-time session control platform that manages WebRTC communications for service providers. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "identity_management_suite",
        "summary": "oracle identity_manager_connector is a software component that integrates identity management systems to streamline user provisioning and access control. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "financial_services",
        "product": "instantis_enterprisetrack",
        "summary": "oracle insurance_policy_administration is an insurance policy management system that automates and streamlines insurance policy lifecycle processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_service_broker",
        "summary": "oracle communications_service_broker is a network service orchestration platform that enables integration and management of telecom services. It sits in the core_infra layer of the tech stack, functions as a service orchestration tool in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "snapcenter",
        "summary": "netapp snapcenter is a centralized data protection and management software that simplifies backup, recovery, and cloning of enterprise data. It sits in the data_storage layer of the tech stack, functions as a core infrastructure tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "api_gateway",
        "summary": "oracle api_gateway is an API management and security platform that enables organizations to create, secure, and manage APIs. It sits in the core_infra layer of the tech stack, functions as a service gateway in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_converged_application_server_-_service_controller",
        "summary": "oracle communications_converged_application_server_-_service_controller is a telecom application server component that manages service lifecycle and orchestration in communication networks. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_instant_messaging_server",
        "summary": "oracle communications_instant_messaging_server is a real-time messaging server that enables instant communication across enterprise networks. It sits in the core_infra layer of the tech stack, functions as a network service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_interactive_session_recorder",
        "summary": "oracle communications_interactive_session_recorder is a session recording and monitoring solution that captures and analyzes communication sessions for compliance and quality assurance. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_manager_for_fusion_middleware",
        "summary": "oracle enterprise_manager_for_mysql_database is a database management and monitoring tool that provides performance tuning and administration for MySQL databases. It sits in the core_infra layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "financial_services",
        "product": "financial_services_analytical_applications_infrastructure",
        "summary": "oracle financial_services_behavior_detection_platform is a behavior detection platform designed to identify and mitigate financial fraud and risks. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "identity_manager_connector",
        "summary": "oracle in-memory_performance-driven_planning is a high-performance planning and analytics solution that leverages in-memory computing to accelerate decision-making processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "insurance_policy_administration",
        "summary": "oracle jd_edwards_enterpriseone_tools is a suite of development and deployment tools designed to customize and extend JD Edwards EnterpriseOne applications. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jdeveloper",
        "summary": "oracle peoplesoft_enterprise_fin_install is a financial management software suite that helps organizations manage accounting, procurement, and financial reporting. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "policy_automation_connector_for_siebel",
        "summary": "oracle primavera_gateway is an integration middleware that facilitates data exchange between Primavera P6 and other enterprise systems. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "soa_suite",
        "summary": "oracle timesten_in-memory_database is an in-memory data grid and database that accelerates application performance by storing data in memory. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "utilities_advanced_spatial_and_operational_analytics",
        "summary": "oracle weblogic_server is a Java EE application server that enables deployment and management of enterprise applications. It sits in the core_infra layer of the tech stack, functions as a middleware platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_workflow_automation",
        "summary": "netapp oncommand_workflow_automation is an IT automation and orchestration software that simplifies and automates storage and data management workflows. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_network_integrity",
        "summary": "oracle communications_network_integrity is a network integrity solution that ensures the security and reliability of telecommunications networks. It sits in the core_infra layer of the tech stack, functions as a security product in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "financial_services",
        "product": "insurance_calculation_engine",
        "summary": "oracle insurance_rules_palette is a business rules management system designed to automate and manage insurance policy rules and workflows. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "energy_utilities",
        "product": "timesten_in-memory_database",
        "summary": "oracle utilities_work_and_asset_management is an enterprise asset management solution that helps utilities optimize work and asset performance. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the energy_utilities industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "product": "utilities_work_and_asset_management",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_insight",
        "summary": "netapp oncommand_insight is an infrastructure analytics and monitoring solution that provides visibility and optimization for storage and data center resources. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "fuse",
        "summary": "redhat fuse is an open source integration platform that enables connectivity and communication between disparate applications and services. It sits in the core_infra layer of the tech stack, functions as a middleware integration platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_messaging_server",
        "summary": "oracle communications_messaging_server is a scalable messaging platform that provides email and collaboration services for telecom operators. It sits in the core_infra layer of the tech stack, functions as a self-hosted communication server in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_online_mediation_controller",
        "summary": "oracle communications_online_mediation_controller is a network mediation and data collection solution that enables real-time data processing and integration for telecom operators. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_manager_for_oracle_database",
        "summary": "oracle enterprise_manager_for_peoplesoft is a management and monitoring tool designed to optimize PeopleSoft applications and infrastructure. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "identity_analytics",
        "summary": "oracle identity_management_suite is a comprehensive identity and access management solution that secures user authentication and authorization across enterprise systems. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "retail_integration_bus",
        "summary": "oracle retail_predictive_application_server is a predictive analytics platform designed to optimize retail operations and forecasting. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux",
        "summary": "redhat enterprise_linux is a commercial Linux operating system distribution that provides a stable, secure, and supported platform for enterprise applications. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_manager_for_mysql_database",
        "summary": "oracle enterprise_manager_for_oracle_database is a comprehensive database management and monitoring tool that optimizes Oracle database performance and availability. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "financial_services",
        "product": "financial_services_loan_loss_forecasting_and_provisioning",
        "summary": "oracle financial_services_profitability_management is a financial analytics and profitability management solution that helps financial institutions optimize profitability and risk. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the business_apps domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "retail_clearance_optimization_engine",
        "summary": "oracle retail_integration_bus is an integration middleware that connects various retail systems and applications to streamline data flow and operations. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "application_testing_suite",
        "summary": "oracle application_testing_suite is an integrated testing solution that automates functional, regression, and load testing for enterprise applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the qa domain.",
        "tech_domain": "qa",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "financial_services",
        "product": "banking_platform",
        "summary": "oracle banking_platform is a comprehensive banking software solution that enables financial institutions to manage core banking operations efficiently. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_pricing_design_center",
        "summary": "oracle communications_pricing_design_center is a pricing and rating solution that enables telecom operators to design and manage complex pricing models. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the telecommunications industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jd_edwards_enterpriseone_tools",
        "summary": "oracle mysql_enterprise_monitor is a database monitoring and management tool that provides real-time performance insights and alerts for MySQL databases. It sits in the core_infra layer of the tech stack, functions as a self-hosted monitoring service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "retail_predictive_application_server",
        "summary": "oracle siebel_ui_framework is a user interface framework designed to build and customize Siebel CRM applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server",
        "summary": "redhat enterprise_linux_server is a robust and secure operating system designed for enterprise environments that provides a stable platform for applications and services. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "financial_services",
        "product": "financial_services_regulatory_reporting_with_agilereporter",
        "summary": "oracle flexcube_investor_servicing is a comprehensive investor servicing solution that manages investment portfolios and client interactions efficiently. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the business_apps domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "goldengate",
        "summary": "oracle goldengate_application_adapters is a set of pre-built adapters that simplify integration and data replication between heterogeneous systems. It sits in the core_infra layer of the tech stack, functions as a middleware integration tool in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_data_quality",
        "summary": "oracle enterprise_manager_base_platform is an IT management software that provides comprehensive monitoring and management of enterprise IT environments. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "cli",
        "industry": "information_technology",
        "product": "insurance_rules_palette",
        "summary": "oracle jdeveloper is an integrated development environment (IDE) that facilitates application development with comprehensive tools and features. It sits in the application_library layer of the tech stack, functions as a devtool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "autovue_vuelink_integration",
        "summary": "oracle autovue_vuelink_integration is an integration solution that connects Oracle's AutoVue with VUElink to enable seamless document visualization and collaboration. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "financial_services",
        "product": "financial_services_lending_and_leasing",
        "summary": "oracle financial_services_loan_loss_forecasting_and_provisioning is a financial analytics solution that helps forecast loan losses and manage provisioning for risk mitigation. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "mobile_iot_apps",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "policy_automation",
        "summary": "oracle policy_automation_for_mobile_devices is a mobile application that enables users to automate and enforce business policies on mobile devices. It sits in the mobile_iot_apps layer of the tech stack, functions as a consumer application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "retail_advanced_inventory_planning",
        "summary": "oracle retail_extract_transform_and_load is a data integration and processing tool designed to extract, transform, and load retail data efficiently. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_manager_base_platform",
        "summary": "oracle enterprise_manager_for_fusion_middleware is a comprehensive management tool that monitors and manages Oracle Fusion Middleware environments. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "financial_services",
        "product": "in-memory_performance-driven_planning",
        "summary": "oracle insurance_calculation_engine is a specialized software engine that performs complex insurance premium calculations and risk assessments. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "siebel_ui_framework",
        "summary": "oracle tape_library_acsls is a tape library management software that automates and manages tape storage for data backup and archiving. It sits in the data_storage layer of the tech stack, functions as an enterprise storage management system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "energy_utilities",
        "product": "tape_library_acsls",
        "summary": "oracle utilities_advanced_spatial_and_operational_analytics is an advanced analytics platform designed to optimize spatial and operational data for utility companies. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the energy_utilities industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "oncommand_api_services",
        "summary": "netapp oncommand_api_services is a storage management and automation platform that provides API-driven control over NetApp storage systems. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_desktop",
        "summary": "redhat enterprise_linux_desktop is a robust Linux-based operating system designed for desktop environments that provides stability and security for enterprise users. It sits in the operating_system layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux_server_eus",
        "summary": "redhat enterprise_linux_server_eus is a long-term supported Linux operating system designed for stability and security in enterprise environments. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "financial_services",
        "product": "financial_services_hedge_management_and_ifrs_valuations",
        "summary": "oracle financial_services_lending_and_leasing is a comprehensive lending and leasing management software that automates loan origination, servicing, and compliance processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the business_apps domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fusion_middleware_mapviewer",
        "summary": "oracle goldengate is a real-time data replication and integration solution that enables high availability and disaster recovery for enterprise data. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "goldengate_application_adapters",
        "summary": "oracle identity_analytics is an identity governance and analytics solution that helps organizations manage and secure user access across systems. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "oracle"
      }
    ],
    "created_at": "2017-04-17T21:59:00Z",
    "doc_id": "CVE-2017-5645",
    "doc_type": "cve_template",
    "exposure": {
      "max_hosts": 942013,
      "min_hosts": 7
    },
    "h1": {
      "rank": 2540,
      "reports": 1
    },
    "ntps": 68,
    "updated_at": "2026-06-12T04:15:55.154Z",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade log4j to latest patched version"
  },
  {
    "cve_id": "CVE-2021-45046",
    "age_in_days": 1634,
    "assignee": "security@apache.org",
    "cve_created_at": "2021-12-14T19:15:07Z",
    "cve_updated_at": "2025-10-27T17:35:56Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 9,
    "epss_percentile": 0.99957,
    "epss_score": 0.9434,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "is_template": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2023-05-01T00:00:00Z",
        "due_date": "2023-05-22T00:00:00Z",
        "known_ransomware_campaign_use": true,
        "source": "cisa"
      },
      {
        "added_date": "2021-12-06T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 17,
    "poc_first_seen": "2021-12-15T05:48:53Z",
    "pocs": [
      {
        "added_at": "2021-12-15T05:48:53Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/cckuailong/Log4j_CVE-2021-45046.git"
      },
      {
        "added_at": "2021-12-18T11:43:56Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/ludy-dev/cve-2021-45046"
      },
      {
        "added_at": "2025-07-23T13:55:58Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/ifconfig-me/Log4Shell-Payloads"
      },
      {
        "added_at": "2025-07-23T13:55:58Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:ifconfig-me/Log4Shell-Payloads.git"
      },
      {
        "added_at": "2021-12-20T12:07:41Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/lijiejie/log4j2_vul_local_scanner"
      },
      {
        "added_at": "2021-12-18T11:43:56Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:ludy-dev/cve-2021-45046.git"
      },
      {
        "added_at": "2021-12-18T11:43:56Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/ludy-dev/cve-2021-45046.git"
      },
      {
        "added_at": "2021-12-17T18:59:16Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/lukepasek/log4jjndilookupremove"
      },
      {
        "added_at": "2021-12-15T09:01:37Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/BobTheShoplifter/CVE-2021-45046-Info"
      },
      {
        "added_at": "2021-12-15T05:48:53Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/cckuailong/Log4j_CVE-2021-45046"
      },
      {
        "added_at": "2025-07-23T13:55:58Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/ifconfig-me/Log4Shell-Payloads.git"
      },
      {
        "added_at": "2024-05-09T03:04:17Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/shaily29-eng/CyberSecurity_CVE-2021-45046"
      },
      {
        "added_at": "2021-12-24T09:02:55Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/CaptanMoss/Log4Shell-Sandbox-Signature"
      },
      {
        "added_at": "2021-12-15T19:19:52Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/pravin-pp/log4j2-CVE-2021-45046"
      },
      {
        "added_at": "2021-12-15T16:28:11Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/tejas-nagchandi/CVE-2021-45046"
      },
      {
        "added_at": "2021-12-16T18:12:29Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/mergebase/log4j-samples"
      },
      {
        "added_at": "2021-12-15T05:48:53Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:cckuailong/Log4j_CVE-2021-45046.git"
      }
    ],
    "vuln_status": "confirmed",
    "citations": [
      {
        "added_at": "2026-05-11T06:34:54Z",
        "source": "nuclei_template",
        "url": "https://twitter.com/marcioalm/status/1471740771581652995"
      },
      {
        "added_at": "2026-05-11T06:34:54Z",
        "source": "nuclei_template",
        "url": "https://logging.apache.org/log4j/2.x/"
      },
      {
        "added_at": "2026-05-11T06:34:54Z",
        "source": "nuclei_template",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
      },
      {
        "added_at": "2025-06-27T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.tenable.com/blog/frequently-asked-questions-about-iranian-cyber-operations"
      },
      {
        "added_at": "2024-03-27T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.ptsecurity.com/ww-en/analytics/apt-groups-in-the-middle-east/"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00646.html"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-479842.pdf"
      },
      {
        "added_at": "2025-03-31T00:00:00Z",
        "source": "vulncheck",
        "url": "https://blog.talosintelligence.com/content/files/2025/03/2024YiR-report.pdf"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SIG7FZULMNK2XF6FZRU4VWYDQXNMUGAJ/"
      },
      {
        "added_at": "2026-03-31T00:00:00Z",
        "source": "vulncheck",
        "url": "https://fortiguard.fortinet.com/outbreak-alert/iran-linked-cyber-attacks"
      },
      {
        "added_at": "2024-10-16T00:00:00Z",
        "source": "vulncheck",
        "url": "https://pt-global.storage.yandexcloud.net/positive_research_2024_a9c4fb10c2.pdf"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://security.gentoo.org/glsa/202310-16"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://www.kb.cert.org/vuls/id/930724"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/alert-cve-2021-44228.html"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-397453.pdf"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-661247.pdf"
      },
      {
        "added_at": "2024-06-03T00:00:00Z",
        "source": "vulncheck",
        "url": "https://cloud.google.com/blog/topics/threat-intelligence/ransomware-attacks-surge-rely-on-public-legitimate-tools"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://logging.apache.org/log4j/2.x/security.html"
      },
      {
        "added_at": "2026-05-11T06:34:54Z",
        "source": "nuclei_template",
        "url": "http://www.openwall.com/lists/oss-security/2021/12/14/4"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpujul2022.html"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EOKPQGV24RRBBI4TBZUDQMM4MEH7MXCY/"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpuapr2022.html"
      },
      {
        "added_at": "2024-11-20T00:00:00Z",
        "source": "vulncheck",
        "url": "https://go.catonetworks.com/rs/245-RJK-441/images/CATO_CTRL_Report_Q3_2024.pdf"
      },
      {
        "added_at": "2024-07-18T00:00:00Z",
        "source": "vulncheck",
        "url": "https://rt-solar.ru/solar-4rays/blog/4527/"
      },
      {
        "added_at": "2026-03-23T00:00:00Z",
        "source": "vulncheck",
        "url": "https://storage.ghost.io/c/af/a0/afa04ee3-414f-4481-8d23-7e7c146f192e/content/files/2026/03/2025YiR-report.pdf"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2021/12/15/3"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2021/12/18/1"
      },
      {
        "added_at": "2026-05-11T06:34:54Z",
        "source": "nuclei_template",
        "url": "https://securitylab.github.com/advisories/GHSL-2021-1054_GHSL-2021-1055_log4j2/"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-714170.pdf"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0032"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpujan2022.html"
      },
      {
        "added_at": "2025-10-21T19:19:26Z",
        "source": "nvd",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-45046"
      },
      {
        "added_at": "2024-02-20T00:00:00Z",
        "source": "vulncheck",
        "url": "https://arcticwolf.com/arctic-wolf-labs-threat-report-2023/"
      },
      {
        "added_at": "2025-03-12T19:52:00Z",
        "source": "nvd",
        "url": "https://www.debian.org/security/2021/dsa-5022"
      }
    ],
    "cwe": [
      "CWE-917"
    ],
    "description": "Apache Log4j2 contains a remote code execution caused by vulnerable thread context lookup pattern in certain non-default configurations, letting remote attackers execute arbitrary code, exploit requires specific non-default configuration.",
    "impact": "Remote attackers can execute arbitrary code on affected systems, leading to full system compromise.",
    "name": "Apache Log4j2 - Remote Code Execution",
    "remediation": "Update to the latest version of Log4j2 or apply recommended configuration changes.",
    "requirement_type": "none",
    "severity": "critical",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "jndi_injection",
    "weaknesses": [
      {
        "cwe_id": "CWE-917",
        "cwe_name": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')"
      }
    ],
    "category": "cve",
    "ref": "projectdiscovery/nuclei-templates:a76a9baaf430",
    "release_tag": "v8.8.0",
    "filename": "CVE-2021-45046.yaml",
    "uri": "http/cves/2021/CVE-2021-45046.yaml",
    "author": [
      "imnightmaree"
    ],
    "metadata": {
      "max-request": 1,
      "product": "log4j",
      "vendor": "apache"
    },
    "tags": [
      "cve2021",
      "cve",
      "rce",
      "oast",
      "log4j",
      "injection",
      "kev",
      "apache",
      "vkev",
      "vuln"
    ],
    "type": "http",
    "id": "CVE-2021-45046",
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "energy_utilities",
        "product": "energy_engage",
        "summary": "siemens energy_engage is a digital energy management platform that optimizes energy consumption and sustainability for utilities and enterprises. It sits in the core_infra layer of the tech stack, functions as a software service in the software supply chain, and—within the energy_utilities industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "6bk1602-0aa32-0tp0_firmware",
        "summary": "siemens 6bk1602-0aa42-0tp0_firmware is a firmware component designed to control and operate industrial automation hardware. It sits in the hardware layer of the tech stack, functions as a firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "energy_utilities",
        "product": "sppa-t3000_ses3000_firmware",
        "summary": "siemens sppa-t3000_ses3000_firmware is a firmware component that controls and manages power plant turbine systems. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the energy_utilities industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "datacenter_manager",
        "summary": "intel datacenter_manager is a data center infrastructure management software that optimizes and monitors data center operations and hardware performance. It sits in the core_infra layer of the tech stack, functions as a self-hosted management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "intel"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "unclassified",
        "product": "sensor_solution_firmware_development_kit",
        "summary": "intel sensor_solution_firmware_development_kit is a firmware development kit that enables creation and customization of sensor firmware for embedded devices. It sits in the hardware layer of the tech stack, functions as a self-hosted development toolkit in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "intel"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "navigator",
        "summary": "siemens navigator is a digital operations platform that provides data-driven insights and analytics for industrial processes. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the industrial_control industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "energy_utilities",
        "product": "sentron_powermanager",
        "summary": "siemens sentron_powermanager is an energy management software that monitors and optimizes power consumption and distribution. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the energy_utilities industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "sipass_integrated",
        "summary": "siemens sipass_integrated is an access control system that manages physical security and access permissions for facilities. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "energy_utilities",
        "product": "spectrum_power_4",
        "summary": "siemens spectrum_power_4 is an advanced energy management system that optimizes power grid operations and enhances grid reliability. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the energy_utilities industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "fedora",
        "summary": "siemens 6bk1602-0aa12-0tp0_firmware is a firmware component designed for industrial automation hardware that controls and manages device operations. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "fedoraproject"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "desigo_cc_advanced_reports",
        "summary": "siemens desigo_cc_advanced_reports is an advanced reporting tool designed for building management and automation systems that enhances data analysis and operational insights. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "siguard_dsa",
        "summary": "siemens siguard_dsa is a digital security appliance designed to protect industrial control systems from cyber threats. It sits in the core_infra layer of the tech stack, functions as a security appliance in the software supply chain, and—within the industrial_control industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "siveillance_identity",
        "summary": "siemens siveillance_identity is a security management system that provides identity and access control solutions for physical security environments. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "siveillance_vantage",
        "summary": "siemens siveillance_vantage is a comprehensive video management system that enables real-time surveillance and security monitoring. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "manufacturing",
        "product": "solid_edge_harness_design",
        "summary": "siemens solid_edge_harness_design is a specialized CAD software for designing electrical wiring harnesses that enhances the accuracy and efficiency of electrical system layouts. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "energy_utilities",
        "product": "spectrum_power_7",
        "summary": "siemens spectrum_power_7 is an advanced energy management system that optimizes power grid operations and enhances grid reliability. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the energy_utilities industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "email_security",
        "summary": "fedoraproject fedora is a Linux-based open-source operating system that provides a robust and secure platform for developers and users. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "sonicwall"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "6bk1602-0aa12-0tp0_firmware",
        "summary": "siemens 6bk1602-0aa22-0tp0_firmware is a firmware component that controls and manages industrial automation hardware. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "log4j",
        "summary": "apache log4j is a Java-based logging utility that provides flexible and reliable logging capabilities for applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "system_debugger",
        "summary": "intel system_debugger is a debugging tool designed to analyze and troubleshoot system-level software and hardware interactions. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "intel"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "e-car_operation_center",
        "summary": "siemens e-car_operation_center is a management and monitoring system designed for electric vehicle operations that optimizes fleet performance and charging infrastructure. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "gma-manager",
        "summary": "siemens gma-manager is a software solution designed for managing and optimizing industrial automation processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "energy_utilities",
        "product": "head-end_system_universal_device_integration_system",
        "summary": "siemens head-end_system_universal_device_integration_system is a device integration and management system that collects and processes data from various field devices in utility networks. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure component in the software supply chain, and—within the energy_utilities industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "6bk1602-0aa22-0tp0_firmware",
        "summary": "siemens 6bk1602-0aa32-0tp0_firmware is a firmware component that controls and manages industrial automation hardware. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "desigo_cc_info_center",
        "summary": "siemens desigo_cc_info_center is a building management and automation platform that integrates various building systems for centralized control and monitoring. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "energy_utilities",
        "product": "energyip",
        "summary": "siemens energyip is an advanced energy data management and analytics platform that optimizes utility operations and grid management. It sits in the core_infra layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the energy_utilities industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "energy_utilities",
        "product": "energyip_prepay",
        "summary": "siemens energyip_prepay is a prepaid energy management solution that enables utilities to manage and monitor prepaid electricity consumption. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the energy_utilities industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "industrial_edge_management",
        "summary": "siemens industrial_edge_management is an edge computing platform that enables real-time data processing and management for industrial environments. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure platform in the software supply chain, and—within the industrial_control industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "mendix",
        "summary": "siemens mendix is a low-code application development platform that enables rapid creation and deployment of enterprise applications. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "manufacturing",
        "product": "nx",
        "summary": "siemens nx is an advanced computer-aided design (CAD) and manufacturing software that enables product engineering and digital twin creation. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "manufacturing",
        "product": "opcenter_intelligence",
        "summary": "siemens opcenter_intelligence is a manufacturing operations management software that provides advanced analytics and insights to optimize production processes. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "siveillance_viewpoint",
        "summary": "siemens siveillance_viewpoint is a video management software that provides centralized monitoring and control for security systems. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "industrial_control",
        "product": "comos",
        "summary": "siemens comos is an integrated software solution for plant engineering and operations that enhances collaboration and lifecycle management. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "computer_vision_annotation_tool",
        "summary": "cvat computer_vision_annotation_tool is an open-source web-based tool that facilitates annotation of images and videos for computer vision tasks. It sits in the application_library layer of the tech stack, functions as a self-hosted tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "cvat"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "manufacturing",
        "product": "solid_edge_cam_pro",
        "summary": "siemens solid_edge_cam_pro is a computer-aided manufacturing (CAM) software that provides advanced machining and manufacturing solutions. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "sonicwall email_security is an email protection solution that safeguards organizations from spam, phishing, and malware attacks. It sits in the core_infra layer of the tech stack, functions as a security service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "debian"
      },
      {
        "category": "hardware",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "6bk1602-0aa42-0tp0_firmware",
        "summary": "siemens 6bk1602-0aa52-0tp0_firmware is a firmware component designed to control and manage industrial automation hardware. It sits in the hardware layer of the tech stack, functions as firmware in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "product": "6bk1602-0aa52-0tp0_firmware",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "manufacturing",
        "product": "captial",
        "summary": "siemens captial is an engineering software suite that provides integrated solutions for electrical, fluid, and wire harness design in manufacturing. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "industrial_edge_management_hub",
        "summary": "siemens industrial_edge_management_hub is an edge computing platform that enables management and orchestration of industrial edge applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted infrastructure platform in the software supply chain, and—within the industrial_control industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "siveillance_control_pro",
        "summary": "siemens siveillance_control_pro is a security management system that integrates video surveillance and access control for enhanced facility security. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "manufacturing",
        "product": "teamcenter",
        "summary": "siemens teamcenter is a product lifecycle management (PLM) software that helps organizations manage product data and processes across the lifecycle. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "tracealertserverplus",
        "summary": "siemens vesys is an engineering software solution that supports the design and analysis of electrical systems. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "manufacturing",
        "product": "vesys",
        "summary": "siemens xpedition_enterprise is an advanced electronic design automation (EDA) software suite that enables PCB design and manufacturing optimization. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the manufacturing industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "xpedition_package_integrator",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "siemens"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "industrial_control",
        "product": "mindsphere",
        "summary": "siemens mindsphere is an industrial IoT platform that connects products, plants, systems, and machines to harness data for analytics and optimization. It sits in the core_infra layer of the tech stack, functions as a software platform in the software supply chain, and—within the industrial_control industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "hardware",
        "deployment_model": "self_hosted",
        "industry": "unclassified",
        "product": "audio_development_kit",
        "summary": "intel audio_development_kit is a hardware and software toolkit that enables development and testing of audio applications and devices. It sits in the hardware layer of the tech stack, functions as a self-hosted development tool in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "intel"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "oneapi",
        "summary": "intel oneapi is a unified programming model and toolkit that simplifies development across diverse computing architectures. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "intel"
      },
      {
        "category": "core_infra",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "secure_device_onboard",
        "summary": "intel secure_device_onboard is a secure provisioning solution that simplifies device onboarding and authentication for IoT devices. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "intel"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "industrial_control",
        "product": "logo\\!_soft_comfort",
        "summary": "siemens logo!_soft_comfort is a programming software tool designed for configuring and simulating Siemens LOGO! logic modules used in automation. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "industrial_control",
        "product": "operation_scheduler",
        "summary": "siemens operation_scheduler is an industrial control software that manages and schedules manufacturing and production operations. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "industrial_control",
        "product": "siveillance_command",
        "summary": "siemens siveillance_command is a security management system that integrates and controls video surveillance and access control devices. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the industrial_control industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "unclassified",
        "product": "xpedition_enterprise",
        "summary": "siemens xpedition_package_integrator is an electronic design automation tool that facilitates package design and integration for semiconductor devices. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "siemens"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "genomics_kernel_library",
        "summary": "intel genomics_kernel_library is a specialized software library that provides optimized computational kernels for genomic data processing. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "intel"
      },
      {
        "category": "application_library",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "system_studio",
        "summary": "intel system_studio is an integrated development environment (IDE) designed to optimize embedded and IoT applications. It sits in the application_library layer of the tech stack, functions as a development tool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "intel"
      }
    ],
    "created_at": "2021-12-14T19:15:07Z",
    "doc_id": "CVE-2021-45046",
    "doc_type": "cve_template",
    "exposure": {
      "max_hosts": 4148165,
      "min_hosts": 25
    },
    "h1": {
      "rank": 753,
      "reports": 7
    },
    "ntps": 85,
    "updated_at": "2026-06-06T15:49:00.461Z",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade log4j - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2021-4104",
    "age_in_days": 1640,
    "assignee": "security@apache.org",
    "cve_created_at": "2021-12-14T12:15:12Z",
    "cve_updated_at": "2026-05-28T21:16:28Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 7.5,
    "epss_percentile": 0.98775,
    "epss_score": 0.72202,
    "is_auth": true,
    "is_kev": true,
    "is_oss": true,
    "is_poc": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2022-04-26T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 2,
    "poc_first_seen": "2021-12-14T12:35:08Z",
    "pocs": [
      {
        "added_at": "2025-07-11T04:01:42Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/cuijiung/log4j-CVE-2021-4104"
      },
      {
        "added_at": "2021-12-14T12:35:08Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/cckuailong/log4shell_1.x"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://security.gentoo.org/glsa/202312-04"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://access.redhat.com/security/cve/CVE-2021-4104"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0033"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20211223-0007/"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://www.cve.org/CVERecord?id=CVE-2021-44228"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2022/01/18/3"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://security.gentoo.org/glsa/202209-02"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://security.gentoo.org/glsa/202312-02"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpuapr2022.html"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpujan2022.html"
      },
      {
        "added_at": "2023-09-21T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.secureworks.com/research/threat-profiles/gold-melody"
      },
      {
        "added_at": "2022-04-26T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/cyber-year-in-retrospect/yir-cyber-threats-annex-download.pdf"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://security.gentoo.org/glsa/202310-16"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://www.kb.cert.org/vuls/id/930724"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpujul2022.html"
      },
      {
        "added_at": "2024-11-21T06:36:54Z",
        "source": "nvd",
        "url": "https://github.com/apache/logging-log4j2/pull/608#issuecomment-990494126"
      }
    ],
    "cwe": [
      "CWE-502"
    ],
    "description": "Log4j 1.2 with JMSAppender configured contains a deserialization of untrusted data caused by write access to the configuration, letting attackers perform JNDI requests that may lead to remote code execution, exploit requires attacker to have write access to Log4j configuration.",
    "impact": "Attackers can execute remote code via JNDI requests, leading to full system compromise.",
    "name": "Log4j - JNDI Injection",
    "remediation": "Upgrade to Log4j 2, which addresses this and other issues.",
    "requirement_type": "logged_in",
    "requirements": "Attacker needs write access to Log4j configuration",
    "severity": "high",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "jndi_injection",
    "weaknesses": [
      {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data"
      }
    ],
    "affected_products": [
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_operations_network",
        "summary": "redhat jboss_operations_network is a management and monitoring solution for JBoss middleware that helps optimize application performance and availability. It sits in the core_infra layer of the tech stack, functions as an enterprise management tool in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "process_automation",
        "summary": "redhat process_automation is a business process management and automation platform that enables organizations to design, execute, and monitor business workflows. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "redhat"
      },
      {
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_linux",
        "summary": "redhat enterprise_linux is a commercial Linux operating system distribution that provides a stable, secure, and supported platform for enterprise applications. It sits in the operating_system layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "business_process_management_suite",
        "summary": "oracle business_process_management_suite is a comprehensive business process management platform that enables organizations to model, automate, and optimize workflows. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "undefined",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "communications_eagle_ftp_table_base_retrieval",
        "summary": "oracle communications_eagle_ftp_table_base_retrieval is a specialized component likely used for retrieving FTP table data within Oracle's Communications Eagle suite. It sits in the undefined layer of the tech stack, functions as an unknown type in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_unified_inventory_management",
        "summary": "oracle communications_unified_inventory_management is a network inventory management solution that provides unified visibility and control over telecom assets. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the telecommunications industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "mysql_enterprise_monitor",
        "summary": "oracle mysql_enterprise_monitor is a database monitoring and management tool that provides real-time performance insights and alerts for MySQL databases. It sits in the core_infra layer of the tech stack, functions as a self-hosted monitoring service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "log4j",
        "summary": "apache log4j is a Java-based logging utility that provides flexible and reliable logging capabilities for applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "codeready_studio",
        "summary": "redhat codeready_studio is an integrated development environment (IDE) designed to facilitate application development with tools and frameworks. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_network_integrity",
        "summary": "oracle communications_network_integrity is a network integrity solution that ensures the security and reliability of telecommunications networks. It sits in the core_infra layer of the tech stack, functions as a security product in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "energy_utilities",
        "product": "utilities_testing_accelerator",
        "summary": "oracle utilities_testing_accelerator is a specialized testing tool designed to accelerate and automate testing processes for utility industry applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the energy_utilities industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "integration_camel_quarkus",
        "summary": "redhat integration_camel_quarkus is a lightweight integration framework that enables building cloud-native applications using Apache Camel on Quarkus. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_data_virtualization",
        "summary": "redhat jboss_data_virtualization is a data integration and virtualization platform that enables unified access to diverse data sources. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redhat"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "software_collections",
        "summary": "redhat software_collections is a set of dynamic programming languages, databases, and tools that enable developers to use newer versions on Red Hat Enterprise Linux without affecting the base system. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_messaging_server",
        "summary": "oracle communications_messaging_server is a scalable messaging platform that provides email and collaboration services for telecom operators. It sits in the core_infra layer of the tech stack, functions as a self-hosted communication server in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
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
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "integration_camel_k",
        "summary": "redhat integration_camel_k is a lightweight integration platform that enables running Apache Camel routes natively on Kubernetes. It sits in the core_infra layer of the tech stack, functions as a self-hosted integration runtime in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "enterprise_manager_base_platform",
        "summary": "oracle enterprise_manager_base_platform is an IT management software that provides comprehensive monitoring and management of enterprise IT environments. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "fusion_middleware_common_libraries_and_tools",
        "summary": "oracle fusion_middleware_common_libraries_and_tools is a set of reusable libraries and tools that support the development and integration of enterprise applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "retail_extract_transform_and_load",
        "summary": "oracle retail_extract_transform_and_load is a data integration and processing tool designed to extract, transform, and load retail data efficiently. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "stream_analytics",
        "summary": "oracle stream_analytics is a real-time data processing and analytics platform that enables continuous insights from streaming data. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "e-business_suite_cloud_manager_and_cloud_backup_module",
        "summary": "oracle e-business_suite_cloud_manager_and_cloud_backup_module is a cloud management and backup solution designed to optimize and protect Oracle E-Business Suite environments. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "hyperion_data_relationship_management",
        "summary": "oracle hyperion_data_relationship_management is a master data management solution that centralizes and governs enterprise data relationships for improved accuracy and compliance. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "cli",
        "industry": "information_technology",
        "product": "jdeveloper",
        "summary": "oracle jdeveloper is an integrated development environment (IDE) that facilitates application development with comprehensive tools and features. It sits in the application_library layer of the tech stack, functions as a devtool in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "timesten_grid",
        "summary": "oracle timesten_grid is an in-memory data grid that accelerates application performance and scalability by caching data in memory. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_enterprise_application_platform",
        "summary": "redhat jboss_enterprise_application_platform is a middleware platform that enables development and deployment of Java applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted application server in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "single_sign-on",
        "summary": "redhat single_sign-on is an identity and access management solution that provides secure single sign-on capabilities for applications and services. It sits in the core_infra layer of the tech stack, functions as a security service in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "business_intelligence",
        "summary": "oracle business_intelligence is a comprehensive analytics and reporting platform that enables organizations to make data-driven decisions. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "retail_allocation",
        "summary": "oracle retail_allocation is a retail inventory allocation solution that optimizes product distribution across stores and channels. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "weblogic_server",
        "summary": "oracle weblogic_server is a Java EE application server that enables deployment and management of enterprise applications. It sits in the core_infra layer of the tech stack, functions as a middleware platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_a-mq",
        "summary": "redhat jboss_a-mq is a messaging middleware that enables reliable communication between distributed applications. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_a-mq_streaming",
        "summary": "redhat jboss_a-mq_streaming is a messaging and streaming platform that enables real-time data integration and event-driven applications. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_data_grid",
        "summary": "redhat jboss_data_grid is an in-memory distributed data grid that provides fast, scalable data storage and caching. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_fuse",
        "summary": "redhat jboss_fuse is an open-source integration platform that enables developers to connect applications, services, and devices. It sits in the core_infra layer of the tech stack, functions as a middleware integration platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "openshift_application_runtimes",
        "summary": "redhat openshift_application_runtimes is a set of cloud-native runtimes that enable developers to build and deploy applications on Kubernetes. It sits in the core_infra layer of the tech stack, functions as a platform service in the software supply chain, and—within the information_technology industry—serves the devtools domain.",
        "tech_domain": "devtools",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "openshift_container_platform",
        "summary": "redhat openshift_container_platform is a comprehensive Kubernetes container orchestration platform that automates deployment, scaling, and management of containerized applications. It sits in the core_infra layer of the tech stack, functions as a self-hosted platform in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_offline_mediation_controller",
        "summary": "oracle communications_offline_mediation_controller is a mediation and data processing solution that collects, processes, and transforms offline communication data for billing and analytics. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "financial_services",
        "product": "financial_services_revenue_management_and_billing_analytics",
        "summary": "oracle financial_services_revenue_management_and_billing_analytics is an analytics and billing management solution designed to optimize revenue processes in financial services. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_fuse_service_works",
        "summary": "redhat jboss_fuse_service_works is an integration platform that enables the connection of applications, services, and devices across hybrid environments. It sits in the core_infra layer of the tech stack, functions as a middleware integration service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "redhat"
      },
      {
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "jboss_web_server",
        "summary": "redhat jboss_web_server is a web server platform that delivers scalable and secure web hosting for Java applications. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "redhat"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "advanced_supply_chain_planning",
        "summary": "oracle advanced_supply_chain_planning is an enterprise software solution that optimizes and manages supply chain operations for businesses. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
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
        "category": "data_storage",
        "deployment_model": "unknown",
        "industry": "healthcare",
        "product": "healthcare_data_repository",
        "summary": "oracle healthcare_data_repository is a data storage solution designed to securely store and manage healthcare data. It sits in the data_storage layer of the tech stack, functions as a data storage system in the software supply chain, and—within the healthcare industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "financial_services",
        "product": "hyperion_infrastructure_technology",
        "summary": "oracle hyperion_infrastructure_technology is a financial performance management platform that provides infrastructure for enterprise planning, budgeting, and forecasting. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "identity_management_suite",
        "summary": "oracle identity_management_suite is a comprehensive identity and access management solution that secures user authentication and authorization across enterprise systems. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the security domain.",
        "tech_domain": "security",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "tuxedo",
        "summary": "oracle tuxedo is a middleware platform that manages distributed transaction processing and application server services. It sits in the core_infra layer of the tech stack, functions as a core infrastructure service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      }
    ],
    "created_at": "2021-12-14T12:15:12Z",
    "doc_id": "CVE-2021-4104",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 942013,
      "min_hosts": 88
    },
    "h1": {
      "delta_rank": 1,
      "rank": 2534,
      "reports": 1
    },
    "ntps": 70,
    "updated_at": "2026-06-11T16:03:11.009Z",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade log4j - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2023-26464",
    "age_in_days": 1189,
    "assignee": "security@apache.org",
    "cve_created_at": "2023-03-10T14:15:10Z",
    "cve_updated_at": "2025-02-13T17:16:12Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "cvss_score": 7.5,
    "epss_percentile": 0.31311,
    "epss_score": 0.00125,
    "is_kev": true,
    "is_oss": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2025-12-08T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-02-13T17:16:12Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20230505-0008/"
      },
      {
        "added_at": "2025-12-08T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.f5.com/labs/articles/shellshock-makes-a-comeback-and-rondodox-changes-tactics"
      },
      {
        "added_at": "2025-02-13T17:16:12Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread/wkx6grrcjkh86crr49p4blc1v1nflj3t"
      }
    ],
    "cwe": [
      "CWE-502"
    ],
    "description": "Log4j 1.x on JRE less than 1.7 contains a denial of service caused by deserialization of specially-crafted nested hashmaps or hashtables, letting attackers exhaust memory, exploit requires attacker to cause specific logging entries.",
    "impact": "Attackers can cause memory exhaustion leading to denial of service, potentially crashing the application or system.",
    "name": "Log4j - Denial of Service",
    "remediation": "Update to Log4j 2.x or later versions.",
    "requirement_type": "user_interaction",
    "requirements": "Attacker needs to cause specific logging entries",
    "severity": "high",
    "vulnerability_impact": [
      "denial_of_service"
    ],
    "vulnerability_type": "insecure_deserialization",
    "weaknesses": [
      {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data"
      }
    ],
    "affected_products": [
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "log4j",
        "summary": "apache log4j is a Java-based logging utility that provides flexible and reliable logging capabilities for applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      }
    ],
    "created_at": "2023-03-10T14:15:10Z",
    "doc_id": "CVE-2023-26464",
    "doc_type": "cve",
    "exposure": {},
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 49,
    "updated_at": "2026-06-11T16:01:23.563Z",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade log4j - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2021-44832",
    "age_in_days": 1625,
    "assignee": "security@apache.org",
    "cve_created_at": "2021-12-28T20:15:08Z",
    "cve_updated_at": "2026-05-29T20:16:21Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 6.6,
    "epss_percentile": 0.98042,
    "epss_score": 0.53591,
    "is_auth": true,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2023-02-14T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 2,
    "poc_first_seen": "2021-12-29T07:50:05Z",
    "pocs": [
      {
        "added_at": "2021-12-29T08:22:41Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/name/log4j-scanner"
      },
      {
        "added_at": "2021-12-29T07:50:05Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/cckuailong/log4j_RCE_CVE-2021-44832"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T06:31:34Z",
        "source": "nvd",
        "url": "https://issues.apache.org/jira/browse/LOG4J2-3293"
      },
      {
        "added_at": "2026-03-23T00:00:00Z",
        "source": "vulncheck",
        "url": "https://storage.ghost.io/c/af/a0/afa04ee3-414f-4481-8d23-7e7c146f192e/content/files/2026/03/2025YiR-report.pdf"
      },
      {
        "added_at": "2024-03-27T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.ptsecurity.com/ww-en/analytics/apt-groups-in-the-middle-east/"
      },
      {
        "added_at": "2024-11-21T06:31:34Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2021/12/28/1"
      },
      {
        "added_at": "2024-11-21T06:31:34Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread/s1o5vlo78ypqxnzn6p8zf6t9shtq5143"
      },
      {
        "added_at": "2024-11-21T06:31:34Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20220104-0001/"
      },
      {
        "added_at": "2025-03-31T00:00:00Z",
        "source": "vulncheck",
        "url": "https://blog.talosintelligence.com/content/files/2025/03/2024YiR-report.pdf"
      },
      {
        "added_at": "2024-06-01T00:00:00Z",
        "source": "vulncheck",
        "url": "https://securityaffairs.com/163984/hacking/critical-apache-log4j2-flaw-still-threatens-global-finance.html"
      },
      {
        "added_at": "2023-08-08T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.securin.io/wp-content/uploads/2023/08/2023-State-of-Cybersecurity-for-Medical-Devices-and-Healthcare-Systems.pdf"
      },
      {
        "added_at": "2024-11-21T06:31:34Z",
        "source": "nvd",
        "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-784507.pdf"
      },
      {
        "added_at": "2024-11-21T06:31:34Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpujan2022.html"
      },
      {
        "added_at": "2024-11-21T06:31:34Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EVV25FXL4FU5X6X5BSL7RLQ7T6F65MRA/"
      },
      {
        "added_at": "2024-10-16T00:00:00Z",
        "source": "vulncheck",
        "url": "https://pt-global.storage.yandexcloud.net/positive_research_2024_a9c4fb10c2.pdf"
      },
      {
        "added_at": "2023-02-14T00:00:00Z",
        "source": "vulncheck",
        "url": "https://info.securin.io/hubfs/Securin%20Ransomware%20Report%202023.pdf"
      },
      {
        "added_at": "2024-11-21T06:31:34Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpuapr2022.html"
      },
      {
        "added_at": "2024-11-21T06:31:34Z",
        "source": "nvd",
        "url": "https://www.oracle.com/security-alerts/cpujul2022.html"
      },
      {
        "added_at": "2024-11-21T06:31:34Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/T57MPJUW3MA6QGWZRTMCHHMMPQNVKGFC/"
      },
      {
        "added_at": "2024-11-21T06:31:34Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2021/12/msg00036.html"
      },
      {
        "added_at": "2024-11-21T06:31:34Z",
        "source": "nvd",
        "url": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd"
      }
    ],
    "cwe": [
      "CWE-20"
    ],
    "description": "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding 2.3.2 and 2.12.4) contain a remote code execution caused by unsafe JNDI LDAP data source URI usage in JDBC Appender, letting attackers with control of LDAP server execute arbitrary code, exploit requires attacker to control LDAP server.",
    "impact": "Attackers controlling LDAP servers can execute arbitrary code remotely on affected systems.",
    "name": "Apache Log4j2 - Remote Code Execution",
    "remediation": "Update to Log4j2 version 2.17.1, 2.12.4, or 2.3.2 to mitigate the vulnerability.",
    "requirement_type": "none",
    "severity": "medium",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "jndi_injection",
    "weaknesses": [
      {
        "cwe_id": "CWE-20",
        "cwe_name": "Improper Input Validation"
      }
    ],
    "affected_products": [
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "primavera_p6_enterprise_project_portfolio_management",
        "summary": "oracle primavera_p6_enterprise_project_portfolio_management is an enterprise project portfolio management software that helps organizations plan, manage, and execute projects efficiently. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "information_technology",
        "product": "retail_assortment_planning",
        "summary": "oracle retail_assortment_planning is a retail planning software that helps optimize product assortments to maximize sales and profitability. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "siebel_ui_framework",
        "summary": "oracle siebel_ui_framework is a user interface framework designed to build and customize Siebel CRM applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "weblogic_server",
        "summary": "oracle weblogic_server is a Java EE application server that enables deployment and management of enterprise applications. It sits in the core_infra layer of the tech stack, functions as a middleware platform in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "cloudcenter",
        "summary": "cisco cloudcenter is a cloud management platform that enables deployment and governance of applications across multiple cloud environments. It sits in the core_infra layer of the tech stack, functions as a platform service in the software supply chain, and—within the information_technology industry—serves the devops domain.",
        "tech_domain": "devops",
        "vendor": "cisco"
      },
      {
        "category": "mobile_iot_apps",
        "deployment_model": "saas",
        "industry": "information_technology",
        "product": "policy_automation_for_mobile_devices",
        "summary": "oracle policy_automation_for_mobile_devices is a mobile application that enables users to automate and enforce business policies on mobile devices. It sits in the mobile_iot_apps layer of the tech stack, functions as a consumer application in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "product_lifecycle_analytics",
        "summary": "oracle product_lifecycle_analytics is an analytics solution that provides insights into product development and lifecycle management. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the unclassified industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "retail_xstore_point_of_service",
        "summary": "oracle retail_xstore_point_of_service is a point-of-sale software solution that enables retail transactions and store operations management. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the retail industry—serves the business_apps domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_diameter_signaling_router",
        "summary": "oracle communications_diameter_signaling_router is a network signaling router that manages and routes Diameter signaling traffic for telecom networks. It sits in the core_infra layer of the tech stack, functions as a network infrastructure component in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "primavera_unifier",
        "summary": "oracle primavera_unifier is an enterprise project portfolio management software that helps organizations manage capital projects and facilities. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "unknown",
        "industry": "unclassified",
        "product": "retail_fiscal_management",
        "summary": "oracle retail_fiscal_management is a fiscal compliance and tax management solution designed for retail businesses to ensure accurate financial reporting and regulatory adherence. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the retail industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "financial_services",
        "product": "flexcube_private_banking",
        "summary": "oracle flexcube_private_banking is a comprehensive core banking solution designed to manage private banking operations and client relationships. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the financial_services industry—serves the business_apps domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "data_storage",
        "deployment_model": "unknown",
        "industry": "healthcare",
        "product": "health_sciences_data_management_workbench",
        "summary": "oracle health_sciences_data_management_workbench is a data management platform that facilitates clinical data integration and analysis for healthcare research. It sits in the data_storage layer of the tech stack, functions as a business application in the software supply chain, and—within the healthcare industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "hybrid",
        "industry": "information_technology",
        "product": "policy_automation",
        "summary": "oracle policy_automation is a business rules and decision automation software that enables organizations to automate complex policies and regulations. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "primavera_gateway",
        "summary": "oracle primavera_gateway is an integration middleware that facilitates data exchange between Primavera P6 and other enterprise systems. It sits in the core_infra layer of the tech stack, functions as a middleware service in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "oracle"
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
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "debian_linux",
        "summary": "debian debian_linux is a free and open-source operating system that provides a stable and secure platform for various computing environments. It sits in the operating_system layer of the tech stack, functions as a self-hosted system in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "debian"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_offline_mediation_controller",
        "summary": "oracle communications_offline_mediation_controller is a mediation and data processing solution that collects, processes, and transforms offline communication data for billing and analytics. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "log4j",
        "summary": "apache log4j is a Java-based logging utility that provides flexible and reliable logging capabilities for applications. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "apache"
      },
      {
        "category": "core_infra",
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "communications_interactive_session_recorder",
        "summary": "oracle communications_interactive_session_recorder is a session recording and monitoring solution that captures and analyzes communication sessions for compliance and quality assurance. It sits in the core_infra layer of the tech stack, functions as a service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "core_infra",
        "deployment_model": "self_hosted",
        "industry": "telecommunications",
        "product": "communications_brm_-_elastic_charging_engine",
        "summary": "oracle communications_brm_-_elastic_charging_engine is a real-time charging and billing solution designed for telecommunications providers to manage usage and billing efficiently. It sits in the core_infra layer of the tech stack, functions as a self-hosted service in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
        "tech_domain": "N/A",
        "vendor": "oracle"
      },
      {
        "category": "enterprise",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "retail_order_broker",
        "summary": "oracle retail_order_broker is an order management system that facilitates order orchestration and fulfillment across retail channels. It sits in the enterprise layer of the tech stack, functions as a business application in the software supply chain, and—within the information_technology industry—serves the business_apps domain.",
        "tech_domain": "business_apps",
        "vendor": "oracle"
      }
    ],
    "created_at": "2021-12-28T20:15:08Z",
    "doc_id": "CVE-2021-44832",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 4038838,
      "min_hosts": 26
    },
    "h1": {
      "delta_rank": -2,
      "rank": 1255,
      "reports": 3
    },
    "ntps": 67,
    "updated_at": "2026-06-11T14:25:46.339Z",
    "product": "log4j",
    "pinned_version": "2.14.1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade log4j - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2002-1399",
    "age_in_days": 8546,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2003-01-17T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.64401,
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
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2003-01-17T05:00:00Z",
    "doc_id": "CVE-2002-1399",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 476261,
      "min_hosts": 476261
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-06-11T14:10:46.075Z",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1902",
    "age_in_days": 4815,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-04-04T17:55:00Z",
    "cve_updated_at": "2026-04-29T01:13:23Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.67362,
    "epss_score": 0.00523,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.postgresql.org/support/security/"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.postgresql.org/about/news/1456/"
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
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2013-04-04T17:55:00Z",
    "doc_id": "CVE-2013-1902",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 476261,
      "min_hosts": 476261
    },
    "h1": {
      "delta_rank": 14,
      "delta_reports": -1,
      "rank": 7968
    },
    "ntps": 45,
    "updated_at": "2026-06-11T14:28:51.839Z",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2007-3279",
    "age_in_days": 6931,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2007-06-19T21:30:00Z",
    "cve_updated_at": "2026-04-23T00:35:47Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.8662,
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
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2007-06-19T21:30:00Z",
    "doc_id": "CVE-2007-3279",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 476261,
      "min_hosts": 476261
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-06-11T14:58:47.924Z",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2013-1903",
    "age_in_days": 4815,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-04-04T17:55:00Z",
    "cve_updated_at": "2026-04-29T01:13:23Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.68417,
    "epss_score": 0.0055,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.postgresql.org/about/news/1456/"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.postgresql.org/support/security/"
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
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2013-04-04T17:55:00Z",
    "doc_id": "CVE-2013-1903",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 476261,
      "min_hosts": 476261
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-06-11T15:28:04.588Z",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2024-1597",
    "age_in_days": 843,
    "assignee": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007",
    "cve_created_at": "2024-02-19T13:15:07Z",
    "cve_updated_at": "2025-11-03T22:16:40Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 10,
    "epss_percentile": 0.57875,
    "epss_score": 0.0035,
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
        "url": "https://www.enterprisedb.com/docs/jdbc_connector/latest/01_jdbc_rel_notes/"
      },
      {
        "added_at": "2024-10-30T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.reliaquest.com/blog/5-critical-threat-actors-you-need-to-know-about/"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TZQTSMESZD2RJ5XBPSXH3TIQVUW5DIUU/"
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
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-24rp-q3w6-vc56"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://www.enterprisedb.com/docs/security/assessments/cve-2024-1597/"
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
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "postgresql_jdbc_driver",
        "summary": "postgresql postgresql_jdbc_driver is a database connectivity library that enables Java applications to interact with PostgreSQL databases. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "postgresql"
      },
      {
        "category": "operating_system",
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
      "max_hosts": 31320,
      "min_hosts": 31320
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 61,
    "updated_at": "2026-06-11T16:02:10.025Z",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": true,
    "recommendation": "Upgrade postgresql to latest patched version"
  },
  {
    "cve_id": "CVE-2019-9193",
    "age_in_days": 2628,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2019-04-01T21:30:45Z",
    "cve_updated_at": "2024-11-21T04:51:10Z",
    "cvss_metrics": "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 7.2,
    "epss_percentile": 0.99851,
    "epss_score": 0.93645,
    "is_auth": true,
    "is_kev": true,
    "is_oss": true,
    "is_poc": true,
    "is_remote": true,
    "is_template": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2021-01-22T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 32,
    "poc_first_seen": "2019-04-01T21:30:45Z",
    "pocs": [
      {
        "added_at": "2024-10-07T11:28:34Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/A0be/CVE-2019-9193.git"
      },
      {
        "added_at": "2023-02-01T16:41:15Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:paulotrindadec/CVE-2019-9193.git"
      },
      {
        "added_at": "2023-02-01T16:41:15Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/paulotrindadec/CVE-2019-9193.git"
      },
      {
        "added_at": "2025-11-17T15:18:42Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/netw0rk7/CVE-2019-9193-Home-Lab"
      },
      {
        "added_at": "2024-10-07T04:40:51Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:AxthonyV/CVE-2019-9193.git"
      },
      {
        "added_at": "2024-10-06T17:16:44Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/geniuszly/CVE-2019-9193"
      },
      {
        "added_at": "2022-03-29T21:02:02Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:b4keSn4ke/CVE-2019-9193.git"
      },
      {
        "added_at": "2020-02-12T00:17:58Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/wkjung0624/cve-2019-9193.git"
      },
      {
        "added_at": "2026-01-21T02:08:03Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:CybersRMUTL/CVE-2019-9193-Postgresql-RCE.git"
      },
      {
        "added_at": "2026-01-21T02:08:03Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/CybersRMUTL/CVE-2019-9193-Postgresql-RCE.git"
      },
      {
        "added_at": "2024-10-06T17:16:44Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:geniuszly/CVE-2019-9193.git"
      },
      {
        "added_at": "2022-11-13T04:28:55Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:chromanite/CVE-2019-9193-PostgreSQL-9.3-11.7.git"
      },
      {
        "added_at": "2026-06-12T12:48:15Z",
        "source": "metasploit",
        "url": "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/postgres/postgres_copy_from_program_cmd_exec.rb"
      },
      {
        "added_at": "2024-10-07T04:40:51Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/AxthonyV/CVE-2019-9193.git"
      },
      {
        "added_at": "2024-10-06T17:16:44Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/geniuszly/CVE-2019-9193.git"
      },
      {
        "added_at": "2023-02-01T16:41:15Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/paulotrindadec/CVE-2019-9193"
      },
      {
        "added_at": "2022-11-13T04:28:55Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/chromanite/CVE-2019-9193-PostgreSQL-9.3-11.7.git"
      },
      {
        "added_at": "2025-04-02T16:04:36Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/corsisechero/CVE-2019-9193byVulHub"
      },
      {
        "added_at": "2025-04-02T16:04:36Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/corsisechero/CVE-2019-9193byVulHub.git"
      },
      {
        "added_at": "2019-04-01T21:30:45Z",
        "source": "nvd",
        "url": "https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5"
      },
      {
        "added_at": "2026-01-21T02:08:03Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/CybersRMUTL/CVE-2019-9193-Postgresql-RCE"
      },
      {
        "added_at": "2025-12-01T02:49:00Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/Cheryanika/CVE-2019-9193---Postgresql---RCE"
      },
      {
        "added_at": "2025-12-01T02:49:00Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/Cheryanika/CVE-2019-9193---Postgresql---RCE.git"
      },
      {
        "added_at": "2025-03-20T17:46:42Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/jhnhnck/CVE-2019-9193"
      },
      {
        "added_at": "2025-04-02T16:04:36Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:corsisechero/CVE-2019-9193byVulHub.git"
      },
      {
        "added_at": "2024-10-07T11:28:34Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/A0be/CVE-2019-9193"
      },
      {
        "added_at": "2022-03-29T21:02:02Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/b4keSn4ke/CVE-2019-9193"
      },
      {
        "added_at": "2020-02-12T00:17:58Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/wkjung0624/cve-2019-9193"
      },
      {
        "added_at": "2024-10-07T11:28:34Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:A0be/CVE-2019-9193.git"
      },
      {
        "added_at": "2025-12-01T02:49:00Z",
        "source": "vulncheck-xdb",
        "url": "https///github.com:Cheryanika/CVE-2019-9193---Postgresql---RCE.git"
      },
      {
        "added_at": "2022-11-13T04:28:55Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/chromanite/CVE-2019-9193-PostgreSQL-9.3-11.7"
      },
      {
        "added_at": "2022-03-29T21:02:02Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/b4keSn4ke/CVE-2019-9193.git"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-05-27T02:30:43Z",
        "source": "nuclei_template",
        "url": "http://packetstormsecurity.com/files/152757/PostgreSQL-COPY-FROM-PROGRAM-Command-Execution.html"
      },
      {
        "added_at": "2025-05-27T02:30:43Z",
        "source": "nuclei_template",
        "url": "http://packetstormsecurity.com/files/171722/PostgreSQL-9.6.1-Remote-Code-Execution.html"
      },
      {
        "added_at": "2021-09-22T00:00:00Z",
        "source": "vulncheck",
        "url": "https://cujo.com/the-sysrv-botnet-and-how-it-evolved/"
      },
      {
        "added_at": "2024-11-21T04:51:10Z",
        "source": "nvd",
        "url": "https://paquier.xyz/postgresql-2/postgres-9-3-feature-highlight-copy-tofrom-program/"
      },
      {
        "added_at": "2025-05-27T02:30:43Z",
        "source": "nuclei_template",
        "url": "http://packetstormsecurity.com/files/166540/PostgreSQL-11.7-Remote-Code-Execution.html"
      },
      {
        "added_at": "2025-05-27T02:30:43Z",
        "source": "nuclei_template",
        "url": "https://blog.hagander.net/when-a-vulnerability-is-not-a-vulnerability-244/"
      },
      {
        "added_at": "2024-05-14T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.trustwave.com/hubfs/Web/Library/Documents_pdf/2024_Trustwave_Public_Sector_Threat_Landscape.pdf"
      },
      {
        "added_at": "2022-04-27T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.botconf.eu/wp-content/uploads/2022/05/Botconf2022-24-PalotayZsigovits.pdf"
      },
      {
        "added_at": "2021-01-22T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.zscaler.com/blogs/security-research/dreambus-botnet-technical-analysis"
      },
      {
        "added_at": "2024-11-21T04:51:10Z",
        "source": "nvd",
        "url": "https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5"
      },
      {
        "added_at": "2024-11-21T04:51:10Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20190502-0003/"
      },
      {
        "added_at": "2024-11-21T04:51:10Z",
        "source": "nvd",
        "url": "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/authenticated-arbitrary-command-execution-on-postgresql-9-3/"
      },
      {
        "added_at": "2026-06-03T07:20:39Z",
        "source": "nuclei_template",
        "url": "https://github.com/vulhub/vulhub/tree/master/postgres/CVE-2019-9193"
      }
    ],
    "cwe": [
      "CWE-78"
    ],
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit requires superuser or group membership.",
    "impact": "Attackers can execute arbitrary OS commands, potentially leading to full system compromise or data breach.",
    "name": "PostgreSQL - Command Injection",
    "remediation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue.",
    "requirement_type": "logged_in",
    "requirements": "Attacker must be a superuser or in the 'pg_execute_server_program' group",
    "severity": "high",
    "vulnerability_impact": [
      "remote_code_execution"
    ],
    "vulnerability_type": "command_injection",
    "weaknesses": [
      {
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
      }
    ],
    "category": "cve",
    "ref": "projectdiscovery/nuclei-templates:5d17f869ddde",
    "release_tag": "v9.8.1",
    "is_pdteam": true,
    "filename": "CVE-2019-9193.yaml",
    "uri": "javascript/cves/2019/CVE-2019-9193.yaml",
    "author": [
      "pussycat0x"
    ],
    "metadata": {
      "max-request": 1,
      "shodan-query": "product:\"PostgreSQL\"",
      "verified": true
    },
    "tags": [
      "cve",
      "cve2019",
      "js",
      "network",
      "postgresql",
      "intrusive",
      "vkev",
      "vuln"
    ],
    "type": "javascript",
    "id": "CVE-2019-9193",
    "affected_products": [
      {
        "category": "data_storage",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "postgresql",
        "summary": "postgresql postgresql is an open-source relational database management system that provides robust data storage and retrieval capabilities. It sits in the data_storage layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the data domain.",
        "tech_domain": "data",
        "vendor": "postgresql"
      }
    ],
    "created_at": "2019-04-01T21:30:45Z",
    "doc_id": "CVE-2019-9193",
    "doc_type": "cve_template",
    "exposure": {
      "max_hosts": 472289,
      "min_hosts": 472289
    },
    "h1": {
      "rank": 916,
      "reports": 5
    },
    "ntps": 69,
    "updated_at": "2026-06-12T12:48:45.956Z",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade postgresql - actively exploited in the wild"
  },
  {
    "cve_id": "CVE-2022-31197",
    "age_in_days": 1407,
    "assignee": "security-advisories@github.com",
    "cve_created_at": "2022-08-03T19:15:08Z",
    "cve_updated_at": "2025-11-03T22:15:58Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
    "cvss_score": 7.1,
    "epss_percentile": 0.85571,
    "epss_score": 0.02462,
    "is_auth": true,
    "is_kev": true,
    "is_oss": true,
    "is_patch_available": true,
    "is_poc": true,
    "is_remote": true,
    "is_vkev": true,
    "kev": [
      {
        "added_date": "2025-12-08T00:00:00Z",
        "source": "vulncheck"
      }
    ],
    "poc_count": 1,
    "poc_first_seen": "2022-08-03T19:15:08Z",
    "pocs": [
      {
        "added_at": "2022-08-03T19:15:08Z",
        "source": "nvd",
        "url": "https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-r38f-c4h4-hqq2"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2024-11-21T07:04:06Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/I6WHUADTZBBQLVHO4YG4XCWDGWBT4LRP/"
      },
      {
        "added_at": "2024-11-21T07:04:06Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UTFE6SV33P5YYU2GNTQZQKQRVR3GYE4S/"
      },
      {
        "added_at": "2025-11-03T22:15:58Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2024/12/msg00017.html"
      },
      {
        "added_at": "2025-12-08T00:00:00Z",
        "source": "vulncheck",
        "url": "https://www.f5.com/labs/articles/shellshock-makes-a-comeback-and-rondodox-changes-tactics"
      },
      {
        "added_at": "2024-11-21T07:04:06Z",
        "source": "nvd",
        "url": "https://github.com/pgjdbc/pgjdbc/commit/739e599d52ad80f8dcd6efedc6157859b1a9d637"
      },
      {
        "added_at": "2024-11-21T07:04:06Z",
        "source": "nvd",
        "url": "https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-r38f-c4h4-hqq2"
      },
      {
        "added_at": "2024-11-21T07:04:06Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2022/10/msg00009.html"
      }
    ],
    "cwe": [
      "CWE-89"
    ],
    "description": "PostgreSQL JDBC Driver versions before 42.2.26 and 42.4.1 contain a SQL injection caused by unescaped column names in the refreshRow() method, letting attackers execute arbitrary SQL commands if the application invokes this method and queries malicious schemas, exploit requires tricking the user into executing SQL on malicious schema.",
    "impact": "Attackers can execute arbitrary SQL commands as the JDBC user, potentially leading to data theft, modification, or privilege escalation.",
    "name": "PostgreSQL JDBC Driver - SQL Injection",
    "remediation": "Upgrade to version 42.2.26 or 42.4.1.",
    "requirement_type": "user_interaction",
    "requirements": "User application must invoke refreshRow() on a ResultSet with malicious column names",
    "severity": "high",
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
        "category": "operating_system",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "fedora",
        "summary": "fedoraproject fedora is a Linux-based open-source operating system that provides a robust and secure platform for developers and users. It sits in the operating_system layer of the tech stack, functions as a self-hosted system software in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "fedoraproject"
      },
      {
        "category": "application_library",
        "deployment_model": "dependency",
        "industry": "information_technology",
        "product": "postgresql_jdbc_driver",
        "summary": "postgresql postgresql_jdbc_driver is a database connectivity library that enables Java applications to interact with PostgreSQL databases. It sits in the application_library layer of the tech stack, functions as a dependency in the software supply chain, and—within the information_technology industry—serves the N/A domain.",
        "tech_domain": "N/A",
        "vendor": "postgresql"
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
    "created_at": "2022-08-03T19:15:08Z",
    "doc_id": "CVE-2022-31197",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 4038838,
      "min_hosts": 31320
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 64,
    "updated_at": "2026-06-11T15:07:58.614Z",
    "product": "postgresql",
    "pinned_version": "9.2.3-1.pgdg20.04+1",
    "affects_pinned_version": true,
    "recommendation": "URGENT: Upgrade postgresql - actively exploited in the wild"
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary

This report documents the ABAC policy mined from the Ansible configuration in `RLM_ANSIBLE_DIR`. The configuration manages a production environment with PCI compliance requirements.

## Environment Overview

- **Organization**: chaincorp
- **Environment**: production
- **Compliance Tier**: PCI
- **Log Retention**: 365 days

## Subjects (Users & Groups)

### Users (3)
| Name | UID | Groups | Department | Clearance |
|------|-----|--------|------------|-----------|
| admin | 1001 | sudo | operations | secret |
| developer | 1002 | developers | engineering | confidential |
| dba | 1003 | dba | data | secret |

### Groups (3)
- `sudo` - Administrative access
- `developers` - Application development
- `dba` - Database administration

### Clearance Levels
- `secret` - Highest clearance (admin, dba)
- `confidential` - Standard clearance (developer)

## Resources

### Hosts (4)
| Hostname | IP | Role | Zone |
|----------|-----|------|------|
| bastion01.lab.local | 10.0.0.5 | bastion | mgmt |
| web01.lab.local | 10.0.1.10 | frontend | dmz |
| app01.lab.local | 10.0.2.10 | application | app |
| db01.lab.local | 10.0.3.10 | primary | data |

### Services (4)
- SSH (port 22) - All hosts
- HTTP (port 80) - Webservers
- App (port 8080) - App servers
- PostgreSQL (port 5432) - Database servers

### Networks (5)
- 10.0.0.0/24 - Management (bastion subnet)
- 10.0.1.0/24 - DMZ (web subnet)
- 10.0.2.0/24 - Application subnet
- 10.0.3.0/24 - Data subnet
- 0.0.0.0/0 - Internet (bastion access)

## Access Rules Summary (12 rules)

### SSH Access Rules (4)
1. **rule-001**: Permit SSH to bastion for sudo/dba groups
2. **rule-002**: Permit SSH to webservers for sudo group
3. **rule-003**: Permit SSH to appservers for sudo/developers groups
4. **rule-004**: Permit SSH to dbservers for sudo/dba groups

### Privilege Escalation (1)
5. **rule-005**: Permit sudo on bastion for secret-clearance users in sudo group

### Database Access (1)
6. **rule-006**: Permit PostgreSQL SUPERUSER access for dba group

### Network Policies (4)
7. **rule-007**: Permit SSH to bastion from internet (0.0.0.0/0)
8. **rule-008**: Permit HTTP to webservers from bastion subnet (10.0.0.0/24)
9. **rule-009**: Permit app port to appservers from web subnet (10.0.1.0/24)
10. **rule-010**: Permit PostgreSQL from app subnet (10.0.2.0/24)

### Filesystem (1)
11. **rule-011**: Permit read access to /var/lib/postgresql/data for postgres user

### Default Deny (1)
12. **rule-012**: Deny all other access (default-deny)

## Vulnerability Assessment (35 vulnerabilities)

### Critical Findings by Product

#### OpenSSH (v1:9.1p1-1ubuntu1 on bastion)
- **10 vulnerabilities** found (5 critical remote, 5 KEV)
- Notable: CVE-2023-38408 (critical, KEV), CVE-2024-6387 (high, KEV)
- **Recommendation**: Upgrade OpenSSH immediately

#### Apache HTTPD (v2.4.49-1)
- **10 vulnerabilities** found (5 critical remote, 5 KEV)
- Notable: CVE-2021-44228 (Log4Shell, critical, KEV)
- **Recommendation**: Upgrade Apache and Log4j immediately

#### Log4j (v2.14.1)
- **8 vulnerabilities** found (4 critical remote, 4 KEV)
- Notable: CVE-2021-45046 (critical, KEV), CVE-2021-4104 (high, KEV)
- **Recommendation**: URGENT - Upgrade Log4j to patched version

#### PostgreSQL (v9.2.3-1.pgdg20.04+1)
- **8 vulnerabilities** found (5 critical remote, 3 KEV)
- Notable: CVE-2019-9193 (high, KEV), CVE-2022-31197 (high, KEV)
- **Recommendation**: Upgrade PostgreSQL to supported version

### Risk Summary
- **Total Critical**: 20+
- **Total KEV (Known Exploited)**: 17
- **Highest Risk**: Log4j and Apache (Log4Shell vulnerability)

## Ambiguities & Notes

1. **Credentials**: No explicit credential management found in configuration
2. **Session Logging**: No audit/logging obligations explicitly configured
3. **SELinux**: No SELinux policies found in configuration
4. **Package Versions**: All pinned versions are known vulnerable - immediate remediation required

## Compliance Considerations

- PCI compliance tier requires strict access controls
- Current configuration implements defense-in-depth with bastion host
- Network segmentation follows zone-based architecture (mgmt → dmz → app → data)
- SSH access is properly restricted by group membership
- Database access limited to dba group with SUPERUSER privileges

## Recommendations

1. **IMMEDIATE**: Upgrade all vulnerable packages (Log4j, Apache, OpenSSH, PostgreSQL)
2. **HIGH**: Implement session logging and audit trails
3. **MEDIUM**: Consider implementing SELinux policies
4. **LOW**: Review and document credential management procedures
