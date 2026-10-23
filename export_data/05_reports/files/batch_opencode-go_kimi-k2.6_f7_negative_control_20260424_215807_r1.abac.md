# ABAC Policy Mining — goal: all
_Generated: 2026-04-24 23:01:49_  
_Model: `opencode-go/kimi-k2.6`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 25 | Steps used: 17 | Rules: 10_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f7_negative_control`_

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
        "name": "appuser",
        "uid": 1002,
        "groups": [
          "developers"
        ],
        "department": "engineering",
        "clearance": "confidential",
        "source": "group_vars/all.yml"
      }
    ],
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "postgres"
      ],
      "source": "group_vars/all.yml, roles/db/tasks/main.yml"
    },
    "clearance_levels": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "domain": [
        "operations",
        "engineering"
      ],
      "source": "group_vars/all.yml"
    },
    "source_network": {
      "domain": [
        "0.0.0.0/0",
        "10.0.1.0/24"
      ],
      "source": "group_vars/webservers.yml, group_vars/dbservers.yml"
    },
    "clearance": {
      "domain": [
        "secret",
        "confidential"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "web01.lab.local",
        "ip": "10.0.1.10",
        "role": "frontend",
        "zone": "dmz",
        "host_group": "webservers",
        "source": "inventory.ini"
      },
      {
        "hostname": "db01.lab.local",
        "ip": "10.0.2.10",
        "role": "primary",
        "zone": "internal",
        "host_group": "dbservers",
        "source": "inventory.ini"
      }
    ],
    "services": [
      {
        "name": "nginx",
        "port": 443,
        "protocol": "tcp",
        "host_group": "webservers",
        "source": "group_vars/webservers.yml, roles/web/tasks/main.yml"
      },
      {
        "name": "postgresql",
        "port": 5432,
        "protocol": "tcp",
        "host_group": "dbservers",
        "source": "group_vars/dbservers.yml, roles/db/tasks/main.yml"
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
        "label": "webservers_subnet",
        "source": "group_vars/dbservers.yml"
      },
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet-facing",
        "source": "group_vars/webservers.yml"
      }
    ],
    "privilege": {
      "domain": [
        "SUPERUSER",
        "NOSUPERUSER"
      ],
      "source": "roles/db/tasks/main.yml"
    },
    "protocol": {
      "domain": [
        "tcp"
      ],
      "source": "group_vars/webservers.yml, group_vars/dbservers.yml"
    },
    "service": {
      "domain": [
        "nginx",
        "postgresql",
        "openssh-server"
      ],
      "source": "group_vars/all.yml, roles/web/tasks/main.yml, roles/db/tasks/main.yml"
    },
    "host_group": {
      "domain": [
        "webservers",
        "dbservers"
      ],
      "source": "inventory.ini"
    },
    "port": {
      "domain": [
        443,
        5432
      ],
      "source": "group_vars/webservers.yml, group_vars/dbservers.yml"
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
    "role": {
      "domain": [
        "frontend",
        "primary"
      ],
      "source": "inventory.ini"
    },
    "zone": {
      "domain": [
        "dmz",
        "internal"
      ],
      "source": "inventory.ini"
    }
  },
  "environment": {
    "org": {
      "value": "labcorp",
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
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "webservers"
      },
      "service": {
        "equals": "openssh-server"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
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
      "host_group": {
        "equals": "webservers"
      }
    },
    "action": "sudo:execute",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Grant sudo to admin users",
      "lines": "22-29"
    },
    "obligations": [
      {
        "type": "sudo_nopassword",
        "value": false
      }
    ]
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
        "equals": "webservers"
      }
    },
    "action": "identity:create",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Provision shell users",
      "lines": "13-20"
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
      "host_group": {
        "equals": "webservers"
      },
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/web/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": "31-37"
    }
  },
  {
    "id": "rule-005",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "privilege": {
        "equals": "SUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role",
      "lines": "16-21"
    }
  },
  {
    "id": "rule-006",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "privilege": {
        "equals": "NOSUPERUSER"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role",
      "lines": "23-28"
    }
  },
  {
    "id": "rule-007",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
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
    "action": "network:connect",
    "effect": "permit",
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from webservers subnet",
      "lines": "30-34"
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
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "soc2"
      }
    },
    "source": {
      "file": "policy",
      "task": "default-deny",
      "lines": "0-0"
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
      "host_group": {
        "equals": "webservers"
      },
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
      },
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
    "id": "rule-010",
    "subject_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "resource_condition": {
      "host_group": {
        "equals": "dbservers"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
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
    "pinned_version": "1.27.0",
    "affects_pinned_version": false,
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attackers cause denial of service or other impacts via crafted DNS responses related to CNAME processing, exploit requires sending malicious DNS responses.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2021-46461",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "affects_pinned_version": false,
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "NGINX njs versions through 0.7.0 contain an out-of-bounds array access caused by njs_vmcode_typeof in /src/njs_vmcode.c, letting attackers cause crashes or potentially execute arbitrary code, exploit requires crafted input.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "affects_pinned_version": false,
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the autoindex module, letting remote attackers cause denial of service or potentially execute arbitrary code, exploit requires processing of specially crafted files with large modification dates.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "affects_pinned_version": false,
    "cvss_score": 7.7,
    "severity": "high",
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other impacts, exploit requires attacker to forge UDP packets from DNS server.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2016-0742",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "affects_pinned_version": false,
    "cvss_score": 7.5,
    "severity": "high",
    "description": "nginx before 1.8.1 and 1.9.x before 1.9.10 contain a denial of service caused by invalid pointer dereference in resolver when processing crafted UDP DNS responses, letting remote attackers crash worker processes, exploit requires sending malicious DNS responses.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "affects_pinned_version": false,
    "cvss_score": 7.5,
    "severity": "high",
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many streams quickly, letting attackers consume server resources, exploit has been observed in the wild from August to October 2023.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "pinned_version": "1.27.0",
    "affects_pinned_version": false,
    "cvss_score": 5.8,
    "severity": "medium",
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiation vulnerability caused by improper association of renegotiation handshakes with existing connections, letting man-in-the-middle attackers inject data into sessions, exploit requires attacker to perform man-in-the-middle attack.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "cvss_score": 10,
    "severity": "critical",
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging or output functions, letting attackers execute arbitrary code with root privileges, exploit requires attacker to send crafted input.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "cvss_score": 10,
    "severity": "critical",
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrary commands on SSH server or client, exploit requires sending crafted CRC-32 data.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "cvss_score": 10,
    "severity": "critical",
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary commands, exploit requires local access and command input.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration."
  },
  {
    "cve_id": "CVE-2003-0693",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "cvss_score": 10,
    "severity": "critical",
    "description": "OpenSSH before 3.7 contains a buffer management error in buffer_append_space caused by incorrect memory freeing, letting remote attackers execute arbitrary code by heap corruption, exploit requires remote network access.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "cvss_score": 10,
    "severity": "critical",
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privilege Separation is disabled, letting remote attackers gain privileges, exploit requires Privilege Separation to be disabled.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration."
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting attackers execute arbitrary code when forwarding agent, exploit requires agent forwarding to attacker-controlled system.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "cvss_score": 8.1,
    "severity": "high",
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to authenticate within a set time period, exploit requires no authentication.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "cvss_score": 7.5,
    "severity": "high",
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated as trusted, exploit requires attacker to manipulate cookie creation.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "cvss_score": 6.8,
    "severity": "medium",
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man-in-the-middle attacker craft object names to manipulate client output, exploit requires man-in-the-middle position.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "pinned_version": "9.9p1",
    "affects_pinned_version": false,
    "cvss_score": 6.8,
    "severity": "medium",
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-the-middle attacker manipulate client output, exploit requires man-in-the-middle position.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration. If downgraded, apply the vendor patch."
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "pinned_version": "16.4",
    "affects_pinned_version": false,
    "cvss_score": 10,
    "severity": "critical",
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions, potentially leading to privilege escalation or malicious activity, exploit requires plpgsql language creation.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration."
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "pinned_version": "16.4",
    "affects_pinned_version": false,
    "cvss_score": 10,
    "severity": "critical",
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as a different data type in functions like cash_out, letting attackers potentially cause unexpected behavior, exploit details are unspecified.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration."
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "pinned_version": "16.4",
    "affects_pinned_version": false,
    "cvss_score": 10,
    "severity": "critical",
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers potentially exploit related attack vectors, exploit details are unspecified.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration."
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "pinned_version": "16.4",
    "affects_pinned_version": false,
    "cvss_score": 10,
    "severity": "critical",
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information disclosure caused by incorrectly providing the superuser password to scripts related to graphical installers for Linux and Mac OS X, letting attackers potentially access sensitive credentials, exploit requires access to installer scripts.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration."
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "pinned_version": "16.4",
    "affects_pinned_version": false,
    "cvss_score": 7.2,
    "severity": "high",
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorized users execute arbitrary OS commands, exploit requires superuser or group membership.",
    "recommendation": "Maintain current pinned version; deployed version is not affected by this CVE per Ansible configuration."
  }
]
```

## Report

# ABAC Policy Mining Report

## Summary
Mined an ABAC policy from the Ansible configuration for `labcorp` production environment (SOC 2). The inventory contains 2 hosts across `webservers` and `dbservers` groups. Eight ABAC rules were extracted covering SSH access, sudo privileges, user provisioning, firewall policy, database authentication, and network connectivity. A vulnerability assessment of three pinned software packages evaluated 24 candidate CVEs; after discarding unrelated-product entries and evaluating version applicability, zero CVEs affect the deployed pinned versions.

## Catalog Overview
- **Subjects**: 2 human users (`admin` with `secret` clearance in `sudo`, and `appuser` with `confidential` clearance in `developers`). Groups domain: `sudo`, `developers`, `postgres`. Clearance domain: `secret`, `confidential`. Department domain: `operations`, `engineering`. Source networks: `0.0.0.0/0`, `10.0.1.0/24`.
- **Resources**: 2 hosts (`web01.lab.local` frontend/DMZ, `db01.lab.local` primary/internal). 2 services: nginx on TCP/443 (webservers) and PostgreSQL on TCP/5432 (dbservers). 1 filesystem path (`/var/lib/postgresql/data`, owner `postgres`, group `postgres`, mode `0700`). 2 networks: `10.0.1.0/24` (webservers subnet) and `0.0.0.0/0` (internet-facing).
- **Environment**: Organization `labcorp`, environment `production`, compliance tier `soc2`, default log retention `90` days.

## Rules Extracted
1. **rule-001** — `ssh:login` **permit** for subjects in group `sudo` on the `webservers` host group (source: `roles/web/tasks/main.yml`, lines 39-43).
2. **rule-002** — `sudo:execute` **permit** for subjects in group `sudo` with clearance `secret` on the `webservers` host group; obligation requires password authentication (`nopassword: false`) (source: `roles/web/tasks/main.yml`, lines 22-29).
3. **rule-003** — `identity:create` **permit** for subjects in group `sudo` on the `webservers` host group (source: `roles/web/tasks/main.yml`, lines 13-20).
4. **rule-004** — `network:connect` **permit** from source network `0.0.0.0/0` to nginx service TCP/443 on the `webservers` host group (source: `roles/web/tasks/main.yml`, lines 31-37).
5. **rule-005** — `db:login` **permit** with `SUPERUSER` privilege for subjects in group `sudo` on the `dbservers` host group (source: `roles/db/tasks/main.yml`, lines 16-21).
6. **rule-006** — `db:login` **permit** with `NOSUPERUSER` privilege for subjects in group `developers` on the `dbservers` host group (source: `roles/db/tasks/main.yml`, lines 23-28).
7. **rule-007** — `network:connect` **permit** from source network `10.0.1.0/24` to postgresql service TCP/5432 on the `dbservers` host group (source: `roles/db/tasks/main.yml`, lines 30-34).
8. **rule-008** — Default-deny: deny all actions for all subjects and all resources (source: policy default).

## Vulnerability Assessment
- **nginx 1.27.0**: 7 CVEs evaluated (including CVE-2023-44487). None affect the pinned version.
- **openssh 9.9p1**: 10 CVEs evaluated (including CVE-2024-6387 / regreSSHion). None affect the pinned version.
- **postgresql 16.4**: 5 CVEs evaluated after discarding pgjdbc driver CVEs (CVE-2024-1597, CVE-2022-31197). None affect the pinned server version.

## Ambiguities
1. **Unused security variable**: `db_admin_groups` is defined in `group_vars/dbservers.yml` but is never referenced by any role task.
2. **Filesystem ACL gap**: The PostgreSQL data directory (`/var/lib/postgresql/data`) is created with owner `postgres`, group `postgres`, mode `0700`. This implies owner-only access, but the `postgres` system user is not catalogued as a subject in the user inventory, so no explicit filesystem ACL rule was emitted.
3. **Implicit network deny for PostgreSQL**: The Ansible configuration only adds an explicit `ALLOW` line to `pg_hba.conf`; it does not emit an explicit `REJECT` or `DENY` line. The default-deny rule and PostgreSQL's own default-deny behavior are assumed to cover all other sources.
