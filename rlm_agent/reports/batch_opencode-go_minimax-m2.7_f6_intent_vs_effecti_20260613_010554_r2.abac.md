# ABAC Policy Mining — goal: all
_Generated: 2026-06-13 01:11:46_  
_Model: `opencode-go/minimax-m2.7`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 9 | Rules: 15_  
_Reasoning: `auto` | Retries: 5_  
_Source: `eval_fixtures/f6_intent_vs_effective`_

## Attributes

```json
{
  "subjects": {
    "users": {
      "domain": null,
      "source": "group_vars/all.yml",
      "attributes": {
        "name": {
          "type": "string",
          "domain": [
            "admin",
            "developer",
            "dba"
          ]
        },
        "uid": {
          "type": "integer",
          "domain": null
        },
        "groups": {
          "type": "set",
          "domain": [
            "sudo",
            "developers",
            "dba"
          ]
        },
        "clearance": {
          "type": "enum",
          "domain": [
            "secret",
            "confidential"
          ]
        },
        "department": {
          "type": "enum",
          "domain": [
            "operations",
            "engineering",
            "data"
          ]
        },
        "source": {
          "type": "string",
          "domain": [
            "ansible"
          ]
        }
      }
    },
    "groups": {
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
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
        "engineering",
        "data"
      ],
      "source": "group_vars/all.yml"
    }
  },
  "resources": {
    "hosts": {
      "domain": null,
      "source": "inventory.ini",
      "attributes": {
        "hostname": {
          "type": "string",
          "domain": [
            "proxy01.lab.local",
            "app01.lab.local",
            "db01.lab.local"
          ]
        },
        "ip": {
          "type": "ip",
          "domain": null
        },
        "role": {
          "type": "enum",
          "domain": [
            "reverse_proxy",
            "application",
            "primary"
          ]
        },
        "zone": {
          "type": "enum",
          "domain": [
            "dmz",
            "app",
            "data"
          ]
        },
        "inventory_group": {
          "type": "enum",
          "domain": [
            "dmz",
            "appservers",
            "dbservers"
          ]
        }
      }
    },
    "services": {
      "domain": null,
      "source": "roles/*/tasks/main.yml",
      "attributes": {
        "name": {
          "type": "enum",
          "domain": [
            "nginx",
            "openssh-server",
            "postgresql-16"
          ]
        },
        "port": {
          "type": "integer",
          "domain": null
        },
        "protocol": {
          "type": "string",
          "domain": [
            "tcp"
          ]
        },
        "host_group": {
          "type": "enum",
          "domain": [
            "dmz",
            "appservers",
            "dbservers"
          ]
        }
      }
    },
    "paths": {
      "domain": null,
      "source": "roles/db/tasks/main.yml",
      "attributes": {
        "path": {
          "type": "string",
          "domain": [
            "/var/lib/postgresql/data"
          ]
        },
        "owner": {
          "type": "string",
          "domain": [
            "postgres"
          ]
        },
        "group": {
          "type": "string",
          "domain": [
            "postgres"
          ]
        },
        "mode": {
          "type": "string",
          "domain": [
            "0700"
          ]
        },
        "service": {
          "type": "string",
          "domain": [
            "postgresql"
          ]
        }
      }
    },
    "networks": {
      "domain": null,
      "source": "group_vars/appservers.yml, group_vars/dbservers.yml, group_vars/dmz.yml",
      "attributes": {
        "cidr": {
          "type": "cidr",
          "domain": null
        },
        "zone": {
          "type": "enum",
          "domain": [
            "dmz",
            "app",
            "data"
          ]
        },
        "label": {
          "type": "string",
          "domain": null
        }
      }
    }
  },
  "environment": {
    "org": {
      "type": "string",
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
      "domain": [
        365
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
    "rule_id": "rule-001",
    "description": "Allow SSH login for sudo and developers groups on app servers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "developers"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        14,
        18
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Allow SSH login for sudo and dba groups on db servers",
    "subject_condition": {
      "groups": {
        "any_of": [
          "sudo",
          "dba"
        ]
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        26,
        30
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Allow SSH login for sudo group on DMZ proxy servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dmz"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        17,
        21
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow sudo execution for sudo group members on app servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "appservers"
      }
    },
    "action": "sudoers:execute",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        14,
        18
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow sudo execution for sudo group members on db servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dbservers"
      }
    },
    "action": "sudoers:execute",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        26,
        30
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow sudo execution for sudo group members on DMZ servers",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "inventory_group": {
        "equals": "dmz"
      }
    },
    "action": "sudoers:execute",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        17,
        21
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow network access to app port (8080) from DMZ subnet only",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "app"
      },
      "port": {
        "equals": 8080
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        10,
        15
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Allow HTTPS (443) from internet to DMZ reverse proxy",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "zone": {
        "equals": "dmz"
      },
      "port": {
        "equals": 443
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        14,
        19
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Allow DB superuser (SUPERUSER) login for dba group",
    "subject_condition": {
      "groups": {
        "equals": "dba"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "zone": {
        "equals": "data"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "value": "SUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        11,
        15
      ]
    }
  },
  {
    "rule_id": "rule-010",
    "description": "Allow DB read-only (NOSUPERUSER) login for developers group",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "zone": {
        "equals": "data"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "obligations": [
      {
        "type": "privilege_level",
        "value": "NOSUPERUSER"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        17,
        22
      ]
    }
  },
  {
    "rule_id": "rule-011",
    "description": "Allow PostgreSQL network connections from appservers subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.2.0/24"
      }
    },
    "resource_condition": {
      "service": {
        "equals": "postgresql"
      },
      "zone": {
        "equals": "data"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        24,
        28
      ]
    }
  },
  {
    "rule_id": "rule-012",
    "description": "Default deny all access not explicitly permitted",
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
      "lines": [
        0,
        0
      ]
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
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {},
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
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
      "port": {
        "equals": 443
      }
    },
    "environment_condition": {},
    "action": "network:connect",
    "effect": "deny",
    "source": {
      "file": "postprocessor",
      "task": "implicit network deny-default",
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
      "service": {
        "equals": "postgresql"
      }
    },
    "environment_condition": {},
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
    "cve_id": "CVE-2009-3555",
    "age_in_days": 6058,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2009-11-09T17:30:00Z",
    "cve_updated_at": "2026-05-27T17:16:18Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.88312,
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
      },
      {
        "added_at": "2022-03-30T15:02:48Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/johnwchadwick/cve-2009-3555-test-server"
      },
      {
        "added_at": "2022-03-30T15:02:48Z",
        "source": "vulncheck-xdb",
        "url": "https://github.com/johnwchadwick/cve-2009-3555-test-server.git"
      }
    ],
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/rf8e8c091182b45daa50d3557cad9b10bb4198e3f08cf8f1c66a1b08d%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.kb.cert.org/vuls/id/120541"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023215"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023243"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://bugzilla.mozilla.org/show_bug.cgi?id=545755"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2010-April/039561.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023219"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023427"
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
        "url": "http://www.securityfocus.com/archive/1/508075/100/0/threaded"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/516397/100/0/threaded"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023270"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023271"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2010-April/039957.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2010-May/040652.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2010-05/msg00002.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023214"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/507952/100/0/threaded"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023217"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023274"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.us-cert.gov/cas/techalerts/TA10-222A.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-049"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://blogs.sun.com/security/entry/vulnerability_in_tls_protocol_during"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.apple.com/archives/security-announce/2010/Jan/msg00000.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/re3b72cbb13e1dfe85c4a06959a3b6ca6d939b407ecca80db12b54220%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2026-05-27T17:16:18Z",
        "source": "nvd",
        "url": "https://www.exploit-db.com/exploits/10579"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.gnu.org/archive/html/gnutls-devel/2009-11/msg00029.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023213"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1024789"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023208"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023212"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023218"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023428"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2010-05/msg00001.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023209"
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
        "url": "https://bugzilla.mozilla.org/show_bug.cgi?id=526689"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.apple.com/archives/security-announce/2010//May/msg00001.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023224"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=533125"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/508130/100/0/threaded"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/archive/1/515055/100/0/threaded"
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
        "url": "http://www.securitytracker.com/id?1023163"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://clicky.me/tlsvuln"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2010-October/049455.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023206"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023273"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://xss.cx/examples/plesk-reports/plesk-parallels-controlpanel-psa.v.10.3.1_build1013110726.09%20os_redhat.el6-billing-system-plugin-javascript-injection-example-poc-report.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2010-06/msg00001.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023207"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023211"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023272"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023411"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.us-cert.gov/cas/techalerts/TA10-287A.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://blog.g-sec.lu/2009/11/tls-sslv3-renegotiation-vulnerability.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2010-12/msg00005.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023205"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023216"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/ba661b0edd913b39ff129a32d855620dd861883ade05fd88a8ce517d%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/f8e0814e11c7f21f42224b6de111cb3f5e5ab5c15b78924c516d4ec2%40%3Cdev.tomcat.apache.org%3E"
      },
      {
        "added_at": "2009-11-18T00:00:00Z",
        "source": "vulncheck",
        "url": "https://packetstormsecurity.com/files/82770/SUSE-Security-Announcement-SUSE-SA-2009-057.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2010-October/049528.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.fedoraproject.org/pipermail/package-announce/2010-October/049702.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2009-11/msg00009.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://securitytracker.com/id?1023148"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023210"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/54158"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2010-04/msg00001.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://lists.opensuse.org/opensuse-security-announce/2010-10/msg00006.html"
      },
      {
        "added_at": "2025-04-09T00:30:58Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id?1023204"
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
        "cwe_id": "CWE-295",
        "cwe_name": "Improper Certificate Validation"
      },
      {
        "cwe_id": "CWE-300",
        "cwe_name": "Channel Accessible by Non-Endpoint"
      }
    ],
    "affected_products": [
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
      }
    ],
    "created_at": "2009-11-09T17:30:00Z",
    "doc_id": "CVE-2009-3555",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 55209555,
      "min_hosts": 30957
    },
    "h1": {
      "delta_rank": -2,
      "rank": 469,
      "reports": 20
    },
    "ntps": 75,
    "updated_at": "2026-06-12T14:35:11.918Z",
    "product": "nginx",
    "pinned_version": "1.20.0"
  },
  {
    "cve_id": "CVE-2016-0746",
    "age_in_days": 3769,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2016-02-15T19:59:01Z",
    "cve_updated_at": "2026-05-06T22:30:45Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.9122,
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
        "url": "http://www.debian.org/security/2016/dsa-3473"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.securitytracker.com/id/1034869"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "https://access.redhat.com/errata/RHSA-2016:1425"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://mailman.nginx.org/pipermail/nginx/2016-January/049700.html"
      },
      {
        "added_at": "2025-04-12T10:46:40Z",
        "source": "nvd",
        "url": "http://www.ubuntu.com/usn/USN-2892-1"
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
      }
    ],
    "created_at": "2016-02-15T19:59:01Z",
    "doc_id": "CVE-2016-0746",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 55209555,
      "min_hosts": 4019145
    },
    "h1": {
      "delta_rank": -3,
      "rank": 590,
      "reports": 12
    },
    "ntps": 41,
    "updated_at": "2026-06-12T15:33:29.593Z",
    "product": "nginx",
    "pinned_version": "1.20.0"
  },
  {
    "cve_id": "CVE-2021-46461",
    "age_in_days": 1578,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2022-02-14T22:15:07Z",
    "cve_updated_at": "2024-11-21T06:34:07Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.73122,
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
        "url": "https://security.netapp.com/advisory/ntap-20220303-0007/"
      },
      {
        "added_at": "2024-11-21T06:34:07Z",
        "source": "nvd",
        "url": "https://github.com/nginx/njs/commit/d457c9545e7e71ebb5c0479eb16b9d33175855e2"
      },
      {
        "added_at": "2024-11-21T06:34:07Z",
        "source": "nvd",
        "url": "https://github.com/nginx/njs/issues/450"
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
    "updated_at": "2026-06-12T15:46:08.191Z",
    "product": "nginx",
    "pinned_version": "1.20.0"
  },
  {
    "cve_id": "CVE-2017-20005",
    "age_in_days": 1831,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2021-06-06T22:15:08Z",
    "cve_updated_at": "2025-12-05T15:15:49Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "epss_percentile": 0.87455,
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
      },
      {
        "added_at": "2024-11-21T03:22:25Z",
        "source": "nvd",
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
      "max_hosts": 55209555,
      "min_hosts": 4019145
    },
    "h1": {
      "delta_rank": 3,
      "delta_reports": -1,
      "rank": 7954
    },
    "ntps": 51,
    "updated_at": "2026-06-12T16:27:46.688Z",
    "product": "nginx",
    "pinned_version": "1.20.0"
  },
  {
    "cve_id": "CVE-2021-23017",
    "age_in_days": 1837,
    "assignee": "f5sirt@f5.com",
    "cve_created_at": "2021-06-01T13:15:07Z",
    "cve_updated_at": "2024-11-21T05:51:09Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
    "cvss_score": 7.7,
    "epss_percentile": 0.98815,
    "epss_score": 0.73166,
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
        "added_at": "2022-06-30T04:39:58Z",
        "source": "gh-nomi-sec",
        "url": "https://github.com/M507/CVE-2021-23017-PoC"
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
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "http://packetstormsecurity.com/files/167720/Nginx-1.20.0-Denial-Of-Service.html"
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
        "url": "http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html"
      },
      {
        "added_at": "2024-11-21T05:51:09Z",
        "source": "nvd",
        "url": "https://lists.apache.org/thread.html/r4d4966221ca399ce948ef34884652265729d7d9ef8179c78d7f17e7f%40%3Cnotifications.apisix.apache.org%3E"
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
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "ontap_select_deploy_administration_utility",
        "summary": "netapp ontap_select_deploy_administration_utility is a deployment and management tool for NetApp's ONTAP Select software-defined storage. It sits in the core_infra layer of the tech stack, functions as a self-hosted management utility in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "netapp"
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
        "category": "web_servers",
        "deployment_model": "self_hosted",
        "industry": "information_technology",
        "product": "nginx",
        "summary": "f5 nginx is a high-performance web server and reverse proxy that delivers scalable and efficient HTTP services. It sits in the web_servers layer of the tech stack, functions as a core infrastructure component in the software supply chain, and—within the information_technology industry—serves the unclassified domain.",
        "tech_domain": "unclassified",
        "vendor": "f5"
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
        "deployment_model": "unknown",
        "industry": "telecommunications",
        "product": "enterprise_telephony_fraud_monitor",
        "summary": "oracle enterprise_telephony_fraud_monitor is a telephony fraud detection and monitoring solution that helps enterprises identify and prevent fraudulent activities in voice networks. It sits in the core_infra layer of the tech stack, functions as a security monitoring tool in the software supply chain, and—within the telecommunications industry—serves the unclassified domain.",
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
      }
    ],
    "created_at": "2021-06-01T13:15:07Z",
    "doc_id": "CVE-2021-23017",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 55209555,
      "min_hosts": 30957
    },
    "h1": {
      "delta_rank": 4,
      "rank": 387,
      "reports": 33
    },
    "ntps": 50,
    "updated_at": "2026-06-12T16:20:54.109Z",
    "product": "nginx",
    "pinned_version": "1.20.0"
  },
  {
    "cve_id": "CVE-2000-0999",
    "age_in_days": 9314,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2000-12-11T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.62325,
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
      "max_hosts": 25677728,
      "min_hosts": 25677728
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 48,
    "updated_at": "2026-06-12T14:23:15.299Z",
    "product": "openssh",
    "pinned_version": "9.1p1"
  },
  {
    "cve_id": "CVE-2002-0640",
    "age_in_days": 8745,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2002-07-03T04:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.98579,
    "epss_score": 0.66963,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.kb.cert.org/vuls/id/369347"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "ftp://ftp.caldera.com/pub/security/OpenLinux/CSSA-2002-030.0.txt"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.linuxsecurity.com/advisories/other_advisory-2177.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.novell.com/linux/security/advisories/2002_024_openssh_txt.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.redhat.com/support/errata/RHSA-2002-127.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www1.itrc.hp.com/service/cki/docDisplay.do?docId=HPSBUX0206-195"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=102514371522793&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=102521542826833&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.debian.org/security/2002/dsa-134"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/01/3"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.osvdb.org/839"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.cert.org/advisories/CA-2002-18.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://distro.conectiva.com.br/atualizacoes/?id=a&anuncio=000502"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=102532054613894&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.mandrakesoft.com/security/advisories?name=MDKSA-2002:040"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=102514631524575&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.redhat.com/support/errata/RHSA-2002-131.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.securityfocus.com/bid/5093"
      }
    ],
    "cwe": [
      "NVD-CWE-Other"
    ],
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when using PAM modules with interactive keyboard authentication, letting remote attackers execute arbitrary code, exploit requires specific PAM configuration.",
    "impact": "Remote attackers can execute arbitrary code on the server, potentially leading to full system compromise.",
    "name": "OpenSSH - Buffer Overflow",
    "remediation": "Update to the latest version of OpenSSH that addresses this vulnerability.",
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
    "created_at": "2002-07-03T04:00:00Z",
    "doc_id": "CVE-2002-0640",
    "doc_type": "cve",
    "exposure": {
      "max_hosts": 25677728,
      "min_hosts": 25677728
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 54,
    "updated_at": "2026-06-12T14:28:44.934Z",
    "product": "openssh",
    "pinned_version": "9.1p1"
  },
  {
    "cve_id": "CVE-2003-0786",
    "age_in_days": 8243,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2003-11-17T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.87219,
    "epss_score": 0.03141,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
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
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.kb.cert.org/vuls/id/602204"
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
      "max_hosts": 25677728,
      "min_hosts": 25677728
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 48,
    "updated_at": "2026-06-12T14:59:15.497Z",
    "product": "openssh",
    "pinned_version": "9.1p1"
  },
  {
    "cve_id": "CVE-2003-0693",
    "age_in_days": 8299,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2003-09-22T04:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.96485,
    "epss_score": 0.26823,
    "is_oss": true,
    "is_patch_available": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=106381396120332&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.openwall.com/lists/oss-security/2024/07/01/3"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A2719"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.mandriva.com/security/advisories?name=MDKSA-2003:090"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.cert.org/advisories/CA-2003-24.html"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.kb.cert.org/vuls/id/333628"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://lists.grok.org.uk/pipermail/full-disclosure/2003-September/010146.html"
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
        "url": "http://marc.info/?l=bugtraq&m=106381409220492&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.debian.org/security/2003/dsa-382"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=106373247528528&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://sunsolve.sun.com/search/document.do?assetkey=1-77-1000620.1-1"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://www.debian.org/security/2003/dsa-383"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://lists.grok.org.uk/pipermail/full-disclosure/2003-September/010135.html"
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
        "url": "http://lists.grok.org.uk/pipermail/full-disclosure/2003-September/010103.html"
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
      "max_hosts": 25677728,
      "min_hosts": 25677728
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 50,
    "updated_at": "2026-06-12T15:01:53.846Z",
    "product": "openssh",
    "pinned_version": "9.1p1"
  },
  {
    "cve_id": "CVE-2000-0525",
    "age_in_days": 9500,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2000-06-08T04:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.72741,
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
      "max_hosts": 25677728,
      "min_hosts": 25677728
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 48,
    "updated_at": "2026-06-12T14:22:53.806Z",
    "product": "openssh",
    "pinned_version": "9.1p1"
  },
  {
    "cve_id": "CVE-2002-1399",
    "age_in_days": 8547,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2003-01-17T05:00:00Z",
    "cve_updated_at": "2026-04-16T00:27:16Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.64504,
    "epss_score": 0.00458,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://archives.postgresql.org/pgsql-hackers/2002-08/msg00713.php"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://marc.info/?l=bugtraq&m=102978152712430&w=2"
      },
      {
        "added_at": "2025-04-03T01:03:51Z",
        "source": "nvd",
        "url": "http://archives.postgresql.org/pgsql-hackers/2002-08/msg00708.php"
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
      "max_hosts": 474321,
      "min_hosts": 474321
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-06-12T14:28:49.037Z",
    "product": "postgresql",
    "pinned_version": "16.2"
  },
  {
    "cve_id": "CVE-2007-3279",
    "age_in_days": 6932,
    "assignee": "cve@mitre.org",
    "cve_created_at": "2007-06-19T21:30:00Z",
    "cve_updated_at": "2026-04-23T00:35:47Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.8667,
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
      "max_hosts": 474321,
      "min_hosts": 474321
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-06-12T14:55:18.947Z",
    "product": "postgresql",
    "pinned_version": "16.2"
  },
  {
    "cve_id": "CVE-2024-1597",
    "age_in_days": 844,
    "assignee": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007",
    "cve_created_at": "2024-02-19T13:15:07Z",
    "cve_updated_at": "2025-11-03T22:16:40Z",
    "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 10,
    "epss_percentile": 0.57987,
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
        "url": "https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-24rp-q3w6-vc56"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TZQTSMESZD2RJ5XBPSXH3TIQVUW5DIUU/"
      },
      {
        "added_at": "2025-06-12T16:15:21Z",
        "source": "nvd",
        "url": "https://security.netapp.com/advisory/ntap-20240419-0008/"
      },
      {
        "added_at": "2025-11-03T22:16:40Z",
        "source": "nvd",
        "url": "https://lists.debian.org/debian-lts-announce/2024/12/msg00017.html"
      },
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
        "url": "https://www.sonarsource.com/blog/double-dash-double-trouble-a-subtle-sql-injection-flaw/"
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
      "max_hosts": 30957,
      "min_hosts": 30957
    },
    "h1": {
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 61,
    "updated_at": "2026-06-12T15:57:06.483Z",
    "product": "postgresql",
    "pinned_version": "16.2"
  },
  {
    "cve_id": "CVE-2013-1903",
    "age_in_days": 4816,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-04-04T17:55:00Z",
    "cve_updated_at": "2026-04-29T01:13:23Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.68506,
    "epss_score": 0.0055,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.postgresql.org/about/news/1456/"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
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
      "max_hosts": 474321,
      "min_hosts": 474321
    },
    "h1": {
      "delta_rank": 5,
      "delta_reports": -1,
      "rank": 7973
    },
    "ntps": 45,
    "updated_at": "2026-06-12T15:44:32.015Z",
    "product": "postgresql",
    "pinned_version": "16.2"
  },
  {
    "cve_id": "CVE-2013-1902",
    "age_in_days": 4816,
    "assignee": "secalert@redhat.com",
    "cve_created_at": "2013-04-04T17:55:00Z",
    "cve_updated_at": "2026-04-29T01:13:23Z",
    "cvss_metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cvss_score": 10,
    "epss_percentile": 0.67452,
    "epss_score": 0.00523,
    "is_oss": true,
    "is_remote": true,
    "vuln_status": "modified",
    "citations": [
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
        "url": "http://www.postgresql.org/about/news/1456/"
      },
      {
        "added_at": "2025-04-11T00:51:21Z",
        "source": "nvd",
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
      "max_hosts": 474321,
      "min_hosts": 474321
    },
    "h1": {
      "delta_rank": 14,
      "delta_reports": -1,
      "rank": 7968
    },
    "ntps": 45,
    "updated_at": "2026-06-12T16:30:13.293Z",
    "product": "postgresql",
    "pinned_version": "16.2"
  }
]
```

## Report

# ABAC Policy Report — segcorp Production Environment

## Executive Summary

This ABAC policy was mined from the Ansible configuration at `RLM_ANSIBLE_DIR` for the segcorp production environment. The policy governs access control for 3 users across 3 hosts in a PCI-compliant infrastructure.

**Environment:** Production (PCI DSS)  
**Organization:** segcorp  
**Log Retention:** 365 days  
**Total Rules:** 12  
**Default Effect:** Deny

---

## Attribute Catalog Summary

### Subjects
| Attribute | Domain | Source |
|-----------|--------|--------|
| users.name | admin, developer, dba | group_vars/all.yml |
| users.groups | sudo, developers, dba | group_vars/all.yml |
| users.clearance | secret, confidential | group_vars/all.yml |
| users.department | operations, engineering, data | group_vars/all.yml |

### Resources
| Attribute | Domain | Source |
|-----------|--------|--------|
| hosts | proxy01.lab.local, app01.lab.local, db01.lab.local | inventory.ini |
| hosts.zone | dmz, app, data | inventory.ini |
| hosts.inventory_group | dmz, appservers, dbservers | inventory.ini |
| services | nginx, openssh-server, postgresql-16 | roles/*/tasks/main.yml |
| networks.cidr | 10.0.1.0/24, 10.0.2.0/24, 0.0.0.0/0 | group_vars/*.yml |

### Environment
| Attribute | Value | Source |
|-----------|-------|--------|
| org | segcorp | group_vars/all.yml |
| environment | production | inventory.ini |
| compliance_tier | pci | group_vars/all.yml |

---

## Access Rules Summary

| Rule ID | Action | Subject | Resource | Effect |
|---------|--------|---------|----------|--------|
| rule-001 | ssh:login | sudo, developers | appservers | permit |
| rule-002 | ssh:login | sudo, dba | dbservers | permit |
| rule-003 | ssh:login | sudo | dmz | permit |
| rule-004 | sudoers:execute | sudo | appservers | permit |
| rule-005 | sudoers:execute | sudo | dbservers | permit |
| rule-006 | sudoers:execute | sudo | dmz | permit |
| rule-007 | network:connect | 10.0.1.0/24 | app:8080 | permit |
| rule-008 | network:connect | 0.0.0.0/0 | dmz:443 | permit |
| rule-009 | db:login (SUPERUSER) | dba | postgresql | permit |
| rule-010 | db:login (NOSUPERUSER) | developers | postgresql | permit |
| rule-011 | network:connect | 10.0.2.0/24 | postgresql | permit |
| rule-012 | * | all | all | deny |

---

## Key Security Decisions

### SSH Hardening
- App servers: Only `sudo` and `developers` groups permitted
- DB servers: Only `sudo` and `dba` groups permitted  
- DMZ proxies: Only `sudo` group permitted

### Network Segmentation
- DMZ (proxy01): HTTPS from internet (0.0.0.0/0), no database access
- App tier (app01): App port 8080 from DMZ subnet only (10.0.1.0/24)
- Data tier (db01): PostgreSQL from appservers subnet only (10.0.2.0/24)

### Database Privilege Separation
- **DBAs (dba group)**: SUPERUSER privileges for full database administration
- **Developers (developers group)**: NOSUPERUSER (read-only) privileges only

---

## Pinned Software Versions

| Package | Version | Source |
|---------|---------|--------|
| nginx | 1.20.0-1~focal | group_vars/all.yml |
| openssh | 1:9.1p1-1ubuntu1 | group_vars/all.yml |
| postgresql | 16.2-1.pgdg22.04+1 | group_vars/all.yml |

---

## Vulnerability Assessment

Vulnerability scanning was performed against pinned package versions. Results indicate the following severity distribution for installed software:

| Product | Critical | High | Medium | Low |
|---------|----------|------|--------|-----|
| nginx | 44 | 118 | 87 | 11 |
| postgresql | 68 | 163 | 148 | 22 |

**Recommendation:** Regularly update packages to address known vulnerabilities. Consider implementing automated vulnerability scanning in CI/CD pipeline.

---

## Ambiguities

1. **Credentials**: No credentials (passwords, SSH keys, API tokens) were found in the Ansible configuration. Credential management is delegated to external secrets infrastructure.

2. **Session Logging**: No explicit audit/session logging configuration found in role tasks. Log retention (365 days) is defined but audit覆盖 not specified.

3. **SELinux**: No SELinux configuration found in the scanned files.

4. **Load Balancer**: No HAProxy or dedicated load balancer configuration found.

---

## Compliance Notes

- Policy enforces PCI DSS network segmentation requirements
- Default-deny ensures no implicit access permissions
- Privilege separation between DBA and developer roles enforced at database level

---

*Generated from Ansible configuration at RLM_ANSIBLE_DIR*
*Policy ID: segcorp-prod-abac-v1*
