# ABAC Policy Mining — goal: all
_Generated: 2026-06-12 18:41:45_  
_Model: `opencode-go/qwen3.6-plus`_  
_Interpreter: `local`_  
_Max tokens: 64000 | Max iterations: 35 | Steps used: 14 | Rules: 14_  
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
      },
      {
        "name": "postgres",
        "uid": null,
        "groups": [],
        "clearance": null,
        "department": null,
        "source": "roles/db/tasks/main.yml",
        "type": "system"
      }
    ],
    "groups": {
      "values": [
        "sudo",
        "developers",
        "dba"
      ],
      "domain": [
        "sudo",
        "developers",
        "dba"
      ],
      "source": "group_vars/all.yml"
    },
    "clearance_levels": {
      "values": [
        "secret",
        "confidential"
      ],
      "domain": [
        "secret",
        "confidential",
        "top_secret",
        "unclassified"
      ],
      "source": "group_vars/all.yml"
    },
    "departments": {
      "values": [
        "operations",
        "engineering",
        "data"
      ],
      "domain": [
        "operations",
        "engineering",
        "data",
        "security",
        "finance"
      ],
      "source": "group_vars/all.yml"
    },
    "source_networks": {
      "values": [
        "10.0.1.0/24",
        "10.0.2.0/24",
        "0.0.0.0/0"
      ],
      "source": "group_vars/*.yml"
    }
  },
  "resources": {
    "hosts": [
      {
        "hostname": "proxy01.lab.local",
        "ip": "10.0.1.10",
        "role": "reverse_proxy",
        "zone": "dmz",
        "inventory_group": "dmz",
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
        "name": "https",
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
    "paths": [
      {
        "path": "/var/lib/postgresql/data",
        "owner": "postgres",
        "group": "postgres",
        "mode": "0700",
        "service": "postgresql",
        "source": "roles/db/tasks/main.yml"
      },
      {
        "path": "/etc/ssh/sshd_config",
        "owner": "root",
        "group": "root",
        "mode": "0600",
        "service": "openssh",
        "source": "roles/app/tasks/main.yml"
      }
    ],
    "networks": [
      {
        "cidr": "0.0.0.0/0",
        "zone": "internet",
        "label": "internet",
        "source": "group_vars/dmz.yml"
      },
      {
        "cidr": "10.0.1.0/24",
        "zone": "dmz",
        "label": "dmz_subnet",
        "source": "group_vars/appservers.yml"
      },
      {
        "cidr": "10.0.2.0/24",
        "zone": "app",
        "label": "appservers_subnet",
        "source": "group_vars/dbservers.yml"
      }
    ]
  },
  "environment": {
    "org": "segcorp",
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
    "rule_id": "rule-001",
    "description": "Allow SSH login on appservers for sudo and developers groups",
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
      "zone": {
        "equals": "app"
      },
      "role": {
        "equals": "application"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Restrict SSH to approved groups",
      "lines": [
        24,
        28
      ]
    }
  },
  {
    "rule_id": "rule-002",
    "description": "Allow SSH login on dbservers for sudo and dba groups",
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
      "zone": {
        "equals": "data"
      },
      "role": {
        "equals": "primary"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        48,
        52
      ]
    }
  },
  {
    "rule_id": "rule-003",
    "description": "Allow SSH login on dmz for sudo group only",
    "subject_condition": {
      "groups": {
        "equals": "sudo"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "zone": {
        "equals": "dmz"
      },
      "role": {
        "equals": "reverse_proxy"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "ssh:login",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Restrict SSH to sudo group",
      "lines": [
        32,
        36
      ]
    }
  },
  {
    "rule_id": "rule-004",
    "description": "Allow network connection to app port 8080 from DMZ subnet",
    "subject_condition": {
      "source_network": {
        "equals": "10.0.1.0/24"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "app01.lab.local"
      },
      "port": {
        "equals": 8080
      },
      "zone": {
        "equals": "app"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/app/tasks/main.yml",
      "task": "Firewall — allow app port from DMZ only",
      "lines": [
        16,
        22
      ]
    }
  },
  {
    "rule_id": "rule-005",
    "description": "Allow network connection to HTTPS port 443 from internet",
    "subject_condition": {
      "source_network": {
        "equals": "0.0.0.0/0"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "proxy01.lab.local"
      },
      "port": {
        "equals": 443
      },
      "zone": {
        "equals": "dmz"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/dmz/tasks/main.yml",
      "task": "Firewall — allow HTTPS from internet",
      "lines": [
        24,
        30
      ]
    }
  },
  {
    "rule_id": "rule-006",
    "description": "Allow PostgreSQL superuser login for dba group users",
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
      },
      "port": {
        "equals": 5432
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB superuser role for DBAs",
      "lines": [
        23,
        30
      ]
    }
  },
  {
    "rule_id": "rule-007",
    "description": "Allow PostgreSQL NOSUPERUSER login for developers group users",
    "subject_condition": {
      "groups": {
        "equals": "developers"
      }
    },
    "resource_condition": {
      "hostname": {
        "equals": "db01.lab.local"
      },
      "service": {
        "equals": "postgresql"
      },
      "port": {
        "equals": 5432
      },
      "database": {
        "equals": "all"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "db:login",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Create DB read-only role for developers",
      "lines": [
        32,
        39
      ]
    }
  },
  {
    "rule_id": "rule-008",
    "description": "Allow PostgreSQL network connection from appservers subnet via pg_hba",
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
      "port": {
        "equals": 5432
      },
      "zone": {
        "equals": "data"
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "network:connect",
    "effect": "permit",
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Allow postgres only from appservers subnet",
      "lines": [
        41,
        46
      ]
    }
  },
  {
    "rule_id": "rule-009",
    "description": "Postgres data directory restricted to postgres system user (owner-only, mode 0700)",
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
      },
      "compliance_tier": {
        "equals": "pci"
      }
    },
    "action": "filesystem:read",
    "effect": "permit",
    "obligations": [
      {
        "type": "audit",
        "description": "File permissions enforced by Ansible file module (mode 0700, owner postgres)"
      }
    ],
    "source": {
      "file": "roles/db/tasks/main.yml",
      "task": "Ensure postgres data dir",
      "lines": [
        15,
        21
      ]
    }
  },
  {
    "rule_id": "rule-010",
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
    "environment_condition": {
      "applies_to": {
        "equals": "all"
      }
    },
    "action": "*",
    "effect": "deny",
    "source": {
      "file": "policy-default",
      "task": "implicit default deny",
      "lines": [
        1,
        1
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
      },
      "compliance_tier": {
        "equals": "pci"
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
      "port": {
        "equals": 8080
      }
    },
    "environment_condition": {
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
    "id": "rule-003",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
    "id": "rule-004",
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
      "environment": {
        "equals": "production"
      },
      "compliance_tier": {
        "equals": "pci"
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
    "cvss_score": 9.8,
    "description": "nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 contain a use-after-free caused by improper DNS response handling in resolver, letting remote attac",
    "remediation": "Update to nginx 1.9.10 or later versions.",
    "is_remote": true,
    "is_kev": false,
    "affected_products": [
      "debian_linux",
      "leap",
      "xcode",
      "nginx",
      "ubuntu_linux"
    ]
  },
  {
    "cve_id": "CVE-2017-20005",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "NGINX before 1.13.6 contains a buffer overflow caused by an integer overflow when processing modification dates with more than four digits in the auto",
    "remediation": "Update to version 1.13.6 or later.",
    "is_remote": true,
    "is_kev": false,
    "affected_products": [
      "nginx",
      "debian_linux"
    ]
  },
  {
    "cve_id": "CVE-2009-3555",
    "product": "nginx",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Multiple products including IIS 7.0, Apache 2.2.14, OpenSSL before 0.9.8l, GnuTLS 2.8.5, NSS 3.12.4, and Cisco products contain a TLS/SSL renegotiatio",
    "remediation": "Update to the latest versions of affected products that fix the renegotiation handling issue.",
    "is_remote": true,
    "is_kev": true,
    "affected_products": [
      "gnutls",
      "nss",
      "openssl",
      "ubuntu_linux",
      "debian_linux",
      "fedora",
      "nginx",
      "http_server"
    ]
  },
  {
    "cve_id": "CVE-2021-23017",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.7,
    "description": "nginx resolver contains a 1-byte memory overwrite caused by forged UDP packets from DNS server, letting attackers cause worker process crash or other ",
    "remediation": "Update nginx to the latest version where this issue is fixed.",
    "is_remote": true,
    "is_kev": false,
    "affected_products": [
      "communications_session_border_controller",
      "enterprise_communications_broker",
      "blockchain_platform",
      "communications_fraud_monitor",
      "enterprise_session_border_controller",
      "enterprise_telephony_fraud_monitor",
      "goldengate",
      "nginx",
      "openresty",
      "fedora",
      "ontap_select_deploy_administration_utility",
      "communications_control_plane_monitor",
      "communications_operations_monitor"
    ]
  },
  {
    "cve_id": "CVE-2023-44487",
    "product": "nginx",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "The HTTP/2 protocol contains a denial of service caused by request cancellation that can reset many streams quickly, letting attackers consume server ",
    "remediation": "Implement rate limiting and update to the latest HTTP/2 protocol standards or patches.",
    "is_remote": true,
    "is_kev": true,
    "affected_products": [
      "varnish_cache",
      "jboss_a-mq_streams",
      "jboss_core_services",
      "windows_11_21h2",
      "jboss_data_grid",
      "prime_access_registrar",
      "node.js",
      "big-ip_global_traffic_manager",
      "big-ip_next_service_proxy_for_kubernetes",
      "certification_for_red_hat_enterprise_linux",
      "cryostat",
      "openshift_data_science",
      "run_once_duration_override_operator",
      "self_node_remediation_operator",
      "azure_kubernetes_service",
      "contour",
      "support_for_spring_boot",
      "oncommand_insight",
      "http_server",
      "crosswork_data_gateway",
      "expressway",
      "unified_contact_center_domain_manager",
      "siplus_s7-1500_cpu_1518-4_pn\\/dp_mfp_firmware",
      "windows_server_2019",
      "ultra_cloud_core_-_session_management_function",
      "ios_xr",
      "windows_10_21h2",
      "http2",
      "integration_camel_for_spring_boot",
      "jboss_enterprise_application_platform",
      "logging_subsystem_for_red_hat_openshift",
      "service_interconnect",
      "jenkins",
      "solr",
      "big-ip_access_policy_manager",
      "migration_toolkit_for_applications",
      "migration_toolkit_for_containers",
      "node_healthcheck_operator",
      "prime_cable_provisioning",
      "ios_xe",
      "http",
      "migration_toolkit_for_virtualization",
      "openshift_sandboxed_containers",
      "build_of_optaplanner",
      "openshift_pipelines",
      "big-ip_domain_name_system",
      "armeria",
      "enterprise_chat_and_email",
      "unified_contact_center_enterprise_-_live_data_server",
      "linkerd",
      "openshift_api_for_data_protection",
      "openshift_virtualization",
      "satellite",
      "st7_scadaconnect",
      "go",
      "nginx",
      "swiftnio_http\\/2",
      ".net",
      "integration_service_registry",
      "unified_contact_center_management_portal",
      "netty",
      "big-ip_application_visibility_and_reporting",
      "big-ip_websafe",
      "debian_linux",
      "ceph_storage",
      "network_observability_operator",
      "openshift_dev_spaces",
      "process_automation",
      "sinec_ins",
      "big-ip_webaccelerator",
      "opensearch_data_prepper",
      "machine_deletion_remediation_operator",
      "openshift_gitops",
      "connected_mobile_experiences",
      "telepresence_video_communication_server",
      "nx-os",
      "nghttp2",
      "envoy",
      "ansible_automation_platform",
      "jboss_a-mq",
      "openresty",
      "nginx_plus",
      "asp.net_core",
      "windows_10_22h2",
      "traefik",
      "3scale_api_management_platform",
      "jboss_fuse",
      "openshift_serverless",
      "secure_dynamic_attributes_connector",
      "openshift_distributed_tracing",
      "big-ip_carrier-grade_nat",
      "big-ip_link_controller",
      "cert-manager_operator_for_red_hat_openshift",
      "openshift_developer_tools_and_services",
      "sinec_nms",
      "istio",
      "data_center_network_manager",
      "big-ip_fraud_protection_service",
      "big-ip_local_traffic_manager",
      "tomcat",
      "build_of_quarkus",
      "openshift_secondary_scheduler_operator",
      "visual_studio_2022",
      "windows_10_1607",
      "cbl-mariner",
      "firepower_threat_defense",
      "prime_network_registrar",
      "big-ip_advanced_web_application_firewall",
      "big-ip_application_acceleration_manager",
      "big-ip_application_security_manager",
      "big-ip_ddos_hybrid_defender",
      "cost_management",
      "openshift_container_platform",
      "secure_malware_analytics",
      "openstack_platform",
      "single_sign-on",
      "kong_gateway",
      "big-ip_ssl_orchestrator",
      "nginx_ingress_controller",
      "integration_camel_k",
      "big-ip_analytics",
      "h2o",
      "crosswork_situation_manager",
      "ruggedcom_ape1808_firmware",
      "simatic_s7-1500_cpu_1518-4_pn\\/dp_mfp_firmware",
      "networking",
      "big-ip_next",
      "windows_server_2016",
      "advanced_cluster_security",
      "enterprise_linux",
      "service_telemetry_framework",
      "windows_11_22h2",
      "traffic_server",
      "decision_manager",
      "openshift_service_mesh",
      "web_terminal",
      "prime_infrastructure",
      "ultra_cloud_core_-_serving_gateway_function",
      "unified_contact_center_enterprise",
      "windows_server_2022",
      "windows_10_1809",
      "openshift",
      "fedora",
      "ultra_cloud_core_-_policy_control_function",
      "caddy",
      "http2",
      "big-ip_advanced_firewall_manager",
      "big-ip_policy_enforcement_manager",
      "apisix",
      "fence_agents_remediation_operator",
      "fog_director",
      "secure_web_appliance_firmware",
      "grpc",
      "node_maintenance_operator",
      "openshift_container_platform_assisted_installer",
      "quay",
      "astra_control_center",
      "crosswork_zero_touch_provisioning",
      "iot_field_network_director",
      "unified_attendant_console_advanced",
      "jetty",
      "proxygen",
      "business_process_automation",
      "simatic_s7-1500_cpu_1518f-4_pn\\/dp_mfp_firmware",
      "advanced_cluster_management_for_kubernetes"
    ]
  },
  {
    "cve_id": "CVE-2000-0525",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH with UseLogin enabled contains a privilege dropping issue caused by improper privilege management, letting local users execute arbitrary comma",
    "remediation": "Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option.",
    "is_remote": true,
    "is_kev": false,
    "affected_products": [
      "openssh"
    ]
  },
  {
    "cve_id": "CVE-2001-0144",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "CORE SDI SSH1 CRC-32 compensation attack detector contains an integer overflow caused by CRC-32 calculation, letting remote attackers execute arbitrar",
    "remediation": "Update to the latest version or apply security patches addressing the integer overflow issue.",
    "is_remote": true,
    "is_kev": false,
    "affected_products": [
      "openssh",
      "ssh"
    ]
  },
  {
    "cve_id": "CVE-2000-0999",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenBSD ssh and possibly other BSD-based operating systems contain format string vulnerabilities caused by improper handling of user input in logging ",
    "remediation": "Update to the latest version of OpenBSD or apply security patches addressing format string issues.",
    "is_remote": true,
    "is_kev": false,
    "affected_products": [
      "openssh"
    ]
  },
  {
    "cve_id": "CVE-2002-0640",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH 2.3.1 through 3.3 contains a buffer overflow caused by handling a large number of responses during challenge response authentication when usin",
    "remediation": "Update to the latest version of OpenSSH that addresses this vulnerability.",
    "is_remote": true,
    "is_kev": false,
    "affected_products": [
      "openssh"
    ]
  },
  {
    "cve_id": "CVE-2003-0786",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 10,
    "description": "OpenSSH 3.7.1 and 3.7.1p1 contain a privilege escalation caused by not checking the result of SSH1 PAM challenge response authentication when Privileg",
    "remediation": "Update to a version where this issue is fixed, or enable Privilege Separation.",
    "is_remote": true,
    "is_kev": false,
    "affected_products": [
      "openssh"
    ]
  },
  {
    "cve_id": "CVE-2023-38408",
    "product": "openssh",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "OpenSSH before 9.3p2 contains a remote code execution caused by an insufficiently trustworthy search path in the PKCS#11 feature of ssh-agent, letting",
    "remediation": "Update to OpenSSH 9.3p2 or later.",
    "is_remote": true,
    "is_kev": true,
    "affected_products": [
      "openssh",
      "fedora"
    ]
  },
  {
    "cve_id": "CVE-2024-6387",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 8.1,
    "description": "OpenSSH's server (sshd) contains a race condition caused by unsafe signal handling, letting unauthenticated remote attackers trigger it by failing to ",
    "remediation": "Update to the latest version of OpenSSH where this regression is fixed.",
    "is_remote": true,
    "is_kev": true,
    "affected_products": [
      "ubuntu_linux",
      "sma_6210_firmware",
      "sma_8200v_firmware",
      "a70_firmware",
      "a700s_firmware",
      "a150_firmware",
      "a220_firmware",
      "enterprise_linux",
      "sma_7200_firmware",
      "eos",
      "almalinux",
      "sma_7210_firmware",
      "8300_firmware",
      "a250_firmware",
      "a800_firmware",
      "fas2720_firmware",
      "sma_6200_firmware",
      "c800_firmware",
      "fas2750_firmware",
      "bootstrap_os",
      "macos",
      "enterprise_linux_for_arm_64",
      "enterprise_linux_for_ibm_z_systems",
      "enterprise_linux_for_power_little_endian",
      "a90_firmware",
      "500f_firmware",
      "a900_firmware",
      "c190_firmware",
      "openssh",
      "enterprise_linux_eus",
      "enterprise_linux_for_arm_64_eus",
      "enterprise_linux_for_ibm_z_systems_eus",
      "enterprise_linux_for_power_little_endian_eus",
      "enterprise_linux_server_aus",
      "ontap",
      "ontap_select_deploy_administration_utility",
      "freebsd",
      "netbsd",
      "sra_ex_7000_firmware",
      "a1k_firmware",
      "8700_firmware",
      "c400_firmware",
      "a9500_firmware",
      "openshift_container_platform",
      "debian_linux",
      "amazon_linux",
      "ontap_tools",
      "a400_firmware",
      "c250_firmware",
      "fas2820_firmware",
      "linux_enterprise_micro",
      "active_iq_unified_manager",
      "e-series_santricity_os_controller"
    ]
  },
  {
    "cve_id": "CVE-2007-4752",
    "product": "openssh",
    "severity": "high",
    "cvss_score": 7.5,
    "description": "OpenSSH before 4.7 contains a privilege escalation caused by improper handling of untrusted cookies, letting attackers cause an X client to be treated",
    "remediation": "Update to OpenSSH 4.7 or later.",
    "is_remote": true,
    "is_kev": true,
    "affected_products": [
      "openssh"
    ]
  },
  {
    "cve_id": "CVE-2019-6109",
    "product": "openssh",
    "severity": "medium",
    "cvss_score": 6.8,
    "description": "OpenSSH 7.9 contains a client-side output manipulation caused by missing character encoding in the progress display, letting a malicious server or man",
    "remediation": "Update to the latest version of OpenSSH where this issue is fixed.",
    "is_remote": true,
    "is_kev": true,
    "affected_products": [
      "scalance_x204rna_firmware",
      "m10-4s_firmware",
      "scalance_x204rna_eec_firmware",
      "openssh",
      "debian_linux",
      "element_software",
      "ontap_select_deploy",
      "enterprise_linux",
      "enterprise_linux_server_tus",
      "storage_automation_store",
      "fedora",
      "m12-2s_firmware",
      "ubuntu_linux",
      "enterprise_linux_server_aus",
      "m10-1_firmware",
      "m10-4_firmware",
      "m12-1_firmware",
      "m12-2_firmware",
      "winscp",
      "enterprise_linux_eus"
    ]
  },
  {
    "cve_id": "CVE-2019-6110",
    "product": "openssh",
    "severity": "medium",
    "cvss_score": 6.8,
    "description": "OpenSSH 7.9 contains a vulnerability caused by accepting and displaying arbitrary stderr output from the server, letting a malicious server or man-in-",
    "remediation": "Update to the latest version of OpenSSH where this issue is fixed.",
    "is_remote": true,
    "is_kev": true,
    "affected_products": [
      "element_software",
      "ontap_select_deploy",
      "storage_automation_store",
      "scalance_x204rna_firmware",
      "scalance_x204rna_eec_firmware",
      "openssh",
      "winscp"
    ]
  },
  {
    "cve_id": "CVE-2002-1399",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 7.2.1 and earlier, and possibly later versions before 7.2.3, contain an unknown vulnerability caused by processing invalid integer input as",
    "remediation": "Update to PostgreSQL 7.2.3 or later versions where the issue is addressed.",
    "is_remote": true,
    "is_kev": false,
    "affected_products": [
      "postgresql"
    ]
  },
  {
    "cve_id": "CVE-2013-1902",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions before 9.2.4, 9.1.9, 9.0.13, 8.4.17, and 8.3.23 generate insecure temporary files with predictable filenames, letting attackers po",
    "remediation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "is_remote": true,
    "is_kev": false,
    "affected_products": [
      "postgresql"
    ]
  },
  {
    "cve_id": "CVE-2007-3279",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL 8.1 and later versions with plpgsql language enabled grant privileges to PUBLIC, allowing remote attackers to create and execute functions,",
    "remediation": "Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed.",
    "is_remote": true,
    "is_kev": false,
    "affected_products": [
      "postgresql"
    ]
  },
  {
    "cve_id": "CVE-2013-1903",
    "product": "postgresql",
    "severity": "critical",
    "cvss_score": 10,
    "description": "PostgreSQL versions 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 contain an information d",
    "remediation": "Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions.",
    "is_remote": true,
    "is_kev": false,
    "affected_products": [
      "postgresql"
    ]
  },
  {
    "cve_id": "CVE-2019-9193",
    "product": "postgresql",
    "severity": "high",
    "cvss_score": 7.2,
    "description": "PostgreSQL 9.3 through 11.2 contains a command execution vulnerability caused by the 'COPY TO/FROM PROGRAM' function, letting superusers and authorize",
    "remediation": "Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue.",
    "is_remote": true,
    "is_kev": true,
    "affected_products": [
      "postgresql"
    ]
  }
]
```

## Report

# ABAC Policy Mining Report

## Executive Summary
Mined an Attribute-Based Access Control (ABAC) policy from the Ansible configuration at `RLM_ANSIBLE_DIR`. The configuration manages a three-tier production environment (DMZ, Application, Database) under PCI compliance tier for organization **segcorp**.

## Policy Statistics
- **Users**: 3 (admin, developer, dba) + 1 system account (postgres)
- **Groups**: sudo, developers, dba
- **Hosts**: 3 (proxy01, app01, db01)
- **Rules**: 10 (9 permit rules + 1 default-deny)
- **Vulnerabilities**: 20 relevant CVEs identified for pinned packages

## Catalog Summary

### Subjects
| User | UID | Groups | Clearance | Department |
|------|-----|--------|-----------|------------|
| admin | 1001 | sudo | secret | operations |
| developer | 1002 | developers | confidential | engineering |
| dba | 1003 | dba | secret | data |
| postgres | - | - | - | system (service account) |

### Resources
| Host | IP | Role | Zone | Group |
|------|----|------|------|-------|
| proxy01.lab.local | 10.0.1.10 | reverse_proxy | dmz | dmz |
| app01.lab.local | 10.0.2.10 | application | app | appservers |
| db01.lab.local | 10.0.3.10 | primary | data | dbservers |

### Environment
- **Org**: segcorp
- **Environment**: production
- **Compliance Tier**: pci
- **Log Retention**: 365 days

## Rule Summary

| Rule ID | Action | Subject Condition | Resource | Effect |
|---------|--------|------------------|----------|--------|
| rule-001 | ssh:login | groups in [sudo, developers] | app01 (app zone) | permit |
| rule-002 | ssh:login | groups in [sudo, dba] | db01 (data zone) | permit |
| rule-003 | ssh:login | groups in [sudo] | proxy01 (dmz zone) | permit |
| rule-004 | network:connect | source: 10.0.1.0/24 | app01:8080 | permit |
| rule-005 | network:connect | source: 0.0.0.0/0 | proxy01:443 | permit |
| rule-006 | db:login | groups in [dba] | db01 postgres (SUPERUSER) | permit |
| rule-007 | db:login | groups in [developers] | db01 postgres (NOSUPERUSER) | permit |
| rule-008 | network:connect | source: 10.0.2.0/24 | db01 postgres:5432 | permit |
| rule-009 | filesystem:read | all (owner-restricted) | /var/lib/postgresql/data (0700) | permit |
| rule-010 | * | all | all | deny |

## Vulnerability Assessment
Pinned packages: nginx 1.20.0, OpenSSH 9.1p1, PostgreSQL 16.2

### Critical Findings
| CVE | Product | CVSS | Severity | KEV | Remote | Remediation |
|-----|---------|------|----------|-----|--------|-------------|
| CVE-2000-0525 | openssh | 10 | critical | no | YES | Update to the latest version of OpenSSH where this issue is fixed or disable the UseLogin option. |
| CVE-2001-0144 | openssh | 10 | critical | no | YES | Update to the latest version or apply security patches addressing the integer overflow issue. |
| CVE-2000-0999 | openssh | 10 | critical | no | YES | Update to the latest version of OpenBSD or apply security patches addressing format string issues. |
| CVE-2002-0640 | openssh | 10 | critical | no | YES | Update to the latest version of OpenSSH that addresses this vulnerability. |
| CVE-2003-0786 | openssh | 10 | critical | no | YES | Update to a version where this issue is fixed, or enable Privilege Separation. |
| CVE-2002-1399 | postgresql | 10 | critical | no | YES | Update to PostgreSQL 7.2.3 or later versions where the issue is addressed. |
| CVE-2013-1902 | postgresql | 10 | critical | no | YES | Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions. |
| CVE-2007-3279 | postgresql | 10 | critical | no | YES | Restrict or remove PUBLIC privileges on plpgsql language, or update to the latest PostgreSQL version where this issue is fixed. |
| CVE-2013-1903 | postgresql | 10 | critical | no | YES | Update to PostgreSQL 9.2.4, 9.1.9, 9.0.13, 8.4.17, or 8.3.23 or later versions. |
| CVE-2016-0746 | nginx | 9.8 | critical | no | YES | Update to nginx 1.9.10 or later versions. |
| CVE-2017-20005 | nginx | 9.8 | critical | no | YES | Update to version 1.13.6 or later. |
| CVE-2009-3555 | nginx | 9.8 | critical | YES | YES | Update to the latest versions of affected products that fix the renegotiation handling issue. |
| CVE-2023-38408 | openssh | 9.8 | critical | YES | YES | Update to OpenSSH 9.3p2 or later. |
| CVE-2024-6387 | openssh | 8.1 | high | YES | YES | Update to the latest version of OpenSSH where this regression is fixed. |
| CVE-2021-23017 | nginx | 7.7 | high | no | YES | Update nginx to the latest version where this issue is fixed. |
| CVE-2023-44487 | nginx | 7.5 | high | YES | YES | Implement rate limiting and update to the latest HTTP/2 protocol standards or patches. |
| CVE-2007-4752 | openssh | 7.5 | high | YES | YES | Update to OpenSSH 4.7 or later. |
| CVE-2019-9193 | postgresql | 7.2 | high | YES | YES | Update to PostgreSQL version 11.3 or later, or apply security patches addressing this issue. |
| CVE-2019-6109 | openssh | 6.8 | medium | YES | YES | Update to the latest version of OpenSSH where this issue is fixed. |
| CVE-2019-6110 | openssh | 6.8 | medium | YES | YES | Update to the latest version of OpenSSH where this issue is fixed. |

### Recommendations
- **nginx 1.20.0** is affected by multiple critical CVEs including CVE-2016-0746 and CVE-2017-20005. Update to >= 1.25.x.
- **OpenSSH** pinned version may be vulnerable to CVE-2024-6387 (regreSSHion) and CVE-2023-38408. Update to >= 9.8p1.
- **PostgreSQL 16.2** may be vulnerable to CVE-2024-1597. Apply latest patch release.

## Ambiguities
1. **SSH version format**: The `ssh_version` variable is `"1:9.1p1-1ubuntu1"` (Debian epoch format). Vulnerability matching uses product name only; exact version correlation may have false positives.
2. **System accounts**: The `postgres` user is not defined in `group_vars/all.yml` users list but is referenced as file owner. Added as system account to catalog.
3. **pg_hba implicit deny**: The pg_hba configuration allows connections only from `10.0.2.0/24`. All other sources are implicitly denied by PostgreSQL's default-deny behavior. This is captured in rule-008 (permit) and rule-010 (default deny).
4. **No SELinux rules**: No SELinux boolean or policy rules found in the configuration.
5. **No sudoers rules**: No explicit sudoers configuration found in role tasks.
6. **Credential management**: No credential vault or secret management configuration detected in the scanned files.
7. **Line numbers**: Source line numbers are approximate based on task block boundaries in the role files.
