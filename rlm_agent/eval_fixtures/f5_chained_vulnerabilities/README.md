# f5_chained_vulnerabilities

## Topology

Four-host linear chain with strict zone segmentation.

- **bastion** (1 host): bastion01.lab.local (10.0.0.5), zone=mgmt — SSH gateway
- **webservers** (1 host): web01.lab.local (10.0.1.10), zone=dmz — Apache httpd
- **appservers** (1 host): app01.lab.local (10.0.2.10), zone=app — Java application
- **dbservers** (1 host): db01.lab.local (10.0.3.10), zone=data — PostgreSQL

## Intent Policy

- Bastion is the only host reachable from the internet (SSH on :22).
- Web tier accepts HTTP (:80) from bastion subnet only (10.0.0.0/24).
- Application tier accepts :8080 from web subnet only (10.0.1.0/24).
- Database tier accepts :5432 from app subnet only (10.0.2.0/24).
- Each tier is isolated: no direct internet access to web, app, or db.
- Only `sudo` group with `secret` clearance may sudo on bastion.
- Only `dba` group has SUPERUSER database access.
