# f3_privsep_service_accounts

## Topology

Web + database + cache deployment with explicit service account privilege separation.

- **webservers** (1 host): web01.lab.local (10.0.1.10), zone=dmz — nginx as www-data
- **dbservers** (1 host): db01.lab.local (10.0.2.10), zone=internal — PostgreSQL as postgres
- **cacheservers** (1 host): cache01.lab.local (10.0.2.20), zone=internal — Redis as redis

## Intent Policy

- nginx runs as `www-data` with no sudo and no shell access.
- PostgreSQL runs as `postgres` with no shell access.
- Redis runs as `redis` with no shell access.
- An RCE on nginx should land as `www-data`, not root.
- Web tier is internet-facing. DB and cache are reachable only from web subnet.
- Only `sudo` group can SSH to web hosts.
