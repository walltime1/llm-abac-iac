# f6_intent_vs_effective

## Topology

Three-tier zone-segmented deployment.

- **dmz** (1 host): proxy01.lab.local (10.0.1.10), zone=dmz — nginx reverse proxy
- **appservers** (1 host): app01.lab.local (10.0.2.10), zone=app — application server
- **dbservers** (1 host): db01.lab.local (10.0.3.10), zone=data — PostgreSQL

## Intent Policy

- The DMZ accepts HTTPS (:443) from the internet.
- The application tier accepts connections on :8080 from the DMZ subnet only (10.0.1.0/24).
- The database tier accepts connections on :5432 from the application subnet only (10.0.2.0/24).
- No external user can access the database directly. Traffic must traverse DMZ, then app, then db.
- Only users in the `sudo` group may SSH to DMZ hosts.
- Only `dba` group members have SUPERUSER database access.
