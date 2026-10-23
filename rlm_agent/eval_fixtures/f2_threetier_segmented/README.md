# f2_threetier_segmented

## Topology

Three-tier zone-segmented deployment with explicit trust boundaries.

- **dmz** (1 host): proxy01.lab.local (10.0.1.10), zone=dmz — nginx reverse proxy
- **appservers** (1 host): app01.lab.local (10.0.2.10), zone=app — application server
- **dbservers** (1 host): db01.lab.local (10.0.3.10), zone=data — PostgreSQL 13

## Intent Policy

- DMZ accepts HTTPS (:443) from the internet.
- Application tier accepts :8080 from DMZ subnet only (10.0.1.0/24).
- Database tier accepts :5432 from application subnet only (10.0.2.0/24).
- No direct internet access to application or database tiers.
- SSH restricted by group per tier.
- Only `dba` group has SUPERUSER database access.
