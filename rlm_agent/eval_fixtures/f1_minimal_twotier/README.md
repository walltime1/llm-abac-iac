# f1_minimal_twotier

## Topology

Two-tier web + database deployment.

- **webservers** (1 host): web01.lab.local (10.0.1.10), zone=dmz
- **dbservers** (1 host): db01.lab.local (10.0.2.10), zone=internal

## Intent Policy

- The web tier is internet-facing and serves HTTP on port 80.
- The database tier is reachable only from the web tier subnet (10.0.1.0/24) on port 5432.
- No external user can access the database directly.
- Only users in the `sudo` group with `secret` clearance may execute sudo on web hosts.
