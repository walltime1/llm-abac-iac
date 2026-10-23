# f4_patched_vs_vulnerable

## Topology

Two parallel web tiers — one patched, one legacy — sharing the same database.

- **webservers_patched** (1 host): web-new01.lab.local (10.0.1.10), zone=dmz — nginx 1.24.0
- **webservers_legacy** (1 host): web-old01.lab.local (10.0.1.20), zone=dmz — nginx 1.20.0
- **dbservers** (1 host): db01.lab.local (10.0.2.10), zone=internal

## Intent Policy

- Both web tiers are internet-facing on :443.
- Database is reachable from the web subnet only (10.0.1.0/24) on :5432.
- Patched hosts run nginx 1.24.0. Legacy hosts run nginx 1.20.0.
- Only `sudo` group can SSH to any web host.
