# Database migrations

Upgrades of the `dns_panel` schema after v1.0. `deploy/install.sh` runs the files that the database has not
recorded in `schema_migrations`, in name order, before it replaces the code. A clean install loads
`docs/INSTALL/schema.sql` and records every file here as applied.

A change of the schema is two edits in one commit: a new file here and the same change in `schema.sql`.

- Name: `NNNN-short-name.sql`, the next number (`0001-api-token-scopes.sql`).
- Plain SQL for MariaDB, no `USE`: it runs against `dns_panel`.
- Safe to run twice: `CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, `DROP ... IF EXISTS`.
- Compatible with the previous release: during an update of a pair one node already runs the new code and
  the other the old one. Add first; remove an old column or table only in a later release.
- It runs once, on the writable node (standalone or ACTIVE), and reaches the STANDBY by replication.
