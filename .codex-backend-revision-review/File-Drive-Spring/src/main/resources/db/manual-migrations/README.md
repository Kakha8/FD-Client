# Manual database migrations

This application currently uses an H2 file database and Hibernate
`ddl-auto=update`; no Flyway or Liquibase history exists. Hibernate schema
updates cannot safely backfill populated columns.

Before deploying the public-UUID entity mapping to an existing database:

1. Stop all application instances and back up the `data` directory.
2. Apply `V20260820__backfill_user_public_uuid_h2.sql` once to the configured
   H2 JDBC URL using H2 `RUNSCRIPT` or `org.h2.tools.RunScript`.
3. Verify `COUNT(*) WHERE public_uuid IS NULL` is zero and
   `COUNT(DISTINCT public_uuid) = COUNT(*)`.
4. Start the upgraded application.

The script adds the column as nullable, assigns a distinct random UUID to each
legacy row, makes it non-null, and adds a unique index. It never changes an
already assigned UUID. It is H2-specific and must not be reused unchanged if
the production database moves to PostgreSQL or MySQL.

Before deploying recipient-envelope V1, also apply
`V20260822__lockbox_share_envelope_v1_h2.sql`. It adds expiry and complete-envelope
storage, makes the obsolete split fields nullable, and removes the file/recipient
unique constraint so revoked rows remain as append-only audit history. Existing
split envelopes are retained but are not used by the V1 application path.
The database `envelope` column intentionally remains nullable while those legacy
rows exist. The V1 JPA mapping and constructor still require every newly created
V1 envelope to contain exactly 1,858 bytes. Do not make the database column
`NOT NULL` until legacy split-envelope rows have been migrated or archived.
`V20260824__lockbox_installation_handle_h2.sql` adds the account-scoped
installation handle and enrollment context. The device handle is intentionally
nullable during development migration. Production rollout must backfill or
re-enroll legacy devices and then enforce `installation_handle NOT NULL`.

Before deploying device-targeted self-sharing, apply
`V20260826__lockbox_share_target_device_h2.sql`. It derives each existing share's
target device from its stored recipient envelope key, makes the association
mandatory, and adds the file/device uniqueness constraint and received-share
lookup indexes. The migration intentionally fails if legacy data has no complete
recipient envelope or contains multiple shares for the same file and target
device; reconcile those rows from a backup before retrying.
