-- H2 file-database migration. Apply before deploying the entity mapping that
-- requires users.public_uuid to be NOT NULL. This script is idempotent.
-- Back up ./data first, stop every application instance, then run with H2's
-- RUNSCRIPT or the org.h2.tools.RunScript utility against the production URL.

ALTER TABLE users ADD COLUMN IF NOT EXISTS public_uuid UUID;

UPDATE users
SET public_uuid = RANDOM_UUID()
WHERE public_uuid IS NULL;

ALTER TABLE users ALTER COLUMN public_uuid SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uk_users_public_uuid
    ON users (public_uuid);
