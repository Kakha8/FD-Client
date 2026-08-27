-- Back up the database and stop all application instances before applying.
-- Append-only sharing permits a new share after an earlier share is revoked.
ALTER TABLE lockbox_shares DROP CONSTRAINT IF EXISTS uk_lockbox_share_file_recipient;
ALTER TABLE lockbox_shares ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE;

-- Legacy split columns are retained for audit/history and made nullable for V1 rows.
ALTER TABLE lockbox_share_envelopes ALTER COLUMN kem_ciphertext SET NULL;
ALTER TABLE lockbox_share_envelopes ALTER COLUMN wrap_nonce SET NULL;
ALTER TABLE lockbox_share_envelopes ALTER COLUMN wrapped_dek SET NULL;
ALTER TABLE lockbox_share_envelopes ADD COLUMN IF NOT EXISTS envelope BINARY LARGE OBJECT;

