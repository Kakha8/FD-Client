-- Back up the database and stop all application instances before applying.
ALTER TABLE lockbox_shares ADD COLUMN IF NOT EXISTS target_device_id BIGINT;

-- The recipient envelope key is the authoritative target for legacy V1 shares.
UPDATE lockbox_shares share
SET target_device_id = (
    SELECT recipient_key.device_id
    FROM lockbox_share_envelopes envelope
    JOIN lockbox_keys recipient_key ON recipient_key.id = envelope.recipient_key_id
    WHERE envelope.share_id = share.id
)
WHERE target_device_id IS NULL;

ALTER TABLE lockbox_shares ALTER COLUMN target_device_id SET NOT NULL;
ALTER TABLE lockbox_shares ADD CONSTRAINT IF NOT EXISTS fk_lockbox_share_target_device
    FOREIGN KEY (target_device_id) REFERENCES lockbox_devices(id);
CREATE INDEX IF NOT EXISTS idx_lockbox_share_target_status
    ON lockbox_shares(target_device_id, status);
CREATE INDEX IF NOT EXISTS idx_lockbox_share_recipient_target_status
    ON lockbox_shares(recipient_user_id, target_device_id, status);
ALTER TABLE lockbox_shares ADD CONSTRAINT IF NOT EXISTS uk_lockbox_share_file_target_device
    UNIQUE (lockbox_file_id, target_device_id);
