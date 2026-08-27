-- Development H2 migration. Keep these columns nullable so legacy rows load.
-- Production must backfill or re-enroll legacy devices, then make
-- lockbox_devices.installation_handle NOT NULL.
ALTER TABLE lockbox_devices ADD COLUMN IF NOT EXISTS installation_handle VARBINARY(32);
ALTER TABLE lockbox_enrollment_challenges ADD COLUMN IF NOT EXISTS device_uuid UUID;
ALTER TABLE lockbox_enrollment_challenges ADD COLUMN IF NOT EXISTS device_name VARCHAR(100);
ALTER TABLE lockbox_enrollment_challenges ADD COLUMN IF NOT EXISTS installation_handle VARBINARY(32);

ALTER TABLE lockbox_devices ADD CONSTRAINT IF NOT EXISTS
    uk_lockbox_device_profile_installation
    UNIQUE (profile_id, installation_handle);
