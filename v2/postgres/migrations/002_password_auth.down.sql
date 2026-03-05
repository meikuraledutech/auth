DROP TABLE IF EXISTS auth_password_resets CASCADE;
ALTER TABLE auth_users DROP COLUMN IF EXISTS password_hash;
