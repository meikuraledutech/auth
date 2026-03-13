ALTER TABLE auth_users DROP COLUMN IF EXISTS organization;
DROP TABLE IF EXISTS auth_organization_permissions CASCADE;
DROP TABLE IF EXISTS auth_organizations CASCADE;
