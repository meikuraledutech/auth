-- Organizations table (mirrors auth_groups pattern)
CREATE TABLE IF NOT EXISTS auth_organizations (
    id         TEXT PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Junction table (mirrors auth_group_permissions pattern)
CREATE TABLE IF NOT EXISTS auth_organization_permissions (
    organization_id TEXT NOT NULL REFERENCES auth_organizations(id) ON DELETE CASCADE,
    permission_id   TEXT NOT NULL REFERENCES auth_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (organization_id, permission_id)
);

-- Add organization field to users (nullable — no default, backward compat)
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS organization TEXT REFERENCES auth_organizations(name);

CREATE INDEX IF NOT EXISTS idx_auth_users_organization ON auth_users(organization);
CREATE INDEX IF NOT EXISTS idx_auth_org_permissions_org ON auth_organization_permissions(organization_id);
