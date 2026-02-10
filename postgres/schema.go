package postgres

import "context"

const schemaSQL = `
CREATE TABLE IF NOT EXISTS auth_users (
    id         TEXT PRIMARY KEY,
    email      TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_otps (
    id         TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    code       TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    verified   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_permissions (
    id          TEXT PRIMARY KEY,
    key         TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_user_permissions (
    user_id       TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES auth_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, permission_id)
);

CREATE TABLE IF NOT EXISTS auth_groups (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_group_permissions (
    group_id      TEXT NOT NULL REFERENCES auth_groups(id) ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES auth_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, permission_id)
);

CREATE TABLE IF NOT EXISTS auth_user_groups (
    user_id  TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES auth_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_otps_email ON auth_otps(email);
CREATE INDEX IF NOT EXISTS idx_auth_users_email ON auth_users(email);
CREATE INDEX IF NOT EXISTS idx_auth_permissions_key ON auth_permissions(key);
CREATE INDEX IF NOT EXISTS idx_auth_user_permissions_user ON auth_user_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_group_permissions_group ON auth_group_permissions(group_id);
CREATE INDEX IF NOT EXISTS idx_auth_user_groups_user ON auth_user_groups(user_id);
`

// CreateSchema creates all auth tables if they don't exist.
func (s *PGStore) CreateSchema(ctx context.Context) error {
	_, err := s.db.Exec(ctx, schemaSQL)
	return err
}

// DropSchema drops all auth tables.
func (s *PGStore) DropSchema(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `
		DROP TABLE IF EXISTS auth_user_groups CASCADE;
		DROP TABLE IF EXISTS auth_group_permissions CASCADE;
		DROP TABLE IF EXISTS auth_user_permissions CASCADE;
		DROP TABLE IF EXISTS auth_groups CASCADE;
		DROP TABLE IF EXISTS auth_permissions CASCADE;
		DROP TABLE IF EXISTS auth_otps CASCADE;
		DROP TABLE IF EXISTS auth_users CASCADE;
	`)
	return err
}
