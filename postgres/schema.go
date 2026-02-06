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

CREATE INDEX IF NOT EXISTS idx_auth_otps_email ON auth_otps(email);
CREATE INDEX IF NOT EXISTS idx_auth_users_email ON auth_users(email);
`

// CreateSchema creates the auth_users and auth_otps tables if they don't exist.
func (s *PGStore) CreateSchema(ctx context.Context) error {
	_, err := s.db.Exec(ctx, schemaSQL)
	return err
}

// DropSchema drops the auth_otps and auth_users tables.
func (s *PGStore) DropSchema(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DROP TABLE IF EXISTS auth_otps, auth_users CASCADE;`)
	return err
}
