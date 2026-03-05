package postgres

import "context"

// CreateSchema applies all pending migrations. Delegates to Migrate for migration-based schema management.
func (s *PGStore) CreateSchema(ctx context.Context) error {
	return s.Migrate(ctx)
}

// DropSchema drops all auth tables and the migrations tracking table.
func (s *PGStore) DropSchema(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `
		DROP TABLE IF EXISTS auth_password_resets CASCADE;
		DROP TABLE IF EXISTS auth_migrations CASCADE;
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
