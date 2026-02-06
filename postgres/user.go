package postgres

import (
	"context"
	"fmt"

	"github.com/meikuraledutech/auth"
)

// GetUserByID fetches a user by their ID.
// Returns nil, nil if not found.
func (s *PGStore) GetUserByID(ctx context.Context, id string) (*auth.User, error) {
	var u auth.User
	err := s.db.QueryRow(ctx,
		`SELECT id, email, created_at FROM auth_users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Email, &u.CreatedAt)

	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("auth: get user by id: %w", err)
	}

	return &u, nil
}

// GetUserByEmail fetches a user by their email.
// Returns nil, nil if not found.
func (s *PGStore) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	var u auth.User
	err := s.db.QueryRow(ctx,
		`SELECT id, email, created_at FROM auth_users WHERE email = $1`, email,
	).Scan(&u.ID, &u.Email, &u.CreatedAt)

	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("auth: get user by email: %w", err)
	}

	return &u, nil
}

// isNoRows checks if the error is a "no rows" error from pgx.
func isNoRows(err error) bool {
	return err != nil && err.Error() == "no rows in result set"
}
