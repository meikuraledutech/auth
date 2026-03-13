package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/meikuraledutech/auth/v2"
)

// CreateUser creates a new user with the given email.
func (s *PGStore) CreateUser(ctx context.Context, email string) (*auth.User, error) {
	user := &auth.User{
		ID:    uuid.NewString(),
		Email: email,
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO auth_users (id, email, organization) VALUES ($1, $2, NULL) ON CONFLICT (email) DO NOTHING`,
		user.ID, user.Email,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: create user: %w", err)
	}
	// Re-fetch to get the actual ID (in case of conflict)
	return s.GetUserByEmail(ctx, email)
}

// CreateUserWithOrganization creates a new user assigned to an organization.
func (s *PGStore) CreateUserWithOrganization(ctx context.Context, email string, organization string) (*auth.User, error) {
	// Validate org exists
	org, err := s.GetOrganizationByName(ctx, organization)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, auth.ErrInvalidOrganization
	}

	user := &auth.User{
		ID:           uuid.NewString(),
		Email:        email,
		Organization: organization,
	}
	_, err = s.db.Exec(ctx,
		`INSERT INTO auth_users (id, email, organization) VALUES ($1, $2, $3) ON CONFLICT (email) DO NOTHING`,
		user.ID, user.Email, user.Organization,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: create user with organization: %w", err)
	}
	// Re-fetch to get the actual ID (in case of conflict)
	return s.GetUserByEmail(ctx, email)
}

// GetUserOrganization returns the organization assigned to a user.
func (s *PGStore) GetUserOrganization(ctx context.Context, userID string) (string, error) {
	var org string
	err := s.db.QueryRow(ctx,
		`SELECT COALESCE(organization, '') FROM auth_users WHERE id = $1`, userID,
	).Scan(&org)
	if err != nil {
		if isNoRows(err) {
			return "", nil
		}
		return "", fmt.Errorf("auth: get user organization: %w", err)
	}
	return org, nil
}

// ListUsers returns all users.
func (s *PGStore) ListUsers(ctx context.Context) ([]auth.User, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, email, organization, created_at FROM auth_users ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("auth: list users: %w", err)
	}
	defer rows.Close()

	users := []auth.User{}
	for rows.Next() {
		var u auth.User
		var org *string
		if err := rows.Scan(&u.ID, &u.Email, &org, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("auth: scan user: %w", err)
		}
		if org != nil {
			u.Organization = *org
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// GetUserByID fetches a user by their ID.
// Returns nil, nil if not found.
func (s *PGStore) GetUserByID(ctx context.Context, id string) (*auth.User, error) {
	var u auth.User
	var org *string
	err := s.db.QueryRow(ctx,
		`SELECT id, email, organization, created_at FROM auth_users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Email, &org, &u.CreatedAt)

	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("auth: get user by id: %w", err)
	}

	if org != nil {
		u.Organization = *org
	}

	return &u, nil
}

// GetUserByEmail fetches a user by their email.
// Returns nil, nil if not found.
func (s *PGStore) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	var u auth.User
	var org *string
	err := s.db.QueryRow(ctx,
		`SELECT id, email, organization, created_at FROM auth_users WHERE email = $1`, email,
	).Scan(&u.ID, &u.Email, &org, &u.CreatedAt)

	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("auth: get user by email: %w", err)
	}

	if org != nil {
		u.Organization = *org
	}

	return &u, nil
}

// isNoRows checks if the error is a "no rows" error from pgx.
func isNoRows(err error) bool {
	return err != nil && err.Error() == "no rows in result set"
}
