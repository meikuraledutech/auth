package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/meikuraledutech/auth/v2"
)

// RegisterWithPassword creates a new user with an email and password.
// Returns ErrEmailAlreadyRegistered if the email is already taken.
func (s *PGStore) RegisterWithPassword(ctx context.Context, email string, plainPassword string) (*auth.User, error) {
	// Validate password strength
	if err := auth.ValidatePasswordStrength(s.cfg, plainPassword); err != nil {
		return nil, err
	}

	// Hash the password
	passwordHash, err := auth.HashPassword(s.cfg, plainPassword)
	if err != nil {
		return nil, err
	}

	// Check if email already exists
	existing, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, auth.ErrEmailAlreadyRegistered
	}

	// Create the user with password hash
	user := &auth.User{
		ID:    uuid.NewString(),
		Email: email,
	}

	_, err = s.db.Exec(ctx,
		`INSERT INTO auth_users (id, email, password_hash) VALUES ($1, $2, $3)`,
		user.ID, user.Email, passwordHash,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: register with password: %w", err)
	}

	return user, nil
}

// LoginWithPassword validates the email and password, returning the user if valid.
// Returns ErrPasswordNotSet if the user exists but has no password (OTP-only account).
// Returns ErrPasswordInvalid if the password is incorrect.
func (s *PGStore) LoginWithPassword(ctx context.Context, email string, plainPassword string) (*auth.User, error) {
	var user auth.User
	var passwordHashPtr *string

	err := s.db.QueryRow(ctx,
		`SELECT id, email, created_at, password_hash FROM auth_users WHERE email = $1`,
		email,
	).Scan(&user.ID, &user.Email, &user.CreatedAt, &passwordHashPtr)

	if err != nil {
		if isNoRows(err) {
			return nil, auth.ErrPasswordInvalid
		}
		return nil, fmt.Errorf("auth: login with password: %w", err)
	}

	// Check if password_hash is NULL (OTP-only account)
	if passwordHashPtr == nil {
		return nil, auth.ErrPasswordNotSet
	}

	// Verify password
	if err := auth.CheckPassword(plainPassword, *passwordHashPtr); err != nil {
		return nil, err
	}

	return &user, nil
}

// SetPassword updates a user's password (admin override).
// Returns ErrUserNotFound if the user does not exist.
func (s *PGStore) SetPassword(ctx context.Context, userID string, plainPassword string) error {
	// Validate password strength
	if err := auth.ValidatePasswordStrength(s.cfg, plainPassword); err != nil {
		return err
	}

	// Hash the password
	passwordHash, err := auth.HashPassword(s.cfg, plainPassword)
	if err != nil {
		return err
	}

	// Check user exists
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return auth.ErrUserNotFound
	}

	// Update password
	_, err = s.db.Exec(ctx,
		`UPDATE auth_users SET password_hash = $1 WHERE id = $2`,
		passwordHash, userID,
	)
	if err != nil {
		return fmt.Errorf("auth: set password: %w", err)
	}

	return nil
}

// ChangePassword verifies the current password, then updates to the new one.
// Returns ErrPasswordNotSet if the user has no password (OTP-only account).
// Returns ErrPasswordInvalid if the current password is wrong.
// Returns ErrPasswordTooWeak if the new password doesn't meet strength requirements.
func (s *PGStore) ChangePassword(ctx context.Context, userID string, currentPassword string, newPassword string) error {
	// Get current password hash
	var passwordHashPtr *string
	err := s.db.QueryRow(ctx,
		`SELECT password_hash FROM auth_users WHERE id = $1`,
		userID,
	).Scan(&passwordHashPtr)

	if err != nil {
		if isNoRows(err) {
			return auth.ErrUserNotFound
		}
		return fmt.Errorf("auth: change password query: %w", err)
	}

	// Check if password_hash is NULL (OTP-only account)
	if passwordHashPtr == nil {
		return auth.ErrPasswordNotSet
	}

	// Verify current password
	if err := auth.CheckPassword(currentPassword, *passwordHashPtr); err != nil {
		return err
	}

	// Validate new password strength
	if err := auth.ValidatePasswordStrength(s.cfg, newPassword); err != nil {
		return err
	}

	// Hash new password
	newHash, err := auth.HashPassword(s.cfg, newPassword)
	if err != nil {
		return err
	}

	// Update password
	_, err = s.db.Exec(ctx,
		`UPDATE auth_users SET password_hash = $1 WHERE id = $2`,
		newHash, userID,
	)
	if err != nil {
		return fmt.Errorf("auth: update password: %w", err)
	}

	return nil
}

// HasPassword checks if a user has a password set.
func (s *PGStore) HasPassword(ctx context.Context, userID string) (bool, error) {
	var passwordHashPtr *string
	err := s.db.QueryRow(ctx,
		`SELECT password_hash FROM auth_users WHERE id = $1`,
		userID,
	).Scan(&passwordHashPtr)

	if err != nil {
		if isNoRows(err) {
			return false, auth.ErrUserNotFound
		}
		return false, fmt.Errorf("auth: has password: %w", err)
	}

	return passwordHashPtr != nil, nil
}

// CreatePasswordReset generates a password reset token for the given email.
// Invalidates any existing unused tokens for that user.
// Returns the raw token (for the reset link) and expiry time.
func (s *PGStore) CreatePasswordReset(ctx context.Context, email string) (rawToken string, expiresAt time.Time, err error) {
	// Get the user
	user, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		return "", time.Time{}, err
	}
	if user == nil {
		// Don't reveal whether email exists (security best practice)
		return "", time.Time{}, nil
	}

	// Generate the reset token
	rawToken, err = auth.GenerateResetToken()
	if err != nil {
		return "", time.Time{}, err
	}

	tokenHash := auth.HashResetToken(rawToken)
	expiresAt = time.Now().Add(s.cfg.PasswordResetExpiry)

	// Use a transaction to invalidate old tokens and create new one
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Invalidate existing unused tokens for this user
	_, err = tx.Exec(ctx,
		`UPDATE auth_password_resets SET used = TRUE WHERE user_id = $1 AND used = FALSE`,
		user.ID,
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: invalidate old tokens: %w", err)
	}

	// Insert new token
	resetID := uuid.NewString()
	_, err = tx.Exec(ctx,
		`INSERT INTO auth_password_resets (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)`,
		resetID, user.ID, tokenHash, expiresAt,
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: insert reset token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, fmt.Errorf("auth: commit tx: %w", err)
	}

	return rawToken, expiresAt, nil
}

// ResetPassword validates the reset token and updates the user's password.
// Marks the token as used atomically.
// Returns ErrResetTokenInvalid if the token is not found or has expired.
// Returns ErrResetTokenUsed if the token has already been used.
// Returns ErrPasswordTooWeak if the new password doesn't meet strength requirements.
func (s *PGStore) ResetPassword(ctx context.Context, rawToken string, newPassword string) error {
	// Hash the token to lookup in DB
	tokenHash := auth.HashResetToken(rawToken)

	// Validate password strength first
	if err := auth.ValidatePasswordStrength(s.cfg, newPassword); err != nil {
		return err
	}

	// Hash the new password
	passwordHash, err := auth.HashPassword(s.cfg, newPassword)
	if err != nil {
		return err
	}

	// Start a transaction
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("auth: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Lookup the reset token
	var resetID string
	var userID string
	var used bool
	var expiresAt time.Time

	err = tx.QueryRow(ctx,
		`SELECT id, user_id, used, expires_at FROM auth_password_resets WHERE token_hash = $1`,
		tokenHash,
	).Scan(&resetID, &userID, &used, &expiresAt)

	if err != nil {
		if isNoRows(err) {
			return auth.ErrResetTokenInvalid
		}
		return fmt.Errorf("auth: lookup reset token: %w", err)
	}

	// Check if already used
	if used {
		return auth.ErrResetTokenUsed
	}

	// Check if expired
	if time.Now().After(expiresAt) {
		return auth.ErrResetTokenInvalid
	}

	// Update password and mark token as used
	_, err = tx.Exec(ctx,
		`UPDATE auth_users SET password_hash = $1 WHERE id = $2`,
		passwordHash, userID,
	)
	if err != nil {
		return fmt.Errorf("auth: update password: %w", err)
	}

	_, err = tx.Exec(ctx,
		`UPDATE auth_password_resets SET used = TRUE WHERE id = $1`,
		resetID,
	)
	if err != nil {
		return fmt.Errorf("auth: mark token used: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("auth: commit tx: %w", err)
	}

	return nil
}
