package postgres

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/meikuraledutech/auth"
)

// CreateOTP generates a random OTP code for the given email and stores it.
func (s *PGStore) CreateOTP(ctx context.Context, email string) (*auth.OTP, error) {
	code, err := generateCode(s.cfg.OTPLength)
	if err != nil {
		return nil, fmt.Errorf("auth: generate otp: %w", err)
	}

	otp := &auth.OTP{
		ID:        uuid.NewString(),
		Email:     email,
		Code:      code,
		ExpiresAt: time.Now().Add(s.cfg.OTPExpiry),
		Verified:  false,
		CreatedAt: time.Now(),
	}

	_, err = s.db.Exec(ctx,
		`INSERT INTO auth_otps (id, email, code, expires_at, verified) VALUES ($1, $2, $3, $4, $5)`,
		otp.ID, otp.Email, otp.Code, otp.ExpiresAt, otp.Verified,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: insert otp: %w", err)
	}

	return otp, nil
}

// VerifyOTP validates the OTP code for the given email.
// If valid, it marks the OTP as verified and returns the user (auto-creating if needed).
func (s *PGStore) VerifyOTP(ctx context.Context, email string, code string) (*auth.User, error) {
	var otp auth.OTP
	err := s.db.QueryRow(ctx,
		`SELECT id, email, code, expires_at, verified FROM auth_otps
		 WHERE email = $1 AND verified = FALSE
		 ORDER BY created_at DESC LIMIT 1`,
		email,
	).Scan(&otp.ID, &otp.Email, &otp.Code, &otp.ExpiresAt, &otp.Verified)

	if err != nil {
		if isNoRows(err) {
			return nil, auth.ErrOTPInvalid
		}
		return nil, fmt.Errorf("auth: query otp: %w", err)
	}

	if time.Now().After(otp.ExpiresAt) {
		return nil, auth.ErrOTPExpired
	}

	if otp.Code != code {
		return nil, auth.ErrOTPInvalid
	}

	// Mark OTP as verified.
	_, err = s.db.Exec(ctx, `UPDATE auth_otps SET verified = TRUE WHERE id = $1`, otp.ID)
	if err != nil {
		return nil, fmt.Errorf("auth: verify otp: %w", err)
	}

	// Find or create user.
	user, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		user = &auth.User{
			ID:    uuid.NewString(),
			Email: email,
		}
		_, err = s.db.Exec(ctx,
			`INSERT INTO auth_users (id, email) VALUES ($1, $2)`,
			user.ID, user.Email,
		)
		if err != nil {
			return nil, fmt.Errorf("auth: create user: %w", err)
		}
	}

	return user, nil
}

// generateCode creates a cryptographically random numeric code of the given length.
func generateCode(length int) (string, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(10), big.NewInt(int64(length)), nil)

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%0*d", length, n), nil
}
