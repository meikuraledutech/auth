package auth

import (
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User represents an authenticated user.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

// OTP represents a one-time password sent to a user's email.
type OTP struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

// PasswordReset represents a password reset request.
type PasswordReset struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
	// token_hash stored in DB only, never exposed
}

// TokenPair holds the JWT access and refresh tokens.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Claims represents the JWT token claims.
type Claims struct {
	UserID      string         `json:"user_id"`
	Email       string         `json:"email"`
	Type        string         `json:"type"` // "access" or "refresh"
	Permissions []string       `json:"permissions,omitempty"`
	Groups      []string       `json:"groups,omitempty"` // group names
	Meta        map[string]any `json:"meta,omitempty"`   // custom app-level claims (e.g. college_id)
}

// Permission represents a single permission that can be assigned to users or groups.
type Permission struct {
	ID          string    `json:"id"`
	Key         string    `json:"key"`         // e.g. "forms:create"
	Description string    `json:"description"` // e.g. "Can create forms"
	CreatedAt   time.Time `json:"created_at"`
}

// Group represents a permission group for bulk assignment.
type Group struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"` // e.g. "Editor"
	Permissions []Permission `json:"permissions,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
}

// MigrationRecord represents an applied database migration.
type MigrationRecord struct {
	Name      string
	Applied   bool
	AppliedAt *time.Time
	Checksum  string
}

// Config holds the configuration for the auth package.
type Config struct {
	JWTSecret           string
	OTPLength           int
	OTPExpiry           time.Duration
	AccessExpiry        time.Duration
	RefreshExpiry       time.Duration
	SuperAdminEmail     string
	AutoMigrate         bool // if true, Bootstrap() runs migrations automatically
	BcryptCost          int
	PasswordResetExpiry time.Duration
	MinPasswordLength   int
	MaxPasswordLength   int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig(jwtSecret string, superAdminEmail string) Config {
	return Config{
		JWTSecret:           jwtSecret,
		OTPLength:           6,
		OTPExpiry:           5 * time.Minute,
		AccessExpiry:        15 * time.Minute,
		RefreshExpiry:       7 * 24 * time.Hour,
		SuperAdminEmail:     superAdminEmail,
		AutoMigrate:         true,
		BcryptCost:          bcrypt.DefaultCost,
		PasswordResetExpiry: time.Hour,
		MinPasswordLength:   8,
		MaxPasswordLength:   72,
	}
}
