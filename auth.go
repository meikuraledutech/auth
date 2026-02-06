package auth

import "time"

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

// TokenPair holds the JWT access and refresh tokens.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Claims represents the JWT token claims.
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Type   string `json:"type"` // "access" or "refresh"
}

// Config holds the configuration for the auth package.
type Config struct {
	JWTSecret      string
	OTPLength      int
	OTPExpiry      time.Duration
	AccessExpiry   time.Duration
	RefreshExpiry  time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig(jwtSecret string) Config {
	return Config{
		JWTSecret:     jwtSecret,
		OTPLength:     6,
		OTPExpiry:     5 * time.Minute,
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
	}
}
