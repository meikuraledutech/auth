package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword validates password strength then bcrypt-hashes the plain text password.
func HashPassword(cfg Config, plain string) (string, error) {
	if err := ValidatePasswordStrength(cfg, plain); err != nil {
		return "", err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plain), cfg.BcryptCost)
	if err != nil {
		return "", fmt.Errorf("auth: hash password: %w", err)
	}

	return string(hash), nil
}

// CheckPassword compares plain text against bcrypt hash.
// Returns ErrPasswordInvalid on mismatch.
func CheckPassword(plain, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
	if err != nil {
		return ErrPasswordInvalid
	}
	return nil
}

// ValidatePasswordStrength enforces password strength requirements:
// - min/max length (max is 72 due to bcrypt limit)
// - uppercase, lowercase, digit, special character
func ValidatePasswordStrength(cfg Config, plain string) error {
	if len(plain) < cfg.MinPasswordLength || len(plain) > cfg.MaxPasswordLength {
		return ErrPasswordTooWeak
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, r := range plain {
		if unicode.IsUpper(r) {
			hasUpper = true
		} else if unicode.IsLower(r) {
			hasLower = true
		} else if unicode.IsDigit(r) {
			hasDigit = true
		} else if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return ErrPasswordTooWeak
	}

	return nil
}

// GenerateResetToken returns a 32-byte CSPRNG token as base64url string (43 chars).
func GenerateResetToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", fmt.Errorf("auth: generate reset token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(token), nil
}

// HashResetToken returns the SHA-256 hex of the raw token (stored in DB, never the raw token).
func HashResetToken(rawToken string) string {
	hash := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hash[:])
}
