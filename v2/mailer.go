package auth

import (
	"context"
	"time"
)

// Mailer defines the contract for sending auth emails.
// Implementors use their own templates and sender identity — auth only calls these methods.
type Mailer interface {
	SendOTP(ctx context.Context, email string, code string, expiresIn time.Duration) error
	SendPasswordReset(ctx context.Context, email string, resetURL string, expiresIn time.Duration) error
	SendWelcome(ctx context.Context, user *User) error
}
