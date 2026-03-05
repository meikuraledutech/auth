package auth

import (
	"context"
	"time"
)

// Mailer defines the contract for sending auth emails.
type Mailer interface {
	SendOTP(ctx context.Context, email string, code string, expiresIn time.Duration) error
	SendPasswordReset(ctx context.Context, email string, resetURL string, expiresIn time.Duration) error
}
