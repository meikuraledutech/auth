package auth

import (
	"context"
	"time"
)

// Mailer defines the contract for sending OTP emails.
type Mailer interface {
	SendOTP(ctx context.Context, email string, code string, expiresIn time.Duration) error
}
