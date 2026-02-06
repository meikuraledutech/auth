package auth

import (
	"context"
	"errors"
)

var (
	ErrOTPExpired   = errors.New("auth: otp has expired")
	ErrOTPInvalid   = errors.New("auth: invalid otp code")
	ErrUserNotFound = errors.New("auth: user not found")
)

// Store defines the contract for persisting and retrieving auth data.
type Store interface {
	// Schema
	CreateSchema(ctx context.Context) error
	DropSchema(ctx context.Context) error

	// OTP
	CreateOTP(ctx context.Context, email string) (*OTP, error)
	VerifyOTP(ctx context.Context, email string, code string) (*User, error)

	// Users
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
}
