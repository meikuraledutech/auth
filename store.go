package auth

import (
	"context"
	"errors"
)

var (
	ErrOTPExpired         = errors.New("auth: otp has expired")
	ErrOTPInvalid         = errors.New("auth: invalid otp code")
	ErrUserNotFound       = errors.New("auth: user not found")
	ErrPermissionNotFound = errors.New("auth: permission not found")
	ErrPermissionExists   = errors.New("auth: permission already exists")
	ErrGroupNotFound      = errors.New("auth: group not found")
	ErrGroupExists        = errors.New("auth: group already exists")
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
	CreateUser(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context) ([]User, error)

	// Permissions
	CreatePermission(ctx context.Context, key string, description string) (*Permission, error)
	GetPermission(ctx context.Context, key string) (*Permission, error)
	ListPermissions(ctx context.Context) ([]Permission, error)
	DeletePermission(ctx context.Context, id string) error

	// User Permissions (direct)
	AssignPermission(ctx context.Context, userID string, permissionKey string) error
	RevokePermission(ctx context.Context, userID string, permissionKey string) error
	GetUserPermissions(ctx context.Context, userID string) ([]Permission, error)
	HasPermission(ctx context.Context, userID string, permissionKey string) (bool, error)

	// Groups
	CreateGroup(ctx context.Context, name string) (*Group, error)
	GetGroup(ctx context.Context, id string) (*Group, error)
	ListGroups(ctx context.Context) ([]Group, error)
	DeleteGroup(ctx context.Context, id string) error
	AddPermissionToGroup(ctx context.Context, groupID string, permissionKey string) error
	RemovePermissionFromGroup(ctx context.Context, groupID string, permissionID string) error

	// User Groups
	AssignUserToGroup(ctx context.Context, userID string, groupID string) error
	RemoveUserFromGroup(ctx context.Context, userID string, groupID string) error
	GetUserGroups(ctx context.Context, userID string) ([]Group, error)

	// Resolved Permissions (direct + from groups)
	GetResolvedPermissions(ctx context.Context, userID string) ([]Permission, error)
	HasResolvedPermission(ctx context.Context, userID string, permissionKey string) (bool, error)

	// Bootstrap
	Bootstrap(ctx context.Context, superAdminEmail string) error
}
