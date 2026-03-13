package auth

import (
	"context"
	"errors"
	"time"
)

var (
	ErrOTPExpired           = errors.New("auth: otp has expired")
	ErrOTPInvalid           = errors.New("auth: invalid otp code")
	ErrUserNotFound         = errors.New("auth: user not found")
	ErrPermissionNotFound   = errors.New("auth: permission not found")
	ErrPermissionExists     = errors.New("auth: permission already exists")
	ErrGroupNotFound        = errors.New("auth: group not found")
	ErrGroupExists          = errors.New("auth: group already exists")
	ErrPasswordInvalid        = errors.New("auth: invalid password")
	ErrPasswordTooWeak        = errors.New("auth: password does not meet strength requirements")
	ErrPasswordNotSet         = errors.New("auth: user has no password set")
	ErrEmailAlreadyRegistered = errors.New("auth: email is already registered")
	ErrResetTokenInvalid    = errors.New("auth: invalid or expired password reset token")
	ErrResetTokenUsed       = errors.New("auth: password reset token has already been used")
	ErrOrganizationNotFound  = errors.New("auth: organization not found")
	ErrOrganizationExists    = errors.New("auth: organization already exists")
	ErrInvalidOrganization   = errors.New("auth: invalid organization")
	ErrGroupMembershipFailed = errors.New("auth: failed to update group membership")
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

	// Resolved Permissions (direct + from groups + from organizations)
	GetResolvedPermissions(ctx context.Context, userID string) ([]Permission, error)
	HasResolvedPermission(ctx context.Context, userID string, permissionKey string) (bool, error)

	// Organizations
	CreateOrganizationWithPermissions(ctx context.Context, name string, permissionKeys []string) (*Organization, error)
	AssignPermissionsToOrganization(ctx context.Context, orgID string, permissionKeys []string) error
	RemovePermissionsFromOrganization(ctx context.Context, orgID string, permissionKeys []string) error
	GetOrganizationPermissions(ctx context.Context, orgID string) ([]Permission, error)
	ListOrganizations(ctx context.Context) ([]Organization, error)
	GetOrganization(ctx context.Context, id string) (*Organization, error)
	GetOrganizationByName(ctx context.Context, name string) (*Organization, error)

	// User-Organization
	CreateUserWithOrganization(ctx context.Context, email string, organization string) (*User, error)
	GetUserOrganization(ctx context.Context, userID string) (string, error)

	// Enhanced Permission Resolution
	GetAllUserPermissions(ctx context.Context, userID string) ([]Permission, error)
	HasAnyPermission(ctx context.Context, userID string, permissionKeys []string) (bool, error)

	// Bulk Group Operations
	AddUsersToGroup(ctx context.Context, groupID string, userIDs []string) error
	RemoveUsersFromGroup(ctx context.Context, groupID string, userIDs []string) error
	GetGroupMembers(ctx context.Context, groupID string) ([]User, error)

	// Bootstrap
	Bootstrap(ctx context.Context, superAdminEmail string, organizations ...map[string][]string) error

	// Password Auth
	RegisterWithPassword(ctx context.Context, email string, plainPassword string) (*User, error)
	LoginWithPassword(ctx context.Context, email string, plainPassword string) (*User, error)
	SetPassword(ctx context.Context, userID string, plainPassword string) error
	ChangePassword(ctx context.Context, userID string, currentPassword string, newPassword string) error
	HasPassword(ctx context.Context, userID string) (bool, error)
	CreatePasswordReset(ctx context.Context, email string) (rawToken string, expiresAt time.Time, err error)
	ResetPassword(ctx context.Context, rawToken string, newPassword string) error
}

// Migrator defines the contract for managing database migrations.
type Migrator interface {
	// Migrate applies all pending migrations in order.
	Migrate(ctx context.Context) error

	// Rollback rolls back the last applied migration.
	Rollback(ctx context.Context) error

	// MigrationStatus returns all migrations with their applied status.
	MigrationStatus(ctx context.Context) ([]MigrationRecord, error)
}
