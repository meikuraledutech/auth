# auth

Go package for **OTP email authentication** with **JWT tokens** and **permission-based access control**.

Interface-driven — swap the database or email provider without changing your app code.

## Install

```bash
go get github.com/meikuraledutech/auth
```

## Interfaces

### Store

Database operations. The `postgres` subpackage provides a production-ready implementation.

```go
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
```

### Mailer

Email delivery. The `zeptomail` subpackage provides a ZeptoMail implementation.

```go
type Mailer interface {
    SendOTP(ctx context.Context, email string, code string, expiresIn time.Duration) error
}
```

## Quick Start

```go
pool, _ := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
cfg := auth.DefaultConfig("jwt-secret", "admin@example.com")

var store auth.Store = postgres.New(pool, cfg)
var mailer auth.Mailer = zeptomail.New("zepto-key", "noreply@example.com")

// Bootstrap (creates tables + seeds super admin)
store.Bootstrap(ctx, "admin@example.com")

// OTP flow
otp, _ := store.CreateOTP(ctx, "user@example.com")
mailer.SendOTP(ctx, "user@example.com", otp.Code, cfg.OTPExpiry)
user, _ := store.VerifyOTP(ctx, "user@example.com", otp.Code)

// Permissions
store.CreatePermission(ctx, "forms:create", "Can create forms")
store.AssignPermission(ctx, user.ID, "forms:create")

// Groups
group, _ := store.CreateGroup(ctx, "Editor")
store.AddPermissionToGroup(ctx, group.ID, "forms:create")
store.AssignUserToGroup(ctx, user.ID, group.ID)

// JWT tokens with embedded permissions and groups
perms, _ := store.GetResolvedPermissions(ctx, user.ID)
permKeys := []string{}
for _, p := range perms {
    permKeys = append(permKeys, p.Key)
}

groups, _ := store.GetUserGroups(ctx, user.ID)
groupNames := []string{}
for _, g := range groups {
    groupNames = append(groupNames, g.Name)
}

tokens, _ := auth.GenerateTokenPair(cfg, user, permKeys, groupNames)

// Validate token (permissions and groups are embedded)
claims, _ := auth.ValidateToken(cfg, tokens.AccessToken)
// claims.Permissions = ["forms:create", ...]
// claims.Groups = ["Editor", ...]
```

## Structs

```go
type User struct {
    ID        string    `json:"id"`
    Email     string    `json:"email"`
    CreatedAt time.Time `json:"created_at"`
}

type Permission struct {
    ID          string    `json:"id"`
    Key         string    `json:"key"`         // "forms:create"
    Description string    `json:"description"`
    CreatedAt   time.Time `json:"created_at"`
}

type Group struct {
    ID          string       `json:"id"`
    Name        string       `json:"name"`
    Permissions []Permission `json:"permissions,omitempty"`
    CreatedAt   time.Time    `json:"created_at"`
}

type TokenPair struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
}

type Claims struct {
    UserID      string   `json:"user_id"`
    Email       string   `json:"email"`
    Type        string   `json:"type"` // "access" or "refresh"
    Permissions []string `json:"permissions,omitempty"` // embedded in access token
    Groups      []string `json:"groups,omitempty"`      // group names, embedded in access token
}
```

## Errors

```go
auth.ErrOTPExpired         // OTP has expired
auth.ErrOTPInvalid         // Wrong code or no OTP exists
auth.ErrUserNotFound       // User not found
auth.ErrPermissionNotFound // Permission key doesn't exist
auth.ErrPermissionExists   // Permission key already exists
auth.ErrGroupNotFound      // Group doesn't exist
auth.ErrGroupExists        // Group name already exists
```

## Config

```go
cfg := auth.DefaultConfig(jwtSecret, superAdminEmail)
// OTPLength:     6
// OTPExpiry:     5 minutes
// AccessExpiry:  15 minutes
// RefreshExpiry: 7 days
```

## Examples

The `server/` directory contains a Fiber HTTP server example with 21 endpoints.
The `example/` directory contains a programmatic usage example.

## License

MIT License - see [LICENSE](LICENSE) for details.
