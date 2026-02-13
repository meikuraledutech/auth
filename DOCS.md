# Auth Package Reference

Go package for **OTP email authentication with JWT tokens and permission-based access control**.

Two interfaces: `Store` (database) and `Mailer` (email). Implement them to use any backend.

## Package Structure

```
auth              — structs, interfaces, JWT helpers, errors
auth/postgres     — PostgreSQL implementation of Store
auth/zeptomail    — ZeptoMail implementation of Mailer
auth/server       — example Fiber HTTP server (not part of the package API)
auth/example      — example programmatic usage
```

## Store Interface

28 methods across 8 groups.

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

### Method Details

**CreateSchema** — Creates 7 tables with indexes. `IF NOT EXISTS`, safe to call repeatedly.

**DropSchema** — Drops all tables with `CASCADE`. Destructive.

**CreateOTP** — Generates cryptographically random numeric code, stores with expiry. Returns `*OTP` including the code.

**VerifyOTP** — Finds latest unverified OTP for email, validates code + expiry, marks verified, finds-or-creates user (auto-signup). Returns `*User`.

**CreateUser** — Creates user with `ON CONFLICT DO NOTHING`. Idempotent.

**CreatePermission** — Idempotent. Returns existing permission if key already exists.

**AssignPermission / RevokePermission** — Direct user-permission assignment. Idempotent.

**HasPermission** — Checks direct permissions only.

**GetGroup** — Returns group with its permissions populated.

**AddPermissionToGroup** — Idempotent. Looks up permission by key.

**AssignUserToGroup / RemoveUserFromGroup** — Idempotent.

**GetResolvedPermissions** — Returns all permissions (direct + inherited from groups), deduplicated.

**HasResolvedPermission** — Checks both direct and group permissions. **Use this for authorization checks.**

**Bootstrap** — Creates schema, seeds default permissions (`permissions:manage`, `groups:manage`, `users:manage`), ensures super admin user exists with all permissions. Idempotent, safe on every server start.

## Mailer Interface

```go
type Mailer interface {
    SendOTP(ctx context.Context, email string, code string, expiresIn time.Duration) error
}
```

Implement this to use any email provider.

## JWT Helpers

```go
// Creates access token (short-lived) + refresh token (long-lived)
// Permissions and groups are embedded in the access token for zero-DB-query authorization
auth.GenerateTokenPair(cfg, user, permissions, groups) (*TokenPair, error)

// Parses and validates JWT, returns claims
// For access tokens, claims.Permissions and claims.Groups contain the embedded data
auth.ValidateToken(cfg, tokenStr) (*Claims, error)
```

Both use HMAC-SHA256 signing. Permissions and groups are only embedded in access tokens (not refresh tokens).

## Types

**User** — `ID`, `Email`, `CreatedAt`

**OTP** — `ID`, `Email`, `Code`, `ExpiresAt`, `Verified`, `CreatedAt`

**Permission** — `ID`, `Key` (e.g. `"forms:create"`), `Description`, `CreatedAt`

**Group** — `ID`, `Name`, `Permissions` (populated on `GetGroup`), `CreatedAt`

**TokenPair** — `AccessToken`, `RefreshToken`

**Claims** — `UserID`, `Email`, `Type` (`"access"` or `"refresh"`), `Permissions` (permission keys, only in access tokens), `Groups` (group names, only in access tokens)

**Config** — `JWTSecret`, `OTPLength` (6), `OTPExpiry` (5m), `AccessExpiry` (15m), `RefreshExpiry` (7d), `SuperAdminEmail`

## Errors

| Error | When |
|-------|------|
| `ErrOTPExpired` | OTP past expiry time |
| `ErrOTPInvalid` | Wrong code or no OTP exists |
| `ErrUserNotFound` | User not found |
| `ErrPermissionNotFound` | Permission key doesn't exist |
| `ErrPermissionExists` | Permission key already exists |
| `ErrGroupNotFound` | Group doesn't exist |
| `ErrGroupExists` | Group name already exists |

## Database Schema

7 tables: `auth_users`, `auth_otps`, `auth_permissions`, `auth_user_permissions`, `auth_groups`, `auth_group_permissions`, `auth_user_groups`.

Foreign keys with cascade deletes. Indexes on all lookup columns.

## Permission Model

Use `resource:action` naming: `forms:create`, `billing:manage`, `users:invite`.

Resolved permissions = direct + inherited from groups. Always check with `HasResolvedPermission`.

## Bootstrap

On app start, call `store.Bootstrap(ctx, superAdminEmail)`:

1. Creates all tables
2. Seeds 3 default permissions
3. Creates super admin user with all permissions

Super admin logs in via OTP like everyone else — they just have all permissions pre-assigned.

## Implementations

**PostgreSQL**: `postgres.New(pool, cfg)` — pool is `*pgxpool.Pool`

**ZeptoMail**: `zeptomail.New(apiKey, fromEmail)` — sends branded HTML OTP emails
