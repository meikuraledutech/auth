# Knowledge Transfer: auth/v2 — v2.0.3 to v2.1.1

**Date:** 2026-03-14
**Project:** meikuraledutech/auth (Go authentication library)
**Scope:** Complete v2 implementation overview, from email/password auth through organization-based permission model

---

## Executive Summary

The `github.com/meikuraledutech/auth/v2` package provides a comprehensive authentication and authorization system for Go applications. It supports:

- **OTP-based login** (email codes) — no password needed
- **Password-based login** — bcrypt hashing, strength validation, password reset
- **JWT tokens** — access (15 min) + refresh (7 days) with custom meta claims
- **Permission system** — direct + group-based + organization-based (3-part UNION)
- **Organizations** — 4 fixed roles (super_admin, trainer, college_admin, student) with base permissions
- **Bulk operations** — add/remove multiple users to groups in one call
- **Mailer interface** — decoupled email sending (app provides implementation via any provider)
- **Database migrations** — PostgreSQL via embedded SQL files
- **Idempotent bootstrap** — safe to call on every server start

---

## Repository Structure

```
auth/
├── v1/                              # Legacy v1 (OTP-only, separate module)
├── v2/                              # Current active development
│   ├── auth.go                      # Core types: User, OTP, Claims, Permission, Group, Organization, Config
│   ├── store.go                     # Store interface (38 methods) + Migrator interface
│   ├── mailer.go                    # Mailer interface (3 methods: SendOTP, SendPasswordReset, SendWelcome)
│   ├── token.go                     # JWT: GenerateTokenPair, RefreshTokenPair, ValidateToken
│   ├── password.go                  # Bcrypt helpers: HashPassword, CheckPassword, ValidatePasswordStrength, GenerateResetToken, HashResetToken
│   ├── postgres/
│   │   ├── postgres.go              # PGStore struct + New()
│   │   ├── user.go                  # CreateUser, GetUserByID, GetUserByEmail, ListUsers
│   │   ├── otp.go                   # CreateOTP, VerifyOTP
│   │   ├── password.go              # RegisterWithPassword, LoginWithPassword, SetPassword, ChangePassword, HasPassword, CreatePasswordReset, ResetPassword
│   │   ├── permission.go            # CreatePermission, GetPermission, ListPermissions, AssignPermission, RevokePermission, GetUserPermissions, HasPermission, GetResolvedPermissions, HasResolvedPermission
│   │   ├── group.go                 # CreateGroup, GetGroup, ListGroups, DeleteGroup, AddPermissionToGroup, RemovePermissionFromGroup, AssignUserToGroup, RemoveUserFromGroup, GetUserGroups, AddUsersToGroup, RemoveUsersFromGroup, GetGroupMembers
│   │   ├── organization.go          # CreateOrganizationWithPermissions, AssignPermissionsToOrganization, RemovePermissionsFromOrganization, GetOrganizationPermissions, ListOrganizations, GetOrganization, GetOrganizationByName, CreateUserWithOrganization, GetUserOrganization, GetAllUserPermissions, HasAnyPermission
│   │   ├── bootstrap.go             # Bootstrap: idempotent schema + permissions + organizations + super admin + password
│   │   ├── migrate.go               # Migrate, Rollback, MigrationStatus (embedded SQL file management)
│   │   ├── schema.go                # CreateSchema, DropSchema
│   │   └── migrations/
│   │       ├── 001_initial_schema.up.sql    # auth_users, auth_otps, auth_permissions, auth_groups, auth_user_permissions, auth_group_permissions, auth_user_groups
│   │       ├── 001_initial_schema.down.sql
│   │       ├── 002_password_auth.up.sql     # password_hash column on users, auth_password_resets table
│   │       ├── 002_password_auth.down.sql
│   │       ├── 003_organizations.up.sql     # auth_organizations, auth_organization_permissions, organization column on users
│   │       └── 003_organizations.down.sql
│   ├── examples/
│   │   ├── main.go                  # 14-test comprehensive example: orgs, users, bulk ops, permission inheritance
│   │   ├── go.mod                   # Points to local v2 via replace directive (dev only)
│   │   └── login_test/
│   │       └── main.go              # Password login test for super admin
│   └── go.mod
├── docs/
│   ├── README.md                    # Version index
│   ├── v2.0.3/mailing.md            # Mailer interface, SendWelcome, removed hardcoded zeptomail
│   ├── v2.0.4/refresh-token.md      # RefreshTokenPair helper
│   ├── v2.0.5/custom-claims.md      # Custom meta claims in JWT
│   ├── v2.1.0/organizations.md      # Organization-based permission model (14 new methods)
│   └── v2.1.1/super-admin-password.md  # Super admin password setup
├── VERSIONING.txt                   # Release rules, lessons learned, go.mod replace directive warning
├── KT.md                            # Overall project KT (from v2.0.0-v2.0.5 era)
└── KT_v2.1.0_to_v2.1.1.md          # This document
```

---

## Key Versions & Timeline

| Version | Date | What Changed |
|---------|------|-------------|
| v2.0.0-v2.0.2 | Early | Password auth baseline implementation (replaced hardcoded zeptomail) |
| v2.0.3 | - | Mailer interface decoupled; `SendWelcome` added; `v2/zeptomail` deleted |
| v2.0.4 | - | `RefreshTokenPair` helper (validates refresh token, fetches latest perms, issues new pair) |
| v2.0.5 | - | Custom meta claims in JWT (`GenerateTokenPair` accepts `map[string]any`) |
| v2.1.0 | 2026-03-14 | Organization-based permission model (14 new methods, 3-part permission UNION) |
| v2.1.1 | 2026-03-14 | Super admin password setup during bootstrap (bug fix) |

---

## Core Concepts

### 1. Authentication Methods

**OTP (One-Time Password)**
```go
otp, _ := store.CreateOTP(ctx, "user@example.com")        // 6-digit code, 5 min expiry
user, _ := store.VerifyOTP(ctx, "user@example.com", code) // Auto-creates user if new
```

**Password**
```go
user, _ := store.RegisterWithPassword(ctx, "user@example.com", "Password@123")
user, _ := store.LoginWithPassword(ctx, "user@example.com", "Password@123")
```

**Password Reset**
```go
rawToken, expiresAt, _ := store.CreatePasswordReset(ctx, "user@example.com")
resetURL := "https://yourapp.com/reset?token=" + rawToken
mailer.SendPasswordReset(ctx, email, resetURL, expiresAt-time.Now())
err := store.ResetPassword(ctx, rawToken, "NewPassword@123")
```

### 2. Permission Resolution (3-Part Union)

All three sources combined (DISTINCT, no duplicates):
```go
perms, _ := store.GetResolvedPermissions(ctx, userID)
// Returns: [org permissions] UNION [group permissions] UNION [direct permissions]

has, _ := store.HasResolvedPermission(ctx, userID, "forms:create")
// Checks all 3 sources

allPerms, _ := store.GetAllUserPermissions(ctx, userID)  // Alias for GetResolvedPermissions
hasAny, _ := store.HasAnyPermission(ctx, userID, []string{"forms:create", "forms:delete"})
// True if user has ANY of the given permission keys
```

### 3. Organizations (Role-Based)

Four fixed organizational roles with base permissions:
```go
// Bootstrap creates these automatically
super_admin:   {permissions:manage, groups:manage, users:manage, ...all other perms}
trainer:       {forms:create, users:manage, ...}
college_admin: {groups:manage, forms:create, ...}
student:       {forms:create, ...}

// Assign users to organizations (fixed, not flexible like groups)
user, _ := store.CreateUserWithOrganization(ctx, "trainer@example.com", "trainer")

// Users inherit all org permissions automatically
```

### 4. Groups (Team-Based, Dynamic)

Flexible group membership (users can be in multiple groups):
```go
group, _ := store.CreateGroup(ctx, "Batch-2024-Q1")
store.AddPermissionToGroup(ctx, group.ID, "forms:grade")
store.AddUsersToGroup(ctx, group.ID, []string{user1ID, user2ID, user3ID})  // Bulk add

members, _ := store.GetGroupMembers(ctx, group.ID)
```

### 5. JWT Tokens

```go
tokens, _ := auth.GenerateTokenPair(cfg, user, []string{"forms:create"}, []string{"group1", "group2"}, map[string]any{
    "college_id": "college-123",
    "batch_id":   "batch-2024",
})

// Access token (15 min): {user_id, email, type:"access", permissions, groups, custom meta}
// Refresh token (7 days): {user_id, email, type:"refresh"} — no perms/groups/meta

// Validate + refresh
claims, _ := auth.ValidateToken(cfg, accessToken)
newTokens, _ := auth.RefreshTokenPair(ctx, cfg, store, refreshToken)  // Fetches latest perms from DB
```

### 6. Custom Meta Claims

Embed arbitrary app-level context in JWT (e.g., organization, college_id, batch_id):
```go
meta := map[string]any{
    "organization": "trainer",
    "college_id": "clg_abc123",
    "batch_id": "batch_456",
}
tokens, _ := auth.GenerateTokenPair(cfg, user, perms, groups, meta)

// Frontend decodes token, reads meta.college_id — avoids DB call
claims, _ := auth.ValidateToken(cfg, token)
collegeID := claims.Meta["college_id"].(string)
```

---

## Database Schema (PostgreSQL)

### Tables

| Table | Purpose | Key Columns |
|-------|---------|-----------|
| `auth_users` | Users | `id TEXT PK`, `email TEXT UNIQUE`, `organization TEXT FK`, `password_hash TEXT` (nullable), `created_at TIMESTAMPTZ` |
| `auth_otps` | OTP codes | `id`, `email`, `code`, `expires_at`, `verified`, `created_at` |
| `auth_permissions` | Permission definitions | `id TEXT PK`, `key TEXT UNIQUE` (e.g. "forms:create"), `description`, `created_at` |
| `auth_user_permissions` | Direct user permissions | `user_id FK`, `permission_id FK`, `PK(user_id, permission_id)` |
| `auth_groups` | Groups/teams | `id TEXT PK`, `name TEXT UNIQUE`, `created_at` |
| `auth_group_permissions` | Permissions in groups | `group_id FK`, `permission_id FK`, `PK(group_id, permission_id)` |
| `auth_user_groups` | Group membership | `user_id FK`, `group_id FK`, `PK(user_id, group_id)` |
| `auth_organizations` | Organizations/roles | `id TEXT PK`, `name TEXT UNIQUE` (e.g. "trainer"), `created_at` |
| `auth_organization_permissions` | Organization base permissions | `organization_id FK`, `permission_id FK`, `PK(organization_id, permission_id)` |
| `auth_password_resets` | Password reset tokens | `id TEXT PK`, `user_id FK`, `token_hash TEXT UNIQUE` (SHA256), `expires_at`, `used BOOL`, `created_at` |
| `auth_migrations` | Migration tracking | `id SERIAL PK`, `name TEXT UNIQUE`, `applied_at TIMESTAMPTZ`, `checksum TEXT` (SHA256) |

### Migration System

- Files: `NNN_name.up.sql` and `NNN_name.down.sql` (embedded via `//go:embed`)
- Tracked in `auth_migrations` table (name, applied_at, checksum)
- Idempotent: `Migrate()` only applies unapplied migrations
- Checksum guard: detects SQL tampering (prevents accidental downgrades)

---

## Key Implementation Patterns

### Duplicate-Check Patterns (Not Uniform!)

| Operation | Strategy | Reason |
|-----------|----------|--------|
| `CreateUser` | `ON CONFLICT (email) DO NOTHING` + re-fetch | Idempotent |
| `CreatePermission` | Explicit `GetPermission` pre-check; return existing | Semantic "permission already exists" |
| `CreateGroup` | No conflict handling — raw INSERT, errors on duplicate | Assumes unique in-app constraint |
| `AssignPermission` | `ON CONFLICT DO NOTHING` | Idempotent |
| `AddPermissionToGroup` | `ON CONFLICT DO NOTHING` | Idempotent |
| `AssignUserToGroup` | `ON CONFLICT DO NOTHING` | Idempotent |

### "Not Found" Convention

All `Get*` methods return `nil, nil` (not an error) when the record doesn't exist. Callers must check for `nil`.

```go
user, err := store.GetUserByID(ctx, "invalid-id")
if err != nil {
    // Database error (connection issue, etc.)
}
if user == nil {
    // User not found (not an error condition)
}
```

### Error Wrapping

```go
fmt.Errorf("auth: <operation>: %w", err)
// Example: "auth: create user: connection refused"
```

### Permission Resolution SQL Pattern

3-part UNION inside a `WHERE p.id IN (...)` clause:
```sql
SELECT DISTINCT p.*
FROM auth_permissions p
WHERE p.id IN (
    SELECT permission_id FROM auth_user_permissions WHERE user_id = $1
    UNION
    SELECT gp.permission_id FROM auth_group_permissions gp
    JOIN auth_user_groups ug ON ug.group_id = gp.group_id
    WHERE ug.user_id = $1
    UNION
    SELECT op.permission_id FROM auth_organization_permissions op
    JOIN auth_organizations o ON o.id = op.organization_id
    WHERE o.name = (SELECT organization FROM auth_users WHERE id = $1)
)
ORDER BY p.key
```

---

## Bootstrap Flow (Idempotent)

```go
store.Bootstrap(ctx, "admin@example.com", "AdminPassword@123", map[string][]string{
    "super_admin":   {...55 perms...},
    "trainer":       {...18 perms...},
    "college_admin": {...5 perms...},
    "student":       {...5 perms...},
})
```

**Steps:**
1. Run migrations (if `AutoMigrate=true`)
2. Seed default permissions: `permissions:manage`, `groups:manage`, `users:manage`
3. Seed any additional permissions referenced in org maps
4. Create organizations with assigned permissions (via `CreateOrganizationWithPermissions`)
5. Create/fetch super admin user
6. **Set super admin password** (NEW in v2.1.1)
7. Assign all permissions to super admin

All steps are idempotent — calling bootstrap multiple times is safe.

---

## Mailer Interface (App-Provided)

The library defines what to send, app provides the implementation:

```go
type Mailer interface {
    SendOTP(ctx context.Context, email string, code string, expiresIn time.Duration) error
    SendPasswordReset(ctx context.Context, email string, resetURL string, expiresIn time.Duration) error
    SendWelcome(ctx context.Context, user *User) error
}
```

**App's responsibility:**
- Choose email provider (ZeptoMail, SES, SendGrid, etc.)
- Design email templates + branding
- Implement mailer with chosen provider
- Call `SendWelcome` at appropriate time (library never auto-triggers it)

**Example (v2.0.3+):**
```go
type SmartFormsMailer struct {
    sender mailing.Sender  // From github.com/meikuraledutech/mailing
    apiKey string
    fromEmail string
}

func (m *SmartFormsMailer) SendWelcome(ctx context.Context, user *auth.User) error {
    _, err := m.sender.Send(ctx, mailing.Mail{
        Token: m.apiKey,
        From: m.fromEmail,
        To: user.Email,
        Subject: "Welcome to Smart Forms!",
        HTML: "<h1>Welcome!</h1>...",
    })
    return err
}
```

---

## Common Gotchas & Lessons Learned

### 1. **Go Module Proxy & replace Directive**

⚠️ **CRITICAL:** Never include `replace github.com/meikuraledutech/auth/v2 => ../` in released code.

**What happened:**
- v2.0.0 tagged with replace directive in `examples/go.mod`
- Proxy tried to download module, but `../` doesn't exist in remote
- Error: "module found but does not contain package"

**Rule:** Remove replace directive before tagging; add it only for local development.

### 2. **User.Organization Field Persistence**

The `organization` column is nullable — existing users before v2.1.0 have `NULL` values. Backward compatible.

### 3. **Password Hash Cost**

Bcrypt cost is configurable (default 10). Higher = slower but more secure. Don't go below 10 for production.

### 4. **Reset Token Security**

- Raw token: 32-byte CSPRNG (256 bits) → base64url (43 chars)
- Stored: SHA256 hash only (never raw token in DB)
- Marked `used=TRUE` atomically with password update (prevents replay)

### 5. **RefreshTokenPair Always Fetches Latest**

`RefreshTokenPair` queries the DB for latest permissions + groups every time. If a user's permissions change, the next refresh reflects it (not after the access token expires).

### 6. **Mailer is Not Auto-Called**

Library calls `SendOTP` and `SendPasswordReset` internally, but **never** calls `SendWelcome`. App must call it at the right time (after registration? after email verification? business decision).

### 7. **Organization is Fixed, Group is Flexible**

- **Organization:** User assigned once at creation; one per user; base permissions tied to role
- **Group:** User can join multiple; dynamic; additional permissions per group

---

## Migration Guide: v2.0.5 → v2.1.0

1. **Add `.env` variable:** `SUPER_ADMIN_PASSWORD=YourPassword@123`
2. **Update Bootstrap call signature:**
   ```go
   // Old
   store.Bootstrap(ctx, "admin@example.com")

   // New
   store.Bootstrap(ctx, "admin@example.com", "SuperAdmin@123", orgsMap)
   ```
3. **Run migrations** (automatic if `AutoMigrate=true`)
4. **Bootstrap creates 4 organizations** with permissions
5. **Users now have `organization` field** (nullable, backward compatible)
6. **Permission checks now include org permissions** (3-part UNION)

---

## Testing & Examples

### Main Test (14 scenarios)
```bash
env $(cat .env | xargs) go run examples/main.go
```

Tests:
1. Bootstrap + schema creation
2. List organizations
3. Organization with permissions
4. Create users with different orgs
5. Super admin has all permissions
6. Permission inheritance from org
7. Unauthorized access blocking (negative tests)
8. HasAnyPermission (multiple keys)
9. GetAllUserPermissions (3-part union)
10. Bulk group operations (add/remove/list)
11. User.Organization persisted
12. Backward compatibility (user without org)
13. Invalid organization rejection
14. Remove users from group

### Login Test
```bash
env $(cat .env | xargs) go run examples/login_test/main.go
```

Verifies:
- Super admin password login works
- Permissions loaded correctly
- Wrong password rejected

---

## Future Work

- **v2.2.0:** Token blacklisting (revoke tokens immediately)
- Enhanced audit logging
- Rate limiting on OTP/password attempts
- User roles vs. organizations clarification
- API endpoint examples (Fiber, Echo, Chi)

---

## Environment Variables

```env
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/auth_v2

# JWT
JWT_SECRET=your-secret-key-min-32-chars

# Email (optional)
ZEPTO_API_KEY=...
ZEPTO_API_URL=https://api.zeptomail.in/v1.1/email
ZEPTO_PROVIDER=zeptomail
FROM_EMAIL=noreply@yourapp.com

# Bootstrap
SUPER_ADMIN_EMAIL=admin@yourapp.com
SUPER_ADMIN_PASSWORD=YourPassword@123
```

---

## References

- **Code:** `/Users/dharanigowtham/Development/go-packs/auth/v2/`
- **Docs:** `/Users/dharanigowtham/Development/go-packs/auth/docs/`
- **Versions:** v2.0.3, v2.0.4, v2.0.5, v2.1.0, v2.1.1
- **Go Module:** `github.com/meikuraledutech/auth/v2`
- **Mailing Package:** `github.com/meikuraledutech/mailing@v0.0.1` (separate)

---

## Contact & Support

For questions or issues:
- Check the docs in `/docs/vX.Y.Z/`
- Review example code in `/v2/examples/`
- Check VERSIONING.txt for release lessons learned

---

**Document created:** 2026-03-14
**Scope:** Complete v2 implementation — v2.0.3 through v2.1.1
