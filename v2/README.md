# Auth v2 - Email Authentication with OTP & Password

A production-ready Go authentication library supporting two authentication methods:
- **OTP (One-Time Password)** via email
- **Email/Password** with secure password reset

## Features

✨ **Dual Authentication Methods**
- OTP-based authentication (6-digit codes, 5-minute expiry)
- Email/password authentication with bcrypt hashing
- Secure password reset tokens with CSPRN randomness

🔐 **Security**
- Bcrypt password hashing (configurable cost, default: cost 10)
- Password strength validation (uppercase, lowercase, digit, special char)
- Password reset tokens: 256-bit CSPRNG + SHA-256 hashing
- Atomic transactions for password updates and token management
- Token reuse prevention via atomic marking

👥 **User Management**
- User creation and authentication
- Direct & group-based permissions
- Permission resolution (direct + inherited from groups)
- Super admin bootstrap on startup

📧 **Email Integration**
- ZeptoMail integration for OTP and password reset emails
- Branded HTML email templates
- Configurable sender address

🗄️ **Database**
- PostgreSQL with pgx driver
- Embedded SQL migrations with checksum verification
- Schema management (create/drop)
- Automatic migration detection and rollback

🎫 **JWT Tokens**
- Access tokens (15 min expiry, includes permissions/groups)
- Refresh tokens (7 days expiry)
- HMAC-SHA256 signing

## Quick Start

### Installation

```bash
go get github.com/meikuraledutech/auth/v2@v2.0.0
```

### Basic Usage

```go
package main

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
	auth "github.com/meikuraledutech/auth/v2"
	"github.com/meikuraledutech/auth/v2/postgres"
	"github.com/meikuraledutech/auth/v2/zeptomail"
)

func main() {
	ctx := context.Background()

	// Connect to PostgreSQL
	pool, err := pgxpool.New(ctx, "postgresql://user:password@localhost/authdb")
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	// Create config
	cfg := auth.DefaultConfig("your-jwt-secret", "admin@example.com")

	// Create store and mailer
	store := postgres.New(pool, cfg)
	mailer := zeptomail.New("api-key", "noreply@example.com")

	// Bootstrap (runs migrations, seeds permissions, creates super admin)
	if err := store.Bootstrap(ctx, "admin@example.com"); err != nil {
		log.Fatal(err)
	}

	// Use store for authentication operations
	// (see examples below)
}
```

## Authentication Methods

### 1. OTP Authentication

**Create OTP:**
```go
otp, err := store.CreateOTP(ctx, "user@example.com")
if err != nil {
	log.Fatal(err)
}

// Send email
err = mailer.SendOTP(ctx, "user@example.com", otp.Code, cfg.OTPExpiry)
```

**Verify OTP:**
```go
user, err := store.VerifyOTP(ctx, "user@example.com", "123456")
if err != nil {
	// Handle ErrOTPInvalid, ErrOTPExpired
	log.Fatal(err)
}

// Auto-creates user if not exists
fmt.Printf("Logged in as: %s\n", user.ID)

// Generate JWT tokens
tokens, err := auth.GenerateTokenPair(cfg, user, permissions, groups)
```

### 2. Password Authentication

**Register with Password:**
```go
user, err := store.RegisterWithPassword(ctx, "user@example.com", "SecurePass123!")
if err != nil {
	// Handle ErrEmailAlreadyRegistered, ErrPasswordTooWeak
	log.Fatal(err)
}
```

**Login with Password:**
```go
user, err := store.LoginWithPassword(ctx, "user@example.com", "SecurePass123!")
if err != nil {
	// Handle ErrPasswordInvalid, ErrPasswordNotSet
	log.Fatal(err)
}

// Generate JWT tokens
tokens, err := auth.GenerateTokenPair(cfg, user, permissions, groups)
```

**Change Password:**
```go
err := store.ChangePassword(ctx, userID, "OldPassword123!", "NewPassword456!")
if err != nil {
	// Handle ErrPasswordInvalid, ErrPasswordTooWeak, ErrPasswordNotSet
	log.Fatal(err)
}
```

**Set Password (Admin Override):**
```go
err := store.SetPassword(ctx, userID, "AdminSetPassword123!")
if err != nil {
	log.Fatal(err)
}
```

**Check if User Has Password:**
```go
hasPassword, err := store.HasPassword(ctx, userID)
if !hasPassword {
	// OTP-only account
}
```

### 3. Password Reset Flow

**Step 1: Create Reset Token**
```go
rawToken, expiresAt, err := store.CreatePasswordReset(ctx, "user@example.com")
if err != nil {
	log.Fatal(err)
}

// Build reset URL with token
resetURL := fmt.Sprintf("https://example.com/reset?token=%s", rawToken)

// Send email
err = mailer.SendPasswordReset(ctx, "user@example.com", resetURL, cfg.PasswordResetExpiry)
```

**Step 2: Reset Password with Token**
```go
err := store.ResetPassword(ctx, rawToken, "NewPassword789!")
if err != nil {
	// Handle ErrResetTokenInvalid, ErrResetTokenUsed, ErrPasswordTooWeak
	log.Fatal(err)
}

// User can now login with new password
user, err := store.LoginWithPassword(ctx, "user@example.com", "NewPassword789!")
```

## Configuration

### Default Config

```go
cfg := auth.DefaultConfig(jwtSecret, superAdminEmail)

// Customize if needed
cfg.BcryptCost = 11              // Default: bcrypt.DefaultCost (10)
cfg.PasswordResetExpiry = 2*time.Hour // Default: 1 hour
cfg.MinPasswordLength = 10        // Default: 8
cfg.MaxPasswordLength = 72        // Default: 72 (bcrypt limit)
cfg.OTPLength = 8                 // Default: 6
cfg.OTPExpiry = 10*time.Minute   // Default: 5 minutes
cfg.AccessExpiry = 20*time.Minute // Default: 15 minutes
cfg.RefreshExpiry = 14*24*time.Hour // Default: 7 days
```

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/authdb

# JWT
JWT_SECRET=your-secret-key-min-32-chars

# Email (ZeptoMail)
ZEPTO_API_KEY=your-zeptomail-api-key
FROM_EMAIL=noreply@example.com

# Admin
SUPER_ADMIN_EMAIL=admin@example.com
```

## Permission & Group Management

### Permissions

**Create Permission:**
```go
perm, err := store.CreatePermission(ctx, "forms:create", "Can create forms")
```

**Assign to User:**
```go
err := store.AssignPermission(ctx, userID, "forms:create")
```

**Assign to Group:**
```go
err := store.AddPermissionToGroup(ctx, groupID, "forms:create")
```

**Check User Permission (with group inheritance):**
```go
hasAccess, err := store.HasResolvedPermission(ctx, userID, "forms:create")
```

### Groups

**Create Group:**
```go
group, err := store.CreateGroup(ctx, "Editors")
```

**Add User to Group:**
```go
err := store.AssignUserToGroup(ctx, userID, groupID)
```

**Add Permission to Group:**
```go
err := store.AddPermissionToGroup(ctx, groupID, "forms:edit")
```

## JWT Token Usage

### Validate Token

```go
claims, err := auth.ValidateToken(cfg, tokenString)
if err != nil {
	// Handle invalid/expired token
	log.Fatal(err)
}

// Access claims
fmt.Printf("User ID: %s\n", claims.UserID)
fmt.Printf("Email: %s\n", claims.Email)
fmt.Printf("Type: %s\n", claims.Type) // "access" or "refresh"
fmt.Printf("Permissions: %v\n", claims.Permissions)
fmt.Printf("Groups: %v\n", claims.Groups)
```

### Token Types

- **Access Token** (15 min default)
  - Contains: user_id, email, permissions, groups
  - Use for API requests
  - Embed permissions for authorization checks

- **Refresh Token** (7 days default)
  - Contains: user_id, email
  - Use to request new access token
  - Longer expiry for device persistence

## Database Schema

### Tables

**auth_users**
```sql
id           TEXT PRIMARY KEY
email        TEXT NOT NULL UNIQUE
password_hash TEXT -- NULL for OTP-only users
created_at   TIMESTAMPTZ DEFAULT NOW()
```

**auth_otps**
```sql
id         TEXT PRIMARY KEY
email      TEXT NOT NULL
code       TEXT NOT NULL
expires_at TIMESTAMPTZ NOT NULL
verified   BOOLEAN DEFAULT FALSE
created_at TIMESTAMPTZ DEFAULT NOW()
```

**auth_password_resets**
```sql
id         TEXT PRIMARY KEY
user_id    TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE
token_hash TEXT NOT NULL UNIQUE
expires_at TIMESTAMPTZ NOT NULL
used       BOOLEAN DEFAULT FALSE
created_at TIMESTAMPTZ DEFAULT NOW()
```

**auth_permissions**
```sql
id          TEXT PRIMARY KEY
key         TEXT NOT NULL UNIQUE (e.g., "forms:create")
description TEXT
created_at  TIMESTAMPTZ DEFAULT NOW()
```

**auth_user_permissions**
```sql
user_id       TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE
permission_id TEXT NOT NULL REFERENCES auth_permissions(id) ON DELETE CASCADE
PRIMARY KEY (user_id, permission_id)
```

**auth_groups**
```sql
id         TEXT PRIMARY KEY
name       TEXT NOT NULL UNIQUE
created_at TIMESTAMPTZ DEFAULT NOW()
```

**auth_group_permissions**
```sql
group_id      TEXT NOT NULL REFERENCES auth_groups(id) ON DELETE CASCADE
permission_id TEXT NOT NULL REFERENCES auth_permissions(id) ON DELETE CASCADE
PRIMARY KEY (group_id, permission_id)
```

**auth_user_groups**
```sql
user_id  TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE
group_id TEXT NOT NULL REFERENCES auth_groups(id) ON DELETE CASCADE
PRIMARY KEY (user_id, group_id)
```

**auth_migrations** (auto-created)
```sql
id         SERIAL PRIMARY KEY
name       TEXT NOT NULL UNIQUE
applied_at TIMESTAMPTZ DEFAULT NOW()
checksum   TEXT NOT NULL
```

## Error Handling

### Authentication Errors

```go
// OTP errors
auth.ErrOTPExpired           // OTP has expired
auth.ErrOTPInvalid           // Invalid OTP code

// Password errors
auth.ErrPasswordInvalid      // Wrong password
auth.ErrPasswordTooWeak      // Doesn't meet strength requirements
auth.ErrPasswordNotSet        // User has no password (OTP-only)
auth.ErrEmailAlreadyRegistered // Email already registered

// Reset token errors
auth.ErrResetTokenInvalid    // Token not found or expired
auth.ErrResetTokenUsed       // Token already used

// User errors
auth.ErrUserNotFound         // User not found

// Permission errors
auth.ErrPermissionNotFound   // Permission doesn't exist
auth.ErrPermissionExists     // Permission already exists

// Group errors
auth.ErrGroupNotFound        // Group doesn't exist
auth.ErrGroupExists          // Group already exists
```

### Example Error Handling

```go
user, err := store.LoginWithPassword(ctx, email, password)
if err != nil {
	switch err {
	case auth.ErrPasswordInvalid:
		// Wrong password
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	case auth.ErrPasswordNotSet:
		// User registered with OTP only
		http.Error(w, "User must login with OTP", http.StatusBadRequest)
	case auth.ErrUserNotFound:
		// No user with this email
		http.Error(w, "User not found", http.StatusNotFound)
	default:
		// Other errors
		http.Error(w, "Server error", http.StatusInternalServerError)
	}
	return
}

// Successfully logged in
```

## Security Considerations

### Password Security

- **Hashing**: bcrypt with configurable cost (default: cost 10)
- **Strength**: Enforces uppercase, lowercase, digit, special character
- **Length**: Configurable 8-72 chars (72 is bcrypt limit)
- **No plaintext**: Never stored in logs or returned to client

### Password Reset

- **Entropy**: 32-byte CSPRNG (256 bits)
- **Format**: Base64url encoded (43 characters)
- **Storage**: Only SHA-256 hash stored in DB
- **Token lifecycle**: Single-use, expires in 1 hour
- **Race condition prevention**: Atomic marking in transaction

### OTP Security

- **Code generation**: Cryptographically random
- **Expiration**: 5 minutes by default
- **Verification**: Marked as verified after successful use
- **Auto-creation**: User created automatically on first OTP verification

### JWT Tokens

- **Signing**: HMAC-SHA256
- **Secret**: Should be min 32 characters
- **Expiry**: Access (15 min) and Refresh (7 days)
- **Claims**: Include permissions for authorization checks

### Database Security

- **Cascading deletes**: Orphaned records removed automatically
- **Unique constraints**: Email, permission keys, group names
- **Indices**: Query optimization for common lookups
- **Transactions**: Password/token operations are atomic

## Migration from v1

v2 is backward compatible with v1 OTP flow. Key differences:

| Feature | v1 | v2 |
|---------|----|----|
| OTP Auth | ✅ | ✅ (unchanged) |
| Password Auth | ❌ | ✅ |
| Password Reset | ❌ | ✅ |
| Permission Model | ✅ | ✅ (same) |
| Database | ✅ | ✅ (added password columns) |

### Upgrade Path

1. Deploy v2 with AutoMigrate enabled
2. Migration 001 creates initial schema (same as v1)
3. Migration 002 adds password_hash column + password reset table
4. Existing OTP users continue to work
5. New users can register with password or OTP

No data loss - password_hash is nullable for existing OTP-only users.

## Testing

Run the included example:

```bash
cd v2/examples

# Set environment variables
export DATABASE_URL="postgresql://postgres:password@localhost:5432/authdb"
export JWT_SECRET="test-secret-key"
export ZEPTO_API_KEY="your-api-key"
export FROM_EMAIL="noreply@example.com"
export SUPER_ADMIN_EMAIL="admin@example.com"

# Run tests
go run main.go
```

Expected output:
```
=== Testing Auth v2 ===

1. Running migrations and bootstrap...
   ✓ Bootstrap complete

2. Creating OTP for test@example.com...
   ✓ OTP created: 123456

3. Sending OTP email...
   ✓ Email sent

4. Testing password auth...
   ✓ User registered
   ✓ Logged in

5. Testing password reset...
   ✓ Reset token created

6. Testing token generation...
   ✓ Access token generated
   ✓ Refresh token generated

=== All tests passed! ===
```

## API Reference

### Store Interface

See [STORE_API.md](./STORE_API.md) for complete interface documentation.

### Helper Functions

See [HELPERS.md](./HELPERS.md) for password and token helper functions.

## Contributing

Issues and pull requests welcome!

## License

MIT
