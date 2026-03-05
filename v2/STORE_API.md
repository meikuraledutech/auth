# Store API Reference

The `Store` interface defines all authentication operations. Implement this interface to provide auth functionality with any backend.

## Schema Management

### CreateSchema

```go
CreateSchema(ctx context.Context) error
```

Applies all pending database migrations. Equivalent to `Migrate()`.

**Usage:**
```go
err := store.CreateSchema(ctx)
if err != nil {
	log.Fatal(err)
}
```

**Returns:**
- `nil` on success
- Error if migration fails

---

### DropSchema

```go
DropSchema(ctx context.Context) error
```

Drops all auth tables (users, otps, permissions, groups, password_resets, migrations). **Use with caution** - irreversible without backups.

**Usage:**
```go
err := store.DropSchema(ctx)
if err != nil {
	log.Fatal(err)
}
```

---

## OTP Authentication

### CreateOTP

```go
CreateOTP(ctx context.Context, email string) (*OTP, error)
```

Generates a 6-digit OTP code and stores it for the given email. The code expires in 5 minutes (configurable).

**Parameters:**
- `email` - User's email address

**Returns:**
- `*OTP` - Contains ID, email, code, expiresAt, verified status, createdAt
- Error if insertion fails

**Example:**
```go
otp, err := store.CreateOTP(ctx, "user@example.com")
if err != nil {
	log.Fatal(err)
}

// otp.Code = "123456"
// otp.ExpiresAt = time.Now().Add(5 * time.Minute)
```

**Errors:**
- Generic database errors

---

### VerifyOTP

```go
VerifyOTP(ctx context.Context, email string, code string) (*User, error)
```

Validates OTP code for email. Auto-creates user if not exists. Marks OTP as verified.

**Parameters:**
- `email` - User's email
- `code` - 6-digit code to verify

**Returns:**
- `*User` - Authenticated user (auto-created if needed)
- `ErrOTPInvalid` - Code doesn't match or no pending OTP
- `ErrOTPExpired` - OTP has expired

**Example:**
```go
user, err := store.VerifyOTP(ctx, "user@example.com", "123456")
if err != nil {
	switch err {
	case auth.ErrOTPInvalid:
		log.Println("Wrong code")
	case auth.ErrOTPExpired:
		log.Println("Code expired, request new OTP")
	default:
		log.Fatal(err)
	}
	return
}

// user.ID, user.Email populated
// Can now generate JWT tokens
```

---

## User Management

### CreateUser

```go
CreateUser(ctx context.Context, email string) (*User, error)
```

Creates a new user with the given email. Returns existing user if email already registered.

**Parameters:**
- `email` - User's email (unique)

**Returns:**
- `*User` - Created or existing user
- Error on database issues

**Example:**
```go
user, err := store.CreateUser(ctx, "newuser@example.com")
if err != nil {
	log.Fatal(err)
}

// user.ID auto-generated UUID
// user.Email = "newuser@example.com"
// user.CreatedAt = current timestamp
```

---

### GetUserByID

```go
GetUserByID(ctx context.Context, id string) (*User, error)
```

Fetches user by ID. Returns nil if not found (not an error).

**Parameters:**
- `id` - UUID of user

**Returns:**
- `*User` - User object, or nil if not found
- Error only on database issues

**Example:**
```go
user, err := store.GetUserByID(ctx, "550e8400-e29b-41d4-a716-446655440000")
if err != nil {
	log.Fatal(err)
}

if user == nil {
	log.Println("User not found")
	return
}

log.Printf("Found: %s\n", user.Email)
```

---

### GetUserByEmail

```go
GetUserByEmail(ctx context.Context, email string) (*User, error)
```

Fetches user by email. Returns nil if not found (not an error).

**Parameters:**
- `email` - User's email address

**Returns:**
- `*User` - User object, or nil if not found
- Error only on database issues

**Example:**
```go
user, err := store.GetUserByEmail(ctx, "user@example.com")
if user == nil && err == nil {
	log.Println("User doesn't exist")
	return
}
if err != nil {
	log.Fatal(err)
}

// user found
```

---

### ListUsers

```go
ListUsers(ctx context.Context) ([]User, error)
```

Returns all users ordered by creation date.

**Returns:**
- `[]User` - All users (empty slice if none)
- Error on database issues

**Example:**
```go
users, err := store.ListUsers(ctx)
if err != nil {
	log.Fatal(err)
}

for _, user := range users {
	fmt.Printf("%s - %s\n", user.ID, user.Email)
}
```

---

## Password Authentication

### RegisterWithPassword

```go
RegisterWithPassword(ctx context.Context, email string, plainPassword string) (*User, error)
```

Creates a new user and sets their password. Password is validated and hashed with bcrypt.

**Parameters:**
- `email` - User's email (must be unique)
- `plainPassword` - Plain text password to hash

**Returns:**
- `*User` - Created user
- `ErrEmailAlreadyRegistered` - Email already in use
- `ErrPasswordTooWeak` - Password doesn't meet strength requirements
- Other errors on database issues

**Password Requirements:**
- Length: 8-72 characters
- Must contain: uppercase, lowercase, digit, special character

**Example:**
```go
user, err := store.RegisterWithPassword(ctx, "newuser@example.com", "MySecure123@Pass")
if err != nil {
	switch err {
	case auth.ErrEmailAlreadyRegistered:
		http.Error(w, "Email already registered", http.StatusConflict)
	case auth.ErrPasswordTooWeak:
		http.Error(w, "Password doesn't meet requirements", http.StatusBadRequest)
	default:
		http.Error(w, "Server error", http.StatusInternalServerError)
	}
	return
}

// user.ID auto-generated, user.Email set
// Password is hashed and stored securely
```

---

### LoginWithPassword

```go
LoginWithPassword(ctx context.Context, email string, plainPassword string) (*User, error)
```

Authenticates user by email and password. Returns user if credentials valid.

**Parameters:**
- `email` - User's email
- `plainPassword` - Plain text password to verify

**Returns:**
- `*User` - Authenticated user
- `ErrPasswordInvalid` - Wrong password or user not found
- `ErrPasswordNotSet` - User exists but has no password (OTP-only)
- Other errors on database issues

**Example:**
```go
user, err := store.LoginWithPassword(ctx, "user@example.com", "MySecure123@Pass")
if err != nil {
	switch err {
	case auth.ErrPasswordInvalid:
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	case auth.ErrPasswordNotSet:
		http.Error(w, "User registered with OTP only", http.StatusBadRequest)
	default:
		http.Error(w, "Server error", http.StatusInternalServerError)
	}
	return
}

// user authenticated
// Generate JWT tokens
tokens, _ := auth.GenerateTokenPair(cfg, user, perms, groups)
```

---

### SetPassword

```go
SetPassword(ctx context.Context, userID string, plainPassword string) error
```

Admin operation to set/override a user's password. Validates strength.

**Parameters:**
- `userID` - User's ID
- `plainPassword` - New password to set

**Returns:**
- `nil` on success
- `ErrUserNotFound` - User doesn't exist
- `ErrPasswordTooWeak` - Password invalid
- Other errors on database issues

**Example:**
```go
// Admin setting password for user
err := store.SetPassword(ctx, userID, "AdminSet123@Pass")
if err == auth.ErrUserNotFound {
	log.Println("User not found")
	return
}
if err != nil {
	log.Fatal(err)
}

log.Println("Password set successfully")
```

---

### ChangePassword

```go
ChangePassword(ctx context.Context, userID string, currentPassword string, newPassword string) error
```

User-initiated password change. Verifies current password before updating.

**Parameters:**
- `userID` - User's ID
- `currentPassword` - Current password (to verify user)
- `newPassword` - New password to set

**Returns:**
- `nil` on success
- `ErrPasswordNotSet` - User has no password (OTP-only)
- `ErrPasswordInvalid` - Current password wrong
- `ErrPasswordTooWeak` - New password invalid
- Other errors on database issues

**Example:**
```go
err := store.ChangePassword(ctx, userID, "Old123@Pass", "New456@Pass")
if err != nil {
	switch err {
	case auth.ErrPasswordInvalid:
		http.Error(w, "Current password incorrect", http.StatusUnauthorized)
	case auth.ErrPasswordTooWeak:
		http.Error(w, "New password too weak", http.StatusBadRequest)
	case auth.ErrPasswordNotSet:
		http.Error(w, "User has no password set", http.StatusBadRequest)
	default:
		http.Error(w, "Server error", http.StatusInternalServerError)
	}
	return
}

log.Println("Password changed")
```

---

### HasPassword

```go
HasPassword(ctx context.Context, userID string) (bool, error)
```

Checks if user has a password set (vs OTP-only).

**Parameters:**
- `userID` - User's ID

**Returns:**
- `true` - User has password
- `false` - User is OTP-only (no password)
- Error on database issues or user not found

**Example:**
```go
hasPassword, err := store.HasPassword(ctx, userID)
if err != nil {
	log.Fatal(err)
}

if hasPassword {
	log.Println("User can login with password")
} else {
	log.Println("User must login with OTP")
}
```

---

## Password Reset

### CreatePasswordReset

```go
CreatePasswordReset(ctx context.Context, email string) (rawToken string, expiresAt time.Time, err error)
```

Generates a password reset token for the given email. Invalidates previous unused tokens.

**Parameters:**
- `email` - User's email address

**Returns:**
- `rawToken` - Base64url-encoded token (43 chars) - for reset link
- `expiresAt` - Token expiration timestamp
- Error on database issues or user not found

**Security Notes:**
- Token is 32-byte CSPRNG (256 bits entropy)
- Only hash is stored in DB, not the raw token
- Old unused tokens marked as used when new one created
- Returns nil token if email not found (security: doesn't reveal if email registered)

**Example:**
```go
rawToken, expiresAt, err := store.CreatePasswordReset(ctx, "user@example.com")
if err != nil {
	log.Fatal(err)
}

// rawToken is single-use, non-reversible to retrieve
// Build reset URL
resetURL := fmt.Sprintf("https://example.com/reset?token=%s", rawToken)

// Send email with URL
err = mailer.SendPasswordReset(ctx, "user@example.com", resetURL, cfg.PasswordResetExpiry)

log.Printf("Reset link valid until: %s\n", expiresAt.Format(time.RFC3339))
```

---

### ResetPassword

```go
ResetPassword(ctx context.Context, rawToken string, newPassword string) error
```

Validates reset token and updates user's password. Marks token as used atomically.

**Parameters:**
- `rawToken` - Base64url token from CreatePasswordReset
- `newPassword` - New password to set

**Returns:**
- `nil` on success
- `ErrResetTokenInvalid` - Token not found or expired
- `ErrResetTokenUsed` - Token already used
- `ErrPasswordTooWeak` - New password invalid
- Other errors on database issues

**Example:**
```go
err := store.ResetPassword(ctx, rawToken, "NewPassword789!")
if err != nil {
	switch err {
	case auth.ErrResetTokenInvalid:
		http.Error(w, "Reset link expired or invalid", http.StatusBadRequest)
	case auth.ErrResetTokenUsed:
		http.Error(w, "Reset link already used", http.StatusBadRequest)
	case auth.ErrPasswordTooWeak:
		http.Error(w, "Password doesn't meet requirements", http.StatusBadRequest)
	default:
		http.Error(w, "Server error", http.StatusInternalServerError)
	}
	return
}

log.Println("Password reset successfully")
// User can now login with new password
```

---

## Permission Management

### CreatePermission

```go
CreatePermission(ctx context.Context, key string, description string) (*Permission, error)
```

Creates a new permission. If already exists, returns existing permission (idempotent).

**Parameters:**
- `key` - Permission identifier (e.g., "forms:create")
- `description` - Human-readable description

**Returns:**
- `*Permission` - Created or existing permission
- Error on database issues

**Example:**
```go
perm, err := store.CreatePermission(ctx, "forms:create", "Can create forms")
if err != nil {
	log.Fatal(err)
}

// perm.ID auto-generated
// perm.Key = "forms:create"
```

---

### GetPermission

```go
GetPermission(ctx context.Context, key string) (*Permission, error)
```

Fetches permission by key. Returns nil if not found (not an error).

**Parameters:**
- `key` - Permission key (e.g., "forms:create")

**Returns:**
- `*Permission` - Permission object, or nil if not found
- Error only on database issues

**Example:**
```go
perm, err := store.GetPermission(ctx, "forms:delete")
if perm == nil {
	log.Println("Permission not found")
	return
}
```

---

### ListPermissions

```go
ListPermissions(ctx context.Context) ([]Permission, error)
```

Returns all permissions ordered by key.

**Returns:**
- `[]Permission` - All permissions (empty if none)
- Error on database issues

---

### DeletePermission

```go
DeletePermission(ctx context.Context, id string) error
```

Deletes a permission by ID. Cascades to remove from users and groups.

**Parameters:**
- `id` - Permission ID

**Returns:**
- `nil` on success
- Error on database issues

---

### AssignPermission

```go
AssignPermission(ctx context.Context, userID string, permissionKey string) error
```

Assigns a permission directly to a user.

**Parameters:**
- `userID` - User's ID
- `permissionKey` - Permission key (e.g., "forms:create")

**Returns:**
- `nil` on success
- `ErrPermissionNotFound` - Permission doesn't exist
- Error on database issues

**Example:**
```go
err := store.AssignPermission(ctx, userID, "forms:create")
if err == auth.ErrPermissionNotFound {
	log.Println("Permission not found")
	return
}
if err != nil {
	log.Fatal(err)
}
```

---

### RevokePermission

```go
RevokePermission(ctx context.Context, userID string, permissionKey string) error
```

Removes a direct permission from a user (doesn't affect group permissions).

**Parameters:**
- `userID` - User's ID
- `permissionKey` - Permission key

**Returns:**
- `nil` on success
- `ErrPermissionNotFound` - Permission doesn't exist
- Error on database issues

---

### GetUserPermissions

```go
GetUserPermissions(ctx context.Context, userID string) ([]Permission, error)
```

Returns direct permissions assigned to user (not group permissions).

**Parameters:**
- `userID` - User's ID

**Returns:**
- `[]Permission` - User's direct permissions (empty if none)
- Error on database issues

---

### HasPermission

```go
HasPermission(ctx context.Context, userID string, permissionKey string) (bool, error)
```

Checks if user has direct permission (not from groups).

**Parameters:**
- `userID` - User's ID
- `permissionKey` - Permission key

**Returns:**
- `true` - User has permission
- `false` - User doesn't have permission
- Error on database issues

---

### GetResolvedPermissions

```go
GetResolvedPermissions(ctx context.Context, userID string) ([]Permission, error)
```

Returns all permissions (direct + inherited from groups), deduplicated.

**Parameters:**
- `userID` - User's ID

**Returns:**
- `[]Permission` - Combined direct and group permissions
- Error on database issues

**Example:**
```go
allPerms, err := store.GetResolvedPermissions(ctx, userID)
if err != nil {
	log.Fatal(err)
}

// allPerms includes both direct and group-based permissions
```

---

### HasResolvedPermission

```go
HasResolvedPermission(ctx context.Context, userID string, permissionKey string) (bool, error)
```

Checks if user has permission via direct or group assignment.

**Parameters:**
- `userID` - User's ID
- `permissionKey` - Permission key

**Returns:**
- `true` - User has permission (direct or via group)
- `false` - User doesn't have permission
- Error on database issues

**Example:**
```go
canCreate, err := store.HasResolvedPermission(ctx, userID, "forms:create")
if err != nil {
	log.Fatal(err)
}

if canCreate {
	// Allow user to create forms
} else {
	http.Error(w, "Forbidden", http.StatusForbidden)
}
```

---

## Group Management

### CreateGroup

```go
CreateGroup(ctx context.Context, name string) (*Group, error)
```

Creates a new permission group.

**Parameters:**
- `name` - Group name (e.g., "Editors")

**Returns:**
- `*Group` - Created group
- Error on database issues

**Example:**
```go
group, err := store.CreateGroup(ctx, "Admins")
if err != nil {
	log.Fatal(err)
}

// group.ID auto-generated
// group.Permissions = []Permission{} initially
```

---

### GetGroup

```go
GetGroup(ctx context.Context, id string) (*Group, error)
```

Fetches group by ID with all its permissions. Returns nil if not found.

**Parameters:**
- `id` - Group ID

**Returns:**
- `*Group` - Group with permissions loaded
- `nil` if not found (not an error)
- Error on database issues

---

### ListGroups

```go
ListGroups(ctx context.Context) ([]Group, error)
```

Returns all groups (without permissions).

**Returns:**
- `[]Group` - All groups ordered by name
- Error on database issues

---

### DeleteGroup

```go
DeleteGroup(ctx context.Context, id string) error
```

Deletes group. Cascades to remove user-group assignments and group-permission assignments.

**Parameters:**
- `id` - Group ID

**Returns:**
- `nil` on success
- Error on database issues

---

### AddPermissionToGroup

```go
AddPermissionToGroup(ctx context.Context, groupID string, permissionKey string) error
```

Adds a permission to a group.

**Parameters:**
- `groupID` - Group ID
- `permissionKey` - Permission key

**Returns:**
- `nil` on success
- `ErrPermissionNotFound` - Permission doesn't exist
- Error on database issues

---

### RemovePermissionFromGroup

```go
RemovePermissionFromGroup(ctx context.Context, groupID string, permissionID string) error
```

Removes a permission from a group.

**Parameters:**
- `groupID` - Group ID
- `permissionID` - Permission ID

**Returns:**
- `nil` on success
- Error on database issues

---

### AssignUserToGroup

```go
AssignUserToGroup(ctx context.Context, userID string, groupID string) error
```

Adds a user to a group. User inherits all group permissions.

**Parameters:**
- `userID` - User ID
- `groupID` - Group ID

**Returns:**
- `nil` on success
- Error on database issues (user/group must exist)

---

### RemoveUserFromGroup

```go
RemoveUserFromGroup(ctx context.Context, userID string, groupID string) error
```

Removes a user from a group.

**Parameters:**
- `userID` - User ID
- `groupID` - Group ID

**Returns:**
- `nil` on success
- Error on database issues

---

### GetUserGroups

```go
GetUserGroups(ctx context.Context, userID string) ([]Group, error)
```

Returns all groups user belongs to (without permissions).

**Parameters:**
- `userID` - User ID

**Returns:**
- `[]Group` - Groups user belongs to
- Error on database issues

---

## Bootstrap

### Bootstrap

```go
Bootstrap(ctx context.Context, superAdminEmail string) error
```

One-stop initialization function. Runs migrations, seeds default permissions, creates super admin.

**Parameters:**
- `superAdminEmail` - Email of super admin account to create/ensure

**Returns:**
- `nil` on success
- Error if any step fails

**What it does:**
1. Runs `Migrate()` if `cfg.AutoMigrate` is true
2. Creates default permissions:
   - `permissions:manage` - Manage permissions
   - `groups:manage` - Manage groups
   - `users:manage` - Manage user permissions/groups
3. Creates/gets super admin user
4. Assigns all permissions to super admin

**Example:**
```go
err := store.Bootstrap(ctx, "admin@example.com")
if err != nil {
	log.Fatal(err)
}

log.Println("System ready")
```

---

## Migration Interface

### Migrate

```go
Migrate(ctx context.Context) error
```

Applies all pending migrations in order. Safe to call multiple times.

**Returns:**
- `nil` on success or all migrations already applied
- Error if any migration fails

---

### Rollback

```go
Rollback(ctx context.Context) error
```

Rolls back the last applied migration.

**Returns:**
- `nil` on success
- Error if no migrations to rollback or rollback fails

---

### MigrationStatus

```go
MigrationStatus(ctx context.Context) ([]MigrationRecord, error)
```

Returns status of all migrations.

**Returns:**
- `[]MigrationRecord` - Each migration with applied status, timestamp, checksum
- Error on database issues

**Example:**
```go
status, err := store.MigrationStatus(ctx)
if err != nil {
	log.Fatal(err)
}

for _, m := range status {
	fmt.Printf("%s: %v\n", m.Name, m.Applied)
}
```
