# Super Admin Password Setup

**Version:** auth/v2 — v2.1.1

---

## What Changed in v2.1.1

Fixed super admin initialization to support password-based login. Previously, super admin was created without a password and could only be accessed via OTP. Now super admin password can be set during bootstrap via environment variable or parameter.

**Breaking change:** `Bootstrap` signature updated to accept `superAdminPassword` parameter.

---

## Changes

### Bootstrap Signature Update

```go
// v2.1.0
Bootstrap(ctx context.Context, superAdminEmail string, organizations ...map[string][]string) error

// v2.1.1
Bootstrap(ctx context.Context, superAdminEmail string, superAdminPassword string, organizations ...map[string][]string) error
```

### Super Admin Creation Flow

During bootstrap:
1. **Create super admin user** with email
2. **Set password** via `SetPassword(ctx, user.ID, superAdminPassword)` if password is provided
3. **Assign all permissions** to super admin
4. **Assign organization** to super admin if "super_admin" org exists

### Environment Variables

Add to your `.env`:
```env
SUPER_ADMIN_EMAIL=admin@example.com
SUPER_ADMIN_PASSWORD=SuperAdmin@123
```

### Usage

```go
superAdminEmail := os.Getenv("SUPER_ADMIN_EMAIL")
superAdminPassword := os.Getenv("SUPER_ADMIN_PASSWORD")
orgs := map[string][]string{
    "super_admin": {"permissions:manage", "groups:manage", "users:manage"},
    // ... other orgs
}

store.Bootstrap(ctx, superAdminEmail, superAdminPassword, orgs)
```

---

## Super Admin Login

Super admin can now login with:

```go
user, err := store.LoginWithPassword(ctx, superAdminEmail, superAdminPassword)
if err != nil {
    // handle error
}
// user authenticated with password
```

---

## Backward Compatibility

✅ If `superAdminPassword` is empty string, no password is set (maintains OTP-only access).

Example:
```go
store.Bootstrap(ctx, email, "", orgs)  // No password, OTP-only access
```
