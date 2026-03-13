# Migration Guide — v2.0.5 → v2.1.0

**Version:** auth/v2 — v2.1.0

---

## TL;DR

**No breaking changes.** If you're using v2.0.5, you can upgrade to v2.1.0 without modifying your code.

New features are opt-in:
- Old code using direct permissions continues to work
- Old code using group-based permissions continues to work
- Old code checking permissions continues to work unchanged

---

## What's New

1. **Organization-based permissions** — assign users to roles (trainer, student, etc.)
2. **Enhanced permission resolution** — permissions now come from 3 sources instead of 2:
   - Direct permissions (user → permission)
   - Group permissions (user → group → permission)
   - **NEW:** Organization permissions (user → organization → permission)
3. **Bulk group operations** — add/remove multiple users to a group in one call
4. **Better permission checks** — `HasAnyPermission()` checks multiple keys at once

---

## Step-by-Step Upgrade

### 1. Update Dependencies

```bash
go get -u github.com/meikuraledutech/auth/v2@v2.1.0
```

### 2. No Code Changes Required

Your existing code continues to work unchanged:

```go
// v2.0.5
err := store.Bootstrap(ctx, "admin@example.com")
user, err := store.CreateUser(ctx, "user@example.com")
has, err := store.HasResolvedPermission(ctx, userID, "forms:create")

// ✅ All still work in v2.1.0
```

### 3. (Optional) Add Organizations

To use organizations, add them to Bootstrap:

**Before:**
```go
err := store.Bootstrap(ctx, superAdminEmail)
```

**After:**
```go
orgs := map[string][]string{
    "super_admin": {"permissions:manage", "groups:manage", "users:manage"},
    "trainer":     {"forms:create", "users:manage"},
    "college_admin": {"groups:manage", "forms:create"},
    "student":     {"forms:create"},
}
err := store.Bootstrap(ctx, superAdminEmail, orgs)
```

The Bootstrap call is **variadic** — old code without `orgs` still works.

### 4. (Optional) Create Users with Organizations

**Before:**
```go
user, err := store.CreateUser(ctx, "trainer@example.com")
// user.Organization = ""
```

**After:**
```go
user, err := store.CreateUserWithOrganization(ctx, "trainer@example.com", "trainer")
// user.Organization = "trainer"
// user automatically has trainer org permissions
```

Old `CreateUser()` still works (creates user without org).

### 5. (Optional) Use Bulk Group Operations

**Before:**
```go
for _, userID := range userIDs {
    err := store.AssignUserToGroup(ctx, userID, groupID)
    if err != nil {
        log.Fatal(err)
    }
}
```

**After:**
```go
err := store.AddUsersToGroup(ctx, groupID, userIDs)
if err != nil {
    log.Fatal(err)
}
```

More efficient (one SQL statement instead of N).

---

## Breaking Changes: None

All existing method signatures unchanged:
- `CreateUser()` — same
- `HasResolvedPermission()` — same (now includes org perms automatically)
- `GetResolvedPermissions()` — same (now includes org perms automatically)
- `AssignUserToGroup()` — same
- `RemoveUserFromGroup()` — same
- `Bootstrap()` — signature changed to variadic (backward compatible)

---

## New User Fields

The `User` struct has a new optional field:

```go
type User struct {
    ID           string    `json:"id"`
    Email        string    `json:"email"`
    Organization string    `json:"organization,omitempty"` // new in v2.1.0
    CreatedAt    time.Time `json:"created_at"`
}
```

**Impact:**
- If you serialize users to JSON, the `Organization` field will appear (or be omitted if empty)
- If you deserialize JSON to User struct, existing JSON without `Organization` will work fine (empty string)
- If you need to serialize/deserialize with custom marshaling, `Organization` is optional

---

## Database Migration

When you run your app with v2.1.0:

1. **First run:** Migration 003 runs automatically (if `AutoMigrate: true`)
2. **Creates:**
   - `auth_organizations` table
   - `auth_organization_permissions` table
   - `organization` column on `auth_users` table (nullable)
3. **Existing data:** Unaffected
   - Existing users get `organization = NULL`
   - Existing permissions unchanged
   - Existing groups unchanged

**Manual migration:** If `AutoMigrate: false`, run:
```bash
v2/postgres/migrations/003_organizations.up.sql
```

---

## FAQ

### Q: Do I have to use organizations?
**A:** No. Organizations are optional. If you don't use them, your code works exactly as before.

### Q: Can I mix users with and without organizations?
**A:** Yes. Some users can have orgs, others don't. Permission checks work for both.

### Q: Do organization permissions override direct permissions?
**A:** No. Permissions are combined via logical OR. If ANY source grants it, user has it.

### Q: Can I change a user's organization?
**A:** Not yet. You can assign org at creation. In future versions, there will be an update method.

### Q: Do I need to update Bootstrap?
**A:** Only if you want to use organizations. Old `Bootstrap(ctx, email)` still works.

### Q: What about backward compatibility with v2.0.x clients?
**A:** If clients are using JWT tokens from v2.0.5, they'll continue to work in v2.1.0. No token changes.

---

## Rollback

If you need to rollback to v2.0.5:

```bash
go get github.com/meikuraledutech/auth/v2@v2.0.5
```

Then rollback the database migration:
```bash
v2/postgres/migrations/003_organizations.down.sql
```

---

## Testing

Run the example to verify everything works:

```bash
cd v2/examples
env $(cat ../.env | xargs) go run main.go
```

Expected output:
```
=== ALL TESTS PASSED ===

Summary:
✓ Organizations created with permissions
✓ Users assigned to organizations
✓ Permission inheritance from organization
✓ Unauthorized access properly blocked
✓ Permission resolution works (direct + group + org)
✓ Bulk group operations work
✓ User.Organization field properly persisted
✓ Backward compatibility maintained
✓ Invalid organization correctly rejected
```

---

## Support

For questions or issues:
- Check [organizations.md](./organizations.md) for detailed feature documentation
- Run the [example](../../v2/examples/main.go) to see all features in action
- File an issue on GitHub
