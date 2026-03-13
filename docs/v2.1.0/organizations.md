# Organization-Based Permission Model

**Version:** auth/v2 — v2.1.0

---

## What Changed in v2.1.0

v2.1.0 introduces **organizations** as a first-class entity for permission management. Users can now be assigned to organizational roles (trainer, student, college_admin, super_admin) which carry base permissions. This enables role-based access control at the organizational level while maintaining existing direct permissions and group-based permissions.

Permission resolution now follows a **3-part union**:
1. **Direct permissions** — assigned to user directly
2. **Group permissions** — inherited from groups user belongs to
3. **Organization permissions** — inherited from user's assigned organization

**Breaking changes:** None. All changes are fully backward compatible.

---

## New Types

### Organization

```go
type Organization struct {
    ID          string       `json:"id"`
    Name        string       `json:"name"`        // e.g. "trainer", "student"
    Permissions []Permission `json:"permissions,omitempty"`
    CreatedAt   time.Time    `json:"created_at"`
}
```

### User (Extended)

```go
type User struct {
    ID           string    `json:"id"`
    Email        string    `json:"email"`
    Organization string    `json:"organization,omitempty"` // e.g. "trainer", "student"
    CreatedAt    time.Time `json:"created_at"`
}
```

---

## New Store Methods

### Organization Management

```go
// Create organization with permissions (idempotent)
CreateOrganizationWithPermissions(ctx context.Context, name string, permissionKeys []string) (*Organization, error)

// Get organization by ID with permissions pre-loaded
GetOrganization(ctx context.Context, id string) (*Organization, error)

// Get organization by name with permissions pre-loaded
GetOrganizationByName(ctx context.Context, name string) (*Organization, error)

// List all organizations (without permissions)
ListOrganizations(ctx context.Context) ([]Organization, error)

// Manage organization permissions
AssignPermissionsToOrganization(ctx context.Context, orgID string, permissionKeys []string) error
RemovePermissionsFromOrganization(ctx context.Context, orgID string, permissionKeys []string) error
GetOrganizationPermissions(ctx context.Context, orgID string) ([]Permission, error)
```

### User-Organization

```go
// Create user assigned to organization (validates org exists)
CreateUserWithOrganization(ctx context.Context, email string, organization string) (*User, error)

// Get user's assigned organization
GetUserOrganization(ctx context.Context, userID string) (string, error)
```

### Enhanced Permission Resolution

```go
// Get all user permissions (direct + group + organization)
GetAllUserPermissions(ctx context.Context, userID string) ([]Permission, error)

// Check if user has ANY of the given permissions
HasAnyPermission(ctx context.Context, userID string, permissionKeys []string) (bool, error)
```

**Updated Methods** — now include organization permissions:
```go
// Returns union of direct + group + organization permissions
GetResolvedPermissions(ctx context.Context, userID string) ([]Permission, error)
HasResolvedPermission(ctx context.Context, userID string, permissionKey string) (bool, error)
```

### Bulk Group Operations

```go
// Add multiple users to a group (idempotent)
AddUsersToGroup(ctx context.Context, groupID string, userIDs []string) error

// Remove multiple users from a group
RemoveUsersFromGroup(ctx context.Context, groupID string, userIDs []string) error

// Get all users in a group (with org field populated)
GetGroupMembers(ctx context.Context, groupID string) ([]User, error)
```

### Bootstrap (Updated)

```go
// Accepts variadic org-permission map (fully backward compatible)
Bootstrap(ctx context.Context, superAdminEmail string, organizations ...map[string][]string) error
```

---

## Usage Examples

### 1. Create Organizations with Permissions

```go
orgs := map[string][]string{
    "super_admin": {"permissions:manage", "groups:manage", "users:manage"},
    "trainer":     {"forms:create", "users:manage"},
    "college_admin": {"groups:manage", "forms:create"},
    "student":     {"forms:create"},
}

// Bootstrap automatically creates these organizations
err := store.Bootstrap(ctx, "admin@example.com", orgs)
if err != nil {
    log.Fatal(err)
}
```

### 2. Create User with Organization

```go
// User assigned to trainer organization inherits trainer permissions
trainer, err := store.CreateUserWithOrganization(ctx, "trainer@example.com", "trainer")
if err != nil {
    log.Fatal(err)
}

// trainer.Organization = "trainer"
// trainer automatically has: forms:create, users:manage
```

### 3. Check Permissions (Automatic Union)

```go
// Checks direct + group + organization permissions automatically
hasPermission, err := store.HasResolvedPermission(ctx, userID, "forms:create")
if err != nil {
    log.Fatal(err)
}

if hasPermission {
    // User can create forms (either directly, via group, or via org)
}
```

### 4. Check Multiple Permissions

```go
// Check if user has ANY of these permissions
canManageContent, err := store.HasAnyPermission(ctx, userID,
    []string{"forms:create", "forms:edit", "forms:delete"})
if err != nil {
    log.Fatal(err)
}

if canManageContent {
    // User can perform at least one content management action
}
```

### 5. Get All User Permissions

```go
// Get full permission set (direct + group + org)
perms, err := store.GetAllUserPermissions(ctx, userID)
if err != nil {
    log.Fatal(err)
}

for _, perm := range perms {
    fmt.Printf("- %s: %s\n", perm.Key, perm.Description)
}
```

### 6. Bulk Group Operations

```go
// Create group
group, err := store.CreateGroup(ctx, "Reviewers")
if err != nil {
    log.Fatal(err)
}

// Add 10 users to group in one call (no duplicates)
userIDs := []string{"user1", "user2", "user3", ...}
err = store.AddUsersToGroup(ctx, group.ID, userIDs)
if err != nil {
    log.Fatal(err)
}

// Get all members (with their org field populated)
members, err := store.GetGroupMembers(ctx, group.ID)
if err != nil {
    log.Fatal(err)
}
```

### 7. Manage Organization Permissions

```go
org, err := store.GetOrganizationByName(ctx, "trainer")
if err != nil {
    log.Fatal(err)
}

// Add new permission to trainer org
err = store.AssignPermissionsToOrganization(ctx, org.ID, []string{"reports:view"})
if err != nil {
    log.Fatal(err)
}

// All trainers now automatically have reports:view
```

---

## Permission Resolution Logic

When checking if a user has a permission, the system checks **all three sources**:

```sql
SELECT EXISTS(
    SELECT 1 FROM auth_permissions p
    WHERE p.key = 'forms:create' AND p.id IN (
        -- Direct permissions
        SELECT permission_id FROM auth_user_permissions WHERE user_id = $1
        UNION
        -- Group permissions
        SELECT gp.permission_id FROM auth_group_permissions gp
        JOIN auth_user_groups ug ON ug.group_id = gp.group_id
        WHERE ug.user_id = $1
        UNION
        -- Organization permissions
        SELECT op.permission_id FROM auth_organization_permissions op
        JOIN auth_organizations o ON o.id = op.organization_id
        JOIN auth_users u ON u.organization = o.name
        WHERE u.id = $1
    )
)
```

**Result:** User has permission if ANY source grants it (logical OR).

---

## Backward Compatibility

All changes are fully backward compatible:

### Old Code Still Works

```go
// Old Bootstrap call (without organizations)
err := store.Bootstrap(ctx, "admin@example.com")

// Old CreateUser call (user created without org)
user, err := store.CreateUser(ctx, "user@example.com")
// user.Organization = ""

// Old permission checks (now include org perms automatically)
has, err := store.HasResolvedPermission(ctx, userID, "forms:create")
// Returns true if user has permission via ANY source (direct, group, OR org)
```

### Migration Path

**No migration needed.** Existing users and permissions continue to work:
- Existing users without org assignment have empty `Organization` field
- Permission checks transparently include organization permissions
- All existing APIs unchanged (except `Bootstrap` is now variadic)

---

## Database Schema

### New Tables

```sql
-- Organizations table
CREATE TABLE auth_organizations (
    id         TEXT PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Organization-permission junction
CREATE TABLE auth_organization_permissions (
    organization_id TEXT NOT NULL REFERENCES auth_organizations(id) ON DELETE CASCADE,
    permission_id   TEXT NOT NULL REFERENCES auth_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (organization_id, permission_id)
);
```

### Updated Users Table

```sql
-- Add organization field to users (nullable, foreign key to org name)
ALTER TABLE auth_users ADD COLUMN organization TEXT
    REFERENCES auth_organizations(name);

-- Index for fast org lookups
CREATE INDEX idx_auth_users_organization ON auth_users(organization);
```

---

## Error Handling

### New Errors

```go
ErrOrganizationNotFound  = errors.New("auth: organization not found")
ErrInvalidOrganization   = errors.New("auth: invalid organization")
ErrGroupMembershipFailed = errors.New("auth: failed to update group membership")
```

### Example Error Handling

```go
user, err := store.CreateUserWithOrganization(ctx, "user@example.com", "trainer")
if err == auth.ErrInvalidOrganization {
    // Organization doesn't exist — create it first
    fmt.Println("Invalid organization: trainer does not exist")
} else if err != nil {
    log.Fatal(err)
}
```

---

## Design Notes

### Idempotency
- `CreateOrganizationWithPermissions` is idempotent — returns existing if already created
- `AddUsersToGroup` is idempotent — no duplicates even if called multiple times
- `Bootstrap` is idempotent — safe to call on every app start

### Permission Precedence
There is no precedence — permissions are combined via logical OR:
- User has permission if ANY source grants it
- Cannot revoke permission from one source if granted by another
- To deny a permission, remove it from all three sources

### Organization Assignment
- Each user has **at most one** organization
- Organization assignment is **optional** (for backward compatibility)
- Cannot create user in non-existent organization (validated at creation)

### Bulk Operations
All bulk operations use efficient SQL:
- `AddUsersToGroup(groupID, [100 userIDs])` = 1 SQL statement (not 100)
- `RemoveUsersFromGroup(groupID, [100 userIDs])` = 1 SQL statement
- `GetGroupMembers(groupID)` = 1 SQL statement

---

## Testing

See `v2/examples/main.go` for comprehensive test suite covering:
- ✅ Organization creation and permission assignment
- ✅ User-organization assignment with validation
- ✅ Permission inheritance from organizations
- ✅ Unauthorized access blocking
- ✅ Permission union (3-part UNION)
- ✅ Bulk group operations
- ✅ Backward compatibility
- ✅ NULL organization handling

Run tests:
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
