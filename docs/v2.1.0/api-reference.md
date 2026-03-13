# API Reference — Organization Methods

**Version:** auth/v2 — v2.1.0

---

## Store Interface Extensions

All new methods are part of the `Store` interface in `v2/store.go`.

---

## Organization Management

### CreateOrganizationWithPermissions

```go
func (s *Store) CreateOrganizationWithPermissions(
    ctx context.Context,
    name string,
    permissionKeys []string,
) (*Organization, error)
```

Creates a new organization with assigned permissions. **Idempotent** — if organization already exists, returns the existing one without error.

**Parameters:**
- `ctx` — context
- `name` — organization name (must be unique, e.g., "trainer", "student")
- `permissionKeys` — list of permission keys to assign (e.g., ["forms:create", "users:manage"])

**Returns:**
- `*Organization` — created/existing organization with permissions loaded
- `error` — nil on success, or permission-related error if key not found

**Example:**
```go
org, err := store.CreateOrganizationWithPermissions(ctx, "trainer", []string{"forms:create", "users:manage"})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Created: %s (%d permissions)\n", org.Name, len(org.Permissions))
```

---

### GetOrganization

```go
func (s *Store) GetOrganization(
    ctx context.Context,
    id string,
) (*Organization, error)
```

Fetches an organization by ID with permissions pre-loaded.

**Parameters:**
- `ctx` — context
- `id` — organization UUID

**Returns:**
- `*Organization` — with `Permissions` array populated
- `nil, nil` — if not found
- `error` — on database error

**Example:**
```go
org, err := store.GetOrganization(ctx, "org-uuid-123")
if err != nil {
    log.Fatal(err)
}
if org == nil {
    log.Println("Organization not found")
    return
}
for _, perm := range org.Permissions {
    fmt.Printf("- %s\n", perm.Key)
}
```

---

### GetOrganizationByName

```go
func (s *Store) GetOrganizationByName(
    ctx context.Context,
    name string,
) (*Organization, error)
```

Fetches an organization by name with permissions pre-loaded. **Preferred over GetOrganization** for name-based lookups.

**Parameters:**
- `ctx` — context
- `name` — organization name (e.g., "trainer")

**Returns:**
- `*Organization` — with `Permissions` array populated
- `nil, nil` — if not found
- `error` — on database error

**Example:**
```go
org, err := store.GetOrganizationByName(ctx, "trainer")
if err != nil {
    log.Fatal(err)
}
if org == nil {
    log.Println("Trainer organization not found")
    return
}
fmt.Printf("Trainer org has %d permissions\n", len(org.Permissions))
```

---

### ListOrganizations

```go
func (s *Store) ListOrganizations(
    ctx context.Context,
) ([]Organization, error)
```

Lists all organizations. Permissions are **not** loaded (use `GetOrganization()` or `GetOrganizationByName()` for permissions).

**Parameters:**
- `ctx` — context

**Returns:**
- `[]Organization` — all orgs (empty slice if none exist)
- `error` — on database error

**Example:**
```go
orgs, err := store.ListOrganizations(ctx)
if err != nil {
    log.Fatal(err)
}
for _, org := range orgs {
    fmt.Printf("- %s\n", org.Name)
}
```

---

### GetOrganizationPermissions

```go
func (s *Store) GetOrganizationPermissions(
    ctx context.Context,
    orgID string,
) ([]Permission, error)
```

Gets all permissions assigned to an organization.

**Parameters:**
- `ctx` — context
- `orgID` — organization UUID

**Returns:**
- `[]Permission` — all permissions for org (empty slice if none)
- `error` — on database error

**Example:**
```go
perms, err := store.GetOrganizationPermissions(ctx, orgID)
if err != nil {
    log.Fatal(err)
}
for _, p := range perms {
    fmt.Printf("- %s: %s\n", p.Key, p.Description)
}
```

---

### AssignPermissionsToOrganization

```go
func (s *Store) AssignPermissionsToOrganization(
    ctx context.Context,
    orgID string,
    permissionKeys []string,
) error
```

Adds permissions to an organization. If permission already assigned, does nothing (idempotent).

**Parameters:**
- `ctx` — context
- `orgID` — organization UUID
- `permissionKeys` — list of permission keys to add

**Returns:**
- `nil` — on success
- `error` — if org not found or permission key not found

**Example:**
```go
err := store.AssignPermissionsToOrganization(ctx, orgID, []string{"reports:view", "reports:edit"})
if err != nil {
    log.Fatal(err)
}
```

---

### RemovePermissionsFromOrganization

```go
func (s *Store) RemovePermissionsFromOrganization(
    ctx context.Context,
    orgID string,
    permissionKeys []string,
) error
```

Removes permissions from an organization.

**Parameters:**
- `ctx` — context
- `orgID` — organization UUID
- `permissionKeys` — list of permission keys to remove

**Returns:**
- `nil` — on success (even if permission wasn't assigned)
- `error` — on database error

**Example:**
```go
err := store.RemovePermissionsFromOrganization(ctx, orgID, []string{"admin:view"})
if err != nil {
    log.Fatal(err)
}
```

---

## User-Organization

### CreateUserWithOrganization

```go
func (s *Store) CreateUserWithOrganization(
    ctx context.Context,
    email string,
    organization string,
) (*User, error)
```

Creates a user assigned to an organization. **Validates organization exists** — returns `ErrInvalidOrganization` if org not found.

**Parameters:**
- `ctx` — context
- `email` — user email (must be unique)
- `organization` — organization name (must exist)

**Returns:**
- `*User` — created user with `Organization` field set
- `nil, ErrInvalidOrganization` — if org doesn't exist
- `nil, ErrEmailAlreadyRegistered` — if email already exists (returns existing user)
- `error` — on other database error

**Example:**
```go
user, err := store.CreateUserWithOrganization(ctx, "trainer@example.com", "trainer")
if err == auth.ErrInvalidOrganization {
    log.Println("Trainer organization doesn't exist")
    return
} else if err != nil {
    log.Fatal(err)
}
fmt.Printf("Created user: %s (org: %s)\n", user.Email, user.Organization)
```

---

### GetUserOrganization

```go
func (s *Store) GetUserOrganization(
    ctx context.Context,
    userID string,
) (string, error)
```

Gets the organization assigned to a user (returns empty string if user has no organization).

**Parameters:**
- `ctx` — context
- `userID` — user UUID

**Returns:**
- `string` — organization name (empty string if none)
- `error` — on database error

**Example:**
```go
org, err := store.GetUserOrganization(ctx, userID)
if err != nil {
    log.Fatal(err)
}
if org == "" {
    log.Println("User has no organization")
} else {
    log.Printf("User's organization: %s\n", org)
}
```

---

## Permission Resolution

### GetAllUserPermissions

```go
func (s *Store) GetAllUserPermissions(
    ctx context.Context,
    userID string,
) ([]Permission, error)
```

Gets all permissions for a user from **all three sources**: direct + groups + organization. Results are deduplicated.

**Parameters:**
- `ctx` — context
- `userID` — user UUID

**Returns:**
- `[]Permission` — all permissions (empty slice if none)
- `error` — on database error

**Example:**
```go
perms, err := store.GetAllUserPermissions(ctx, userID)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("User has %d permissions:\n", len(perms))
for _, p := range perms {
    fmt.Printf("- %s\n", p.Key)
}
```

---

### HasAnyPermission

```go
func (s *Store) HasAnyPermission(
    ctx context.Context,
    userID string,
    permissionKeys []string,
) (bool, error)
```

Checks if user has **any** of the given permissions (logical OR). Faster than `GetAllUserPermissions()` when you only need to check specific keys.

**Parameters:**
- `ctx` — context
- `userID` — user UUID
- `permissionKeys` — list of permission keys to check

**Returns:**
- `true` — if user has at least one of the keys
- `false` — if user has none of them
- `error` — on database error

**Example:**
```go
canEdit, err := store.HasAnyPermission(ctx, userID, []string{"forms:edit", "admin:all"})
if err != nil {
    log.Fatal(err)
}
if canEdit {
    // User can edit forms (either directly or via admin:all)
}
```

---

### GetResolvedPermissions (Enhanced)

```go
func (s *Store) GetResolvedPermissions(
    ctx context.Context,
    userID string,
) ([]Permission, error)
```

Gets permissions from **direct + groups** (unchanged signature from v2.0.5). **Now also includes organization permissions** — transparent upgrade.

**Example:**
```go
// v2.0.5 behavior: direct + groups
// v2.1.0 behavior: direct + groups + org
perms, err := store.GetResolvedPermissions(ctx, userID)
if err != nil {
    log.Fatal(err)
}
```

---

### HasResolvedPermission (Enhanced)

```go
func (s *Store) HasResolvedPermission(
    ctx context.Context,
    userID string,
    permissionKey string,
) (bool, error)
```

Checks if user has a permission from **direct + groups** (unchanged signature from v2.0.5). **Now also checks organization permissions** — transparent upgrade.

**Example:**
```go
// v2.0.5 behavior: direct + groups
// v2.1.0 behavior: direct + groups + org
has, err := store.HasResolvedPermission(ctx, userID, "forms:create")
if err != nil {
    log.Fatal(err)
}
```

---

## Bulk Group Operations

### AddUsersToGroup

```go
func (s *Store) AddUsersToGroup(
    ctx context.Context,
    groupID string,
    userIDs []string,
) error
```

Adds multiple users to a group in bulk (one SQL statement). **Idempotent** — if user already in group, no duplicate is created.

**Parameters:**
- `ctx` — context
- `groupID` — group UUID
- `userIDs` — list of user UUIDs to add

**Returns:**
- `nil` — on success
- `error` — on database error

**Example:**
```go
// Add 100 users in one call
userIDs := []string{"user1", "user2", ..., "user100"}
err := store.AddUsersToGroup(ctx, groupID, userIDs)
if err != nil {
    log.Fatal(err)
}
```

---

### RemoveUsersFromGroup

```go
func (s *Store) RemoveUsersFromGroup(
    ctx context.Context,
    groupID string,
    userIDs []string,
) error
```

Removes multiple users from a group in bulk.

**Parameters:**
- `ctx` — context
- `groupID` — group UUID
- `userIDs` — list of user UUIDs to remove

**Returns:**
- `nil` — on success (even if user wasn't in group)
- `error` — on database error

**Example:**
```go
err := store.RemoveUsersFromGroup(ctx, groupID, []string{"user1", "user2"})
if err != nil {
    log.Fatal(err)
}
```

---

### GetGroupMembers

```go
func (s *Store) GetGroupMembers(
    ctx context.Context,
    groupID string,
) ([]User, error)
```

Gets all users in a group. **User.Organization field is populated** (useful for seeing each member's org).

**Parameters:**
- `ctx` — context
- `groupID` — group UUID

**Returns:**
- `[]User` — all users in group with `Organization` field populated (empty slice if none)
- `error` — on database error

**Example:**
```go
members, err := store.GetGroupMembers(ctx, groupID)
if err != nil {
    log.Fatal(err)
}
for _, member := range members {
    fmt.Printf("- %s (org: %s)\n", member.Email, member.Organization)
}
```

---

## Bootstrap (Updated)

### Bootstrap

```go
func (s *Store) Bootstrap(
    ctx context.Context,
    superAdminEmail string,
    organizations ...map[string][]string,
) error
```

Creates schema, seeds default permissions, optionally creates organizations, and ensures super admin exists. **Idempotent** — safe to call every app start.

**Parameters:**
- `ctx` — context
- `superAdminEmail` — super admin user email
- `organizations` — (optional) variadic map of `org_name -> []permission_keys`

**Returns:**
- `nil` — on success
- `error` — on database error

**Example:**
```go
// Without organizations (backward compatible)
err := store.Bootstrap(ctx, "admin@example.com")

// With organizations
orgs := map[string][]string{
    "trainer": {"forms:create", "users:manage"},
    "student": {"forms:create"},
}
err := store.Bootstrap(ctx, "admin@example.com", orgs)

if err != nil {
    log.Fatal(err)
}
```

---

## Error Types

```go
// Existing errors (v2.0.5)
ErrUserNotFound
ErrPermissionNotFound
ErrGroupNotFound
ErrInvalidPassword
ErrEmailAlreadyRegistered

// New in v2.1.0
ErrOrganizationNotFound  // Organization not found by ID/name
ErrOrganizationExists    // Organization already exists (not thrown, idempotent)
ErrInvalidOrganization   // Organization name doesn't exist (for CreateUserWithOrganization)
ErrGroupMembershipFailed // Failed to update group membership
```

---

## Type Definitions

```go
type Organization struct {
    ID          string       `json:"id"`
    Name        string       `json:"name"`
    Permissions []Permission `json:"permissions,omitempty"`
    CreatedAt   time.Time    `json:"created_at"`
}

type Permission struct {
    ID          string    `json:"id"`
    Key         string    `json:"key"`
    Description string    `json:"description"`
    CreatedAt   time.Time `json:"created_at"`
}

type User struct {
    ID           string    `json:"id"`
    Email        string    `json:"email"`
    Organization string    `json:"organization,omitempty"`
    CreatedAt    time.Time `json:"created_at"`
}
```

---

## See Also

- [organizations.md](./organizations.md) — Feature documentation with examples
- [migration-guide.md](./migration-guide.md) — Upgrade guide from v2.0.5
- [../../v2/examples/main.go](../../v2/examples/main.go) — Complete test suite
