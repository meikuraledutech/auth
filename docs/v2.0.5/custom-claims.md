# Custom Meta Claims in JWT

**Version:** auth/v2 — v2.0.5

---

## What Changed in v2.0.5

`GenerateTokenPair` now accepts an optional `meta map[string]any` parameter. Any key-value pairs in `meta` are embedded directly into the access token. They are extracted back when `ValidateToken` is called, available via `claims.Meta`.

This avoids extra DB calls on every request just to fetch user metadata like `college_id`, `org_id`, `role`, etc.

**Breaking change:** `GenerateTokenPair` signature changed — `meta` parameter added.

---

## Signature Changes

```go
// v2.0.4
GenerateTokenPair(cfg Config, user *User, permissions []string, groups []string) (*TokenPair, error)

// v2.0.5
GenerateTokenPair(cfg Config, user *User, permissions []string, groups []string, meta map[string]any) (*TokenPair, error)
```

`Claims` struct updated:

```go
type Claims struct {
    UserID      string         `json:"user_id"`
    Email       string         `json:"email"`
    Type        string         `json:"type"`
    Permissions []string       `json:"permissions,omitempty"`
    Groups      []string       `json:"groups,omitempty"`
    Meta        map[string]any `json:"meta,omitempty"` // new
}
```

---

## Usage

### Generating a token with meta

```go
tokens, err := auth.GenerateTokenPair(cfg, user, permissions, groups, map[string]any{
    "college_id": "clg_abc123",
    "role":       "college_admin",
})
```

Pass `nil` if you have no custom claims:

```go
tokens, err := auth.GenerateTokenPair(cfg, user, permissions, groups, nil)
```

### Reading meta from a validated token

```go
claims, err := auth.ValidateToken(cfg, accessTokenStr)
if err != nil {
    // handle invalid/expired token
}

collegeID := claims.Meta["college_id"].(string)
role      := claims.Meta["role"].(string)
```

---

## Notes

- Meta is only embedded in the **access token** — not in the refresh token
- On `RefreshTokenPair`, pass `nil` for meta — the new access token will not carry meta unless your app calls `GenerateTokenPair` directly with meta again
- Reserved JWT keys (`user_id`, `email`, `type`, `iat`, `exp`, `permissions`, `groups`) cannot be used as meta keys — they will be overwritten or ignored

---

## Migration from v2.0.4

Add `nil` as the last argument to all existing `GenerateTokenPair` calls:

```go
// before
auth.GenerateTokenPair(cfg, user, permissions, groups)

// after
auth.GenerateTokenPair(cfg, user, permissions, groups, nil)
```
