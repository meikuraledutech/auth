# RefreshTokenPair

**Version:** auth/v2 — v2.0.4

---

## What Changed in v2.0.4

Added `RefreshTokenPair` — a helper function that validates a refresh token and issues a new token pair with the latest user permissions and groups fetched from the database.

Previously, callers had to wire this manually:
1. `ValidateToken` → check type
2. `GetUserByID` → fetch user
3. `GetResolvedPermissions` → fetch permissions
4. `GetUserGroups` → fetch groups
5. `GenerateTokenPair` → issue new pair

`RefreshTokenPair` wraps all of this into one call.

---

## Signature

```go
func RefreshTokenPair(ctx context.Context, cfg Config, store Store, refreshToken string) (*TokenPair, error)
```

| Parameter | Description |
|-----------|-------------|
| `ctx` | Request context |
| `cfg` | Auth config (JWT secret, expiry settings) |
| `store` | Store implementation to fetch user + permissions |
| `refreshToken` | The refresh token string from the client |

**Returns:** A new `*TokenPair` with fresh access + refresh tokens, or an error.

**Errors:**
- `auth: invalid token` — token is expired or tampered
- `auth: token is not a refresh token` — access token was passed instead
- `auth.ErrUserNotFound` — user no longer exists in DB

---

## Usage

```go
// Client sends refresh token → issue new pair
tokens, err := auth.RefreshTokenPair(ctx, cfg, store, refreshTokenStr)
if err != nil {
    // handle expired/invalid token
    return
}
// return tokens.AccessToken + tokens.RefreshToken to client
```

---

## Why Permissions Are Re-fetched

On every refresh, the latest permissions and groups are pulled from the database. This means if a user's permissions were changed (e.g. revoked), the next refresh will reflect that — without waiting for the access token to expire.

---

## Token Expiry Defaults

| Token | Expiry |
|-------|--------|
| Access token | 15 minutes |
| Refresh token | 7 days |

Configurable via `cfg.AccessExpiry` and `cfg.RefreshExpiry`.
