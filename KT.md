# Knowledge Transfer Document
# Auth Package — go-packs/auth

**Project:** meikuraledutech/auth
**Repository:** github.com/meikuraledutech/auth
**Date:** 2026-03-05
**Status:** Production Ready (v1.3.1, v2.0.2)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Repository Structure](#2-repository-structure)
3. [v1 — OTP Authentication](#3-v1--otp-authentication)
4. [v2 — Email/Password Authentication](#4-v2--emailpassword-authentication)
5. [Database Schema](#5-database-schema)
6. [Module Versioning](#6-module-versioning)
7. [Release Process](#7-release-process)
8. [Environment Setup](#8-environment-setup)
9. [Lessons Learned](#9-lessons-learned)
10. [Future Work](#10-future-work)

---

## 1. Project Overview

This is a **Go authentication library** for the meikuraledutech platform. It provides two authentication methods and a permission/group system.

### What It Does

- **Email OTP** — Send a 6-digit code, verify it, issue JWT tokens
- **Email + Password** — Register, login, reset password with bcrypt
- **Permissions & Groups** — Assign fine-grained permissions to users or groups
- **JWT Tokens** — Access token (15 min) + Refresh token (7 days)
- **Email Delivery** — ZeptoMail integration for OTP and password reset emails
- **Database** — PostgreSQL with embedded SQL migrations

### Two Versions

| Version | Module Path | Auth Methods | Latest |
|---------|-------------|--------------|--------|
| v1 | `github.com/meikuraledutech/auth` | OTP only | v1.3.1 |
| v2 | `github.com/meikuraledutech/auth/v2` | OTP + Password | v2.0.2 |

---

## 2. Repository Structure

```
auth/                              ← root = v1 module
├── go.mod                         ← module github.com/meikuraledutech/auth
├── go.sum
├── auth.go                        ← Types: User, OTP, TokenPair, Claims, Permission, Group, Config
├── store.go                       ← Store interface + error vars
├── mailer.go                      ← Mailer interface
├── token.go                       ← GenerateTokenPair, ValidateToken
├── postgres/                      ← PostgreSQL Store implementation
│   ├── postgres.go                ← PGStore struct + New()
│   ├── migrate.go                 ← Migrate, Rollback, MigrationStatus
│   ├── bootstrap.go               ← Bootstrap() — migrations + seed + admin
│   ├── schema.go                  ← CreateSchema, DropSchema
│   ├── otp.go                     ← CreateOTP, VerifyOTP
│   ├── user.go                    ← CreateUser, GetUserByID, GetUserByEmail, ListUsers
│   ├── permission.go              ← Full permission CRUD + assignment
│   ├── group.go                   ← Full group CRUD + user assignment
│   └── migrations/
│       ├── 001_initial_schema.up.sql
│       └── 001_initial_schema.down.sql
├── zeptomail/
│   └── zeptomail.go               ← ZeptoMailer implements Mailer (SendOTP)
├── examples/
│   ├── go.mod                     ← standalone module requiring auth v1.3.1
│   └── main.go
├── server/
│   └── main.go                    ← Fiber HTTP server example
│
├── v2/                            ← v2 module (separate go.mod)
│   ├── go.mod                     ← module github.com/meikuraledutech/auth/v2
│   ├── go.sum
│   ├── auth.go                    ← same as v1 + PasswordReset struct + 4 config fields
│   ├── store.go                   ← same as v1 + 6 new errors + 7 new Store methods
│   ├── mailer.go                  ← same as v1 + SendPasswordReset
│   ├── token.go                   ← verbatim copy from v1
│   ├── password.go                ← NEW: bcrypt helpers (HashPassword, CheckPassword, etc.)
│   ├── postgres/
│   │   ├── postgres.go            ← same as v1 (import path v2)
│   │   ├── migrate.go             ← same as v1 (import path v2)
│   │   ├── bootstrap.go           ← same as v1 (import path v2)
│   │   ├── schema.go              ← same as v1 + auth_password_resets in DropSchema
│   │   ├── otp.go                 ← same as v1 (import path v2)
│   │   ├── user.go                ← same as v1 (import path v2)
│   │   ├── permission.go          ← same as v1 (import path v2)
│   │   ├── group.go               ← same as v1 (import path v2)
│   │   ├── password.go            ← NEW: 7 password auth methods
│   │   └── migrations/
│   │       ├── 001_initial_schema.up.sql   ← same as v1
│   │       ├── 001_initial_schema.down.sql ← same as v1
│   │       ├── 002_password_auth.up.sql    ← NEW: password_hash col + resets table
│   │       └── 002_password_auth.down.sql  ← NEW: rollback
│   ├── zeptomail/
│   │   └── zeptomail.go           ← same as v1 + SendPasswordReset
│   ├── examples/
│   │   ├── go.mod                 ← requires auth/v2 v2.0.2 (NO replace directive)
│   │   └── main.go                ← full test suite (8 tests)
│   ├── README.md
│   ├── GETTING_STARTED.md
│   ├── STORE_API.md
│   ├── HELPERS.md
│   ├── SECURITY.md
│   └── DOCS_INDEX.md
│
├── VERSIONING.txt                 ← Module versioning rules (read this!)
└── KT.md                          ← This document
```

---

## 3. v1 — OTP Authentication

### Authentication Flow

```
Client                    Server                     DB / Email
  │                          │                            │
  │─── POST /auth/otp ──────►│                            │
  │     { email }            │── CreateOTP(email) ───────►│
  │                          │◄── { code, expiresAt } ───│
  │                          │── SendOTP(email, code) ──►Email
  │◄─── { message } ─────────│                            │
  │                          │                            │
  │─── POST /auth/verify ───►│                            │
  │   { email, code }        │── VerifyOTP(email, code) ─►│
  │                          │◄── User (auto-created) ───│
  │                          │── GetResolvedPermissions ──►│
  │                          │── GenerateTokenPair ────────│
  │◄─── { access, refresh } ─│                            │
```

### Key Behaviors

- `VerifyOTP` — auto-creates user if first time
- OTP marked as `verified=TRUE` after use (single-use)
- Tokens embed permissions (no DB call needed on authorization)

### Install

```bash
go get github.com/meikuraledutech/auth@v1.3.1
```

### Usage

```go
import (
    auth "github.com/meikuraledutech/auth"
    "github.com/meikuraledutech/auth/postgres"
    "github.com/meikuraledutech/auth/zeptomail"
)

cfg := auth.DefaultConfig(jwtSecret, superAdminEmail)
store := postgres.New(pool, cfg)
mailer := zeptomail.New(apiKey, fromEmail)

store.Bootstrap(ctx, superAdminEmail)

otp, _ := store.CreateOTP(ctx, "user@example.com")
mailer.SendOTP(ctx, "user@example.com", otp.Code, cfg.OTPExpiry)

user, _ := store.VerifyOTP(ctx, "user@example.com", "123456")
perms, _ := store.GetResolvedPermissions(ctx, user.ID)
tokens, _ := auth.GenerateTokenPair(cfg, user, permKeys, groupNames)
```

### v1 Version History

| Tag | Key Changes |
|-----|-------------|
| v1.0.0 | Initial: OTP + JWT |
| v1.1.0 | Permissions + Groups |
| v1.1.1 | Embed groups in JWT |
| v1.2.0 | Embed permissions in JWT |
| v1.3.0 | Migration-based schema management |
| v1.3.1 | Latest stable |

---

## 4. v2 — Email/Password Authentication

### What's New in v2

v2 keeps OTP auth unchanged and adds password auth as a second method.

### New Config Fields

```go
cfg := auth.DefaultConfig(jwtSecret, superAdminEmail)
cfg.BcryptCost          = 10          // bcrypt work factor
cfg.PasswordResetExpiry = time.Hour   // reset token expiry
cfg.MinPasswordLength   = 8           // min password length
cfg.MaxPasswordLength   = 72          // max (bcrypt limit)
```

### New Errors

```go
auth.ErrPasswordInvalid        // wrong password
auth.ErrPasswordTooWeak        // doesn't meet strength requirements
auth.ErrPasswordNotSet         // user has no password (OTP-only)
auth.ErrEmailAlreadyRegistered // email already registered
auth.ErrResetTokenInvalid      // token not found or expired
auth.ErrResetTokenUsed         // token already used
```

### New Store Methods (7)

```go
RegisterWithPassword(ctx, email, plainPassword) (*User, error)
LoginWithPassword(ctx, email, plainPassword) (*User, error)
SetPassword(ctx, userID, plainPassword) error
ChangePassword(ctx, userID, currentPassword, newPassword) error
HasPassword(ctx, userID) (bool, error)
CreatePasswordReset(ctx, email) (rawToken, expiresAt, error)
ResetPassword(ctx, rawToken, newPassword) error
```

### New Helper Functions (password.go)

```go
auth.HashPassword(cfg, plain)          // validate + bcrypt hash
auth.CheckPassword(plain, hash)        // verify against hash
auth.ValidatePasswordStrength(cfg, plain) // check rules
auth.GenerateResetToken()              // 32-byte CSPRNG → base64url
auth.HashResetToken(rawToken)          // SHA-256 hex (stored in DB)
```

### Password Authentication Flow

```
Register:
  ValidatePasswordStrength → HashPassword (bcrypt) → INSERT user with password_hash

Login:
  SELECT password_hash → CheckPassword (bcrypt compare) → return User

Password Reset:
  CreatePasswordReset:
    GenerateResetToken → HashResetToken → UPDATE old tokens used=TRUE
    → INSERT new token hash → return rawToken to caller

  ResetPassword:
    HashResetToken(submitted) → SELECT by hash → check used/expired
    → UPDATE password_hash + mark token used=TRUE (single TX)
```

### Password Strength Rules

```
✓ Min 8 characters (configurable)
✓ Max 72 characters (bcrypt limit — enforced)
✓ At least 1 uppercase letter
✓ At least 1 lowercase letter
✓ At least 1 digit
✓ At least 1 special character (punct or symbol)

Valid:   MyPassword123!    Secure@Pass456    P@ssw0rd!
Invalid: password123!      MYPASSWORD123!    MyPass123
```

### Security Design

| Concern | Solution |
|---------|----------|
| Password storage | bcrypt with configurable cost (default 10) |
| Reset token entropy | 32-byte CSPRNG = 256 bits |
| Reset token DB leak | Only SHA-256 hash stored in DB |
| Token reuse | Marked `used=TRUE` atomically in same TX |
| Token accumulation | Old unused tokens invalidated on new request |
| bcrypt max input | MaxPasswordLength=72 enforced in validation |

### Install

```bash
go get github.com/meikuraledutech/auth/v2@v2.0.2
```

### v2 Version History

| Tag | Notes |
|-----|-------|
| v2.0.0 | ❌ Failed — had replace directive in examples/go.mod |
| v2.0.1 | ❌ Failed — proxy pseudo-version, incorrect go.mod |
| v2.0.2 | ✅ SUCCESS — replace directive removed, all tests pass |

---

## 5. Database Schema

### v1 Tables

```sql
auth_users           -- id, email, created_at
auth_otps            -- id, email, code, expires_at, verified, created_at
auth_permissions     -- id, key, description, created_at
auth_user_permissions -- user_id, permission_id (direct assignments)
auth_groups          -- id, name, created_at
auth_group_permissions -- group_id, permission_id
auth_user_groups     -- user_id, group_id
auth_migrations      -- id, name, applied_at, checksum (tracks applied migrations)
```

### v2 Additions (migration 002)

```sql
-- Added column to auth_users:
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS password_hash TEXT;
-- NULL for OTP-only users, bcrypt hash for password users

-- New table:
auth_password_resets -- id, user_id, token_hash, expires_at, used, created_at
```

### Migration System

- SQL files embedded in binary via `//go:embed migrations/*.sql`
- Applied in filename order (001, 002, ...)
- Checksums verified on re-run (prevents silent modifications)
- Tracked in `auth_migrations` table
- Support: `Migrate()`, `Rollback()`, `MigrationStatus()`
- `Bootstrap()` calls `Migrate()` automatically if `cfg.AutoMigrate = true`

---

## 6. Module Versioning

### Go Module Rules (Critical)

```
- v1 ALWAYS lives at the repo root — no /v1 suffix in module path
- v2+ MUST live in a subdirectory with its own go.mod
- Tags format:  v1.x.x (for root), v2.x.x (for /v2 dir)
- NO subdirectory prefix in tags — Go resolves via import path

❌ WRONG:  module github.com/meikuraledutech/auth/v1
✅ RIGHT:  module github.com/meikuraledutech/auth  (v1 is root)
```

### Tagging

```bash
# Tag v1 (root module)
git tag v1.4.0
git push origin v1.4.0

# Tag v2 (submodule at /v2)
git tag v2.1.0
git push origin v2.1.0
```

### replace Directive Rule ⚠️

**NEVER include replace directives in released/tagged code.**

```go
// ❌ WRONG — breaks Go module proxy
replace github.com/meikuraledutech/auth/v2 => ../

// ✅ OK for local development only, must remove before tagging
```

The replace directive causes:
`"module found (vX.Y.Z), but does not contain package Y"`

Because the proxy downloads the code without the parent directory.

See `VERSIONING.txt` for the full checklist.

---

## 7. Release Process

### Pre-Release Checklist

```
☐ 1. All code written and tested locally
☐ 2. go build ./... passes
☐ 3. go vet ./... passes
☐ 4. Review ALL go.mod files in the repo:
      - Root go.mod
      - v2/go.mod
      - v2/examples/go.mod
      - examples/go.mod (v1 examples)
☐ 5. Remove ALL replace directives from go.mod files
☐ 6. Update version references in go.mod files to match new tag
☐ 7. go mod tidy in each module directory
☐ 8. Commit ALL changes (go.mod, go.sum, source files)
☐ 9. Create git tag
☐ 10. Push commit + tag
☐ 11. Wait 5-30 min for module proxy to index
☐ 12. Verify: go get github.com/meikuraledutech/auth/v2@vX.Y.Z
```

### Commands

```bash
# After all changes are committed:
git tag v2.1.0
git push origin master
git push origin v2.1.0

# Verify it's available:
go clean -modcache
go get github.com/meikuraledutech/auth/v2@v2.1.0
```

---

## 8. Environment Setup

### Required Environment Variables

```bash
# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/auth_v2

# JWT
JWT_SECRET=<32+ random chars>   # openssl rand -base64 32

# ZeptoMail
ZEPTO_API_KEY=<api-key>
FROM_EMAIL=smart-forms@smart-forms.in

# Super Admin
SUPER_ADMIN_EMAIL=admin@example.com
```

### Local Development

```bash
# Clone
git clone https://github.com/meikuraledutech/auth.git
cd auth

# Setup v2
cd v2
go mod tidy

# Run tests (with replace directive for local)
cd examples
# Add replace directive to go.mod for local dev:
# replace github.com/meikuraledutech/auth/v2 => ../

export $(cat ../.env | xargs)
go run main.go
```

### PostgreSQL Setup

```bash
# Create database
psql -U postgres -c "CREATE DATABASE auth_v2;"

# Run migrations (handled by Bootstrap automatically)
# Or manually:
go run main.go  # Bootstrap() runs migrations on startup
```

---

## 9. Lessons Learned

### 1. Go Module replace Directive

**Problem:** Had `replace github.com/meikuraledutech/auth/v2 => ../` in examples/go.mod. Tagged and pushed. Module proxy downloaded the code but the `../` directory doesn't exist in the downloaded context.

**Symptom:** `"module found (v2.0.1), but does not contain package github.com/meikuraledutech/auth/v2"`

**Fix:** Remove replace directive before tagging. It caused two failed releases (v2.0.0, v2.0.1) before v2.0.2 succeeded.

**Rule:** Use replace ONLY locally. Always remove before release.

### 2. Go Module Proxy Pseudo-Versions

**Problem:** After force-pushing a tag to an old commit, the proxy had already seen newer commits and created a pseudo-version (v2.0.1) for them.

**Symptom:** `go mod tidy` kept fetching the pseudo-version instead of the real tag.

**Fix:** Don't force-push tags. If a tag needs to move to a new commit, create a new version number instead.

### 3. Commit Before Tagging

**Problem:** Made local changes to go.mod but didn't commit before tagging. The tag pointed to a commit without those changes.

**Fix:** Always `git status`, `git add`, `git commit` before `git tag`.

### 4. v1 Must Be Root Module

**Problem:** Early attempts created a `v1/go.mod` with `module github.com/meikuraledutech/auth/v1`.

**Symptom:** Go rejected the module path — `/v1` suffix is invalid in Go's module system.

**Fix:** v1 IS the root module. `go.mod` at repo root, no subdirectory.

---

## 10. Future Work

### Potential v2 Enhancements

- **Refresh Token Rotation** — Invalidate refresh tokens on use, issue new one
- **Token Revocation** — Blacklist tokens (Redis-backed) for immediate logout
- **Rate Limiting** — Built-in rate limiter for OTP/login endpoints
- **Account Lockout** — Lock after N failed attempts
- **Multi-Factor Auth** — TOTP/HOTP alongside password
- **OAuth** — Google/GitHub login support
- **Audit Logging** — Track login events, IP addresses
- **Multiple Email Providers** — SMTP, SendGrid, Mailgun support

### v3 Considerations

If v3 is needed:
1. Create `/v3` directory
2. Add `v3/go.mod` with `module github.com/meikuraledutech/auth/v3`
3. Tag as `v3.0.0` (NOT `v3/v3.0.0`)
4. Follow all rules in `VERSIONING.txt`

---

## Quick Reference

### Import Paths

```go
// v1 (OTP only)
import auth "github.com/meikuraledutech/auth"
import "github.com/meikuraledutech/auth/postgres"
import "github.com/meikuraledutech/auth/zeptomail"

// v2 (OTP + Password)
import auth "github.com/meikuraledutech/auth/v2"
import "github.com/meikuraledutech/auth/v2/postgres"
import "github.com/meikuraledutech/auth/v2/zeptomail"
```

### Key Files to Know

| File | Purpose |
|------|---------|
| `VERSIONING.txt` | Module versioning rules and checklist |
| `v2/README.md` | v2 feature overview |
| `v2/STORE_API.md` | Complete API reference |
| `v2/HELPERS.md` | Password/token function details |
| `v2/SECURITY.md` | Security best practices |
| `v2/GETTING_STARTED.md` | 5-minute setup guide |
| `KT.md` | This document |

### Documentation for v2

```
v2/DOCS_INDEX.md        — Start here, navigation hub
v2/GETTING_STARTED.md   — 5-min setup
v2/README.md            — Feature overview
v2/STORE_API.md         — Every method documented
v2/HELPERS.md           — Password/token utilities
v2/SECURITY.md          — Security guide + checklist
```
