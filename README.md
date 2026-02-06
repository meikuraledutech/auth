# auth

A Go package for **OTP-based email authentication** with JWT tokens, built on an interface-driven architecture. Swap out the database or email provider without changing your application code.

## Features

- **Email OTP verification** — generate, send, and verify one-time passwords
- **Auto-signup** — users are created automatically on first successful OTP verification
- **JWT tokens** — access + refresh token pairs with configurable expiry
- **Interface-based** — `Store` for database, `Mailer` for email delivery
- **PostgreSQL backend** — production-ready implementation using pgx
- **ZeptoMail integration** — branded HTML emails out of the box
- **Fiber HTTP server** — ready-to-run REST API with 4 endpoints

## Install

```bash
go get github.com/meikuraledutech/auth
```

## Quick Start

### As a library

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/meikuraledutech/auth"
    "github.com/meikuraledutech/auth/postgres"
    "github.com/meikuraledutech/auth/zeptomail"
)

func main() {
    ctx := context.Background()

    pool, _ := pgxpool.New(ctx, "postgres://localhost:5432/mydb")
    defer pool.Close()

    cfg := auth.DefaultConfig("my-jwt-secret")
    store := postgres.New(pool, cfg)
    mailer := zeptomail.New("zepto-api-key", "noreply@example.com")

    // Create tables
    store.CreateSchema(ctx)

    // Send OTP
    otp, _ := store.CreateOTP(ctx, "user@example.com")
    mailer.SendOTP(ctx, "user@example.com", otp.Code, cfg.OTPExpiry)

    // Verify OTP (auto-creates user)
    user, _ := store.VerifyOTP(ctx, "user@example.com", otp.Code)
    fmt.Printf("Welcome %s!\n", user.Email)

    // Generate JWT tokens
    tokens, _ := auth.GenerateTokenPair(cfg, user)
    fmt.Printf("Access: %s\n", tokens.AccessToken)

    // Validate token
    claims, _ := auth.ValidateToken(cfg, tokens.AccessToken)
    fmt.Printf("User ID: %s\n", claims.UserID)
}
```

### As an HTTP server

Set environment variables:

```bash
export DATABASE_URL="postgres://user:pass@localhost:5432/mydb"
export JWT_SECRET="your-secret-key"
export ZEPTO_API_KEY="your-zepto-api-key"
export FROM_EMAIL="noreply@yourdomain.com"
```

Run the server:

```bash
go run ./server/
```

## API Endpoints

### POST /otp

Request an OTP code. An email with the code is sent automatically.

```bash
curl -X POST http://localhost:3000/otp \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

```json
{
  "message": "otp sent to user@example.com",
  "expires_at": "2026-02-06T22:34:49Z"
}
```

### POST /verify

Verify the OTP code. Returns JWT tokens and the user. If the user doesn't exist, they are created automatically.

```bash
curl -X POST http://localhost:3000/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "code": "123456"}'
```

```json
{
  "access_token": "eyJhbG...",
  "refresh_token": "eyJhbG...",
  "user": {
    "id": "b797d12b-58bf-437d-983a-f8d605b73c4f",
    "email": "user@example.com",
    "created_at": "2026-02-06T22:30:23Z"
  }
}
```

### POST /refresh

Exchange a refresh token for a new token pair.

```bash
curl -X POST http://localhost:3000/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJhbG..."}'
```

```json
{
  "access_token": "eyJhbG...",
  "refresh_token": "eyJhbG..."
}
```

### GET /me

Get the current authenticated user.

```bash
curl http://localhost:3000/me \
  -H "Authorization: Bearer eyJhbG..."
```

```json
{
  "id": "b797d12b-58bf-437d-983a-f8d605b73c4f",
  "email": "user@example.com",
  "created_at": "2026-02-06T22:30:23Z"
}
```

## Configuration

`auth.DefaultConfig(jwtSecret)` returns sensible defaults:

| Setting | Default | Description |
|---------|---------|-------------|
| OTPLength | 6 | Number of digits in the OTP code |
| OTPExpiry | 5 minutes | How long an OTP is valid |
| AccessExpiry | 15 minutes | JWT access token lifetime |
| RefreshExpiry | 7 days | JWT refresh token lifetime |

Override any field after calling `DefaultConfig`:

```go
cfg := auth.DefaultConfig("secret")
cfg.OTPExpiry = 10 * time.Minute
cfg.AccessExpiry = 1 * time.Hour
```

## Interfaces

### Store

Database operations. Implement this to use a different database.

```go
type Store interface {
    CreateSchema(ctx context.Context) error
    DropSchema(ctx context.Context) error
    CreateOTP(ctx context.Context, email string) (*OTP, error)
    VerifyOTP(ctx context.Context, email string, code string) (*User, error)
    GetUserByID(ctx context.Context, id string) (*User, error)
    GetUserByEmail(ctx context.Context, email string) (*User, error)
}
```

### Mailer

Email delivery. Implement this to use a different email provider.

```go
type Mailer interface {
    SendOTP(ctx context.Context, email string, code string, expiresIn time.Duration) error
}
```

## Error Handling

| Error | Meaning |
|-------|---------|
| `auth.ErrOTPInvalid` | The OTP code is wrong or no OTP exists |
| `auth.ErrOTPExpired` | The OTP has expired |
| `auth.ErrUserNotFound` | No user found with the given ID or email |

## Database Schema

The package creates two tables:

- `auth_users` — stores user accounts (id, email, created_at)
- `auth_otps` — stores OTP codes (id, email, code, expires_at, verified, created_at)

Tables are created with `store.CreateSchema(ctx)` and use `IF NOT EXISTS` so it's safe to call multiple times.

## License

MIT License - see [LICENSE](LICENSE) for details.
