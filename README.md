# Auth Package - Versioned

Go package for **OTP email authentication with JWT tokens and permission-based access control**.

## Versions

### V1 (Current)
```bash
go get github.com/meikuraledutech/auth/v1
```

**Import:**
```go
import (
    "github.com/meikuraledutech/auth/v1"
    "github.com/meikuraledutech/auth/v1/postgres"
)

// Usage
cfg := auth.DefaultConfig(jwtSecret, "admin@example.com")
store := postgres.New(pool, cfg)
if err := store.Bootstrap(ctx, "admin@example.com"); err != nil {
    log.Fatal(err)
}
```

**Documentation:** See [v1/DOCS.md](v1/DOCS.md)

### V2 (Coming)
Reserved for future versions with new interfaces and methods.

## Directory Structure

```
auth/
├── v1/                    ← Current stable version
│   ├── auth.go           ← Core types and interfaces
│   ├── store.go          ← Store interface definition
│   ├── token.go          ← JWT helpers
│   ├── mailer.go         ← Mailer interface
│   ├── DOCS.md           ← Full documentation
│   ├── postgres/         ← PostgreSQL implementation
│   ├── zeptomail/        ← ZeptoMail email provider
│   ├── example/          ← Usage examples
│   └── server/           ← Example HTTP server
└── v2/                    ← Next major version (empty)
```

## Getting Started

### Installation

```bash
go get github.com/meikuraledutech/auth/v1
```

### Basic Usage

```go
import (
    "github.com/meikuraledutech/auth/v1"
    "github.com/meikuraledutech/auth/v1/postgres"
)

cfg := auth.DefaultConfig(jwtSecret, "admin@example.com")
store := postgres.New(pool, cfg)
store.Bootstrap(ctx, "admin@example.com")
```

## Imports Changed

**Old:**
```go
import "github.com/meikuraledutech/auth"
```

**New (V1):**
```go
import "github.com/meikuraledutech/auth/v1"
```

## Documentation

- **[V1 Full Docs](v1/DOCS.md)** — Complete API reference
