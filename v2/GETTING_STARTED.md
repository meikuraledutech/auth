# Getting Started with Auth v2

A quick guide to integrate auth v2 into your Go project.

## Prerequisites

- Go 1.25.0 or higher
- PostgreSQL 12 or higher
- ZeptoMail account (for email)

## 5-Minute Setup

### 1. Install Package

```bash
go get github.com/meikuraledutech/auth/v2@v2.0.0
```

### 2. Create `.env` File

```bash
# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/authdb

# JWT
JWT_SECRET=$(openssl rand -base64 32)

# Email (ZeptoMail)
ZEPTO_API_KEY=your-api-key-here
FROM_EMAIL=noreply@example.com

# Admin
SUPER_ADMIN_EMAIL=admin@example.com
```

### 3. Initialize Database

```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	auth "github.com/meikuraledutech/auth/v2"
	"github.com/meikuraledutech/auth/v2/postgres"
	"github.com/meikuraledutech/auth/v2/zeptomail"
)

func main() {
	ctx := context.Background()

	// Load config
	cfg := auth.DefaultConfig(
		os.Getenv("JWT_SECRET"),
		os.Getenv("SUPER_ADMIN_EMAIL"),
	)

	// Connect to database
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	// Create store
	store := postgres.New(pool, cfg)

	// Initialize database (creates tables, seeds permissions, creates admin)
	if err := store.Bootstrap(ctx, cfg.SuperAdminEmail); err != nil {
		log.Fatal(err)
	}

	log.Println("✓ Database initialized!")
}
```

### 4. Add Authentication Endpoints

```go
package main

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	auth "github.com/meikuraledutech/auth/v2"
	"github.com/meikuraledutech/auth/v2/postgres"
	"github.com/meikuraledutech/auth/v2/zeptomail"
)

var (
	cfg    auth.Config
	store  auth.Store
	mailer auth.Mailer
)

func init() {
	cfg = auth.DefaultConfig(
		os.Getenv("JWT_SECRET"),
		os.Getenv("SUPER_ADMIN_EMAIL"),
	)

	pool, _ := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	store = postgres.New(pool, cfg)
	mailer = zeptomail.New(
		os.Getenv("ZEPTO_API_KEY"),
		os.Getenv("FROM_EMAIL"),
	)
}

// OTP Registration
func handleRequestOTP(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")

	otp, err := store.CreateOTP(r.Context(), email)
	if err != nil {
		http.Error(w, "Failed to create OTP", 500)
		return
	}

	// Send email
	mailer.SendOTP(r.Context(), email, otp.Code, cfg.OTPExpiry)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "OTP sent to " + email,
	})
}

// Verify OTP
func handleVerifyOTP(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	code := r.FormValue("code")

	user, err := store.VerifyOTP(r.Context(), email, code)
	if err != nil {
		http.Error(w, "Invalid OTP", 401)
		return
	}

	// Get permissions
	perms, _ := store.GetResolvedPermissions(r.Context(), user.ID)
	permKeys := make([]string, len(perms))
	for i, p := range perms {
		permKeys[i] = p.Key
	}

	// Generate tokens
	tokens, _ := auth.GenerateTokenPair(cfg, user, permKeys, []string{})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

// Password Registration
func handleRegister(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	user, err := store.RegisterWithPassword(r.Context(), email, password)
	if err != nil {
		switch err {
		case auth.ErrEmailAlreadyRegistered:
			http.Error(w, "Email already registered", 409)
		case auth.ErrPasswordTooWeak:
			http.Error(w, "Password too weak", 400)
		default:
			http.Error(w, "Registration failed", 500)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	})
}

// Password Login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	user, err := store.LoginWithPassword(r.Context(), email, password)
	if err != nil {
		http.Error(w, "Invalid credentials", 401)
		return
	}

	// Get permissions and generate tokens
	perms, _ := store.GetResolvedPermissions(r.Context(), user.ID)
	permKeys := make([]string, len(perms))
	for i, p := range perms {
		permKeys[i] = p.Key
	}

	tokens, _ := auth.GenerateTokenPair(cfg, user, permKeys, []string{})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

// Request Password Reset
func handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")

	rawToken, expiresAt, err := store.CreatePasswordReset(r.Context(), email)
	if err != nil {
		http.Error(w, "Server error", 500)
		return
	}

	// Build reset URL
	resetURL := "https://example.com/reset?token=" + rawToken

	// Send email
	mailer.SendPasswordReset(r.Context(), email, resetURL, cfg.PasswordResetExpiry)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Reset link sent",
		"expires_at": expiresAt,
	})
}

// Reset Password
func handleResetPassword(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	password := r.FormValue("password")

	err := store.ResetPassword(r.Context(), token, password)
	if err != nil {
		switch err {
		case auth.ErrResetTokenInvalid, auth.ErrResetTokenUsed:
			http.Error(w, "Invalid reset link", 400)
		case auth.ErrPasswordTooWeak:
			http.Error(w, "Password too weak", 400)
		default:
			http.Error(w, "Server error", 500)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password reset. Please login.",
	})
}

func main() {
	// OTP flow
	http.HandleFunc("/auth/otp/request", handleRequestOTP)
	http.HandleFunc("/auth/otp/verify", handleVerifyOTP)

	// Password flow
	http.HandleFunc("/auth/register", handleRegister)
	http.HandleFunc("/auth/login", handleLogin)
	http.HandleFunc("/auth/forgot-password", handleForgotPassword)
	http.HandleFunc("/auth/reset-password", handleResetPassword)

	http.ListenAndServe(":8080", nil)
}
```

### 5. Protect Your Routes

```go
import (
	"context"
	"strings"
)

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		// Validate token
		claims, err := auth.ValidateToken(cfg, parts[1])
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Store in context
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Protected endpoint
func handleProtected(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id":     claims.UserID,
		"email":       claims.Email,
		"permissions": claims.Permissions,
	})
}

func main() {
	// Protected routes
	http.Handle("/protected", authMiddleware(http.HandlerFunc(handleProtected)))

	http.ListenAndServe(":8080", nil)
}
```

## Common Tasks

### Send OTP to User

```go
otp, err := store.CreateOTP(ctx, "user@example.com")
if err != nil {
	log.Fatal(err)
}

err = mailer.SendOTP(ctx, "user@example.com", otp.Code, cfg.OTPExpiry)
```

### Register New User with Password

```go
user, err := store.RegisterWithPassword(ctx, "user@example.com", "SecurePass123!")
if err != nil {
	// Handle auth.ErrEmailAlreadyRegistered, auth.ErrPasswordTooWeak
	log.Fatal(err)
}

log.Printf("User created: %s\n", user.ID)
```

### Login User

```go
user, err := store.LoginWithPassword(ctx, "user@example.com", "SecurePass123!")
if err != nil {
	// Handle auth.ErrPasswordInvalid, auth.ErrPasswordNotSet
	log.Fatal(err)
}

// Generate tokens
tokens, err := auth.GenerateTokenPair(cfg, user, permissions, groups)
```

### Check User Permissions

```go
canCreate, err := store.HasResolvedPermission(ctx, userID, "forms:create")
if err != nil {
	log.Fatal(err)
}

if canCreate {
	// User can create forms
}
```

### Create Permission

```go
perm, err := store.CreatePermission(ctx, "forms:delete", "Can delete forms")
if err != nil {
	log.Fatal(err)
}
```

### Assign Permission to User

```go
err := store.AssignPermission(ctx, userID, "forms:create")
if err != nil {
	log.Fatal(err)
}
```

### Create Group and Add User

```go
group, err := store.CreateGroup(ctx, "Editors")
if err != nil {
	log.Fatal(err)
}

err = store.AssignUserToGroup(ctx, userID, group.ID)
if err != nil {
	log.Fatal(err)
}

err = store.AddPermissionToGroup(ctx, group.ID, "forms:edit")
if err != nil {
	log.Fatal(err)
}
```

### Validate Token

```go
claims, err := auth.ValidateToken(cfg, tokenString)
if err != nil {
	log.Fatal(err)
}

fmt.Printf("User: %s\n", claims.Email)
fmt.Printf("Permissions: %v\n", claims.Permissions)
```

## Testing

Run the included example to verify setup:

```bash
cd examples

# Set environment variables
export DATABASE_URL="postgresql://postgres:password@localhost:5432/authdb"
export JWT_SECRET="your-secret-key"
export ZEPTO_API_KEY="your-api-key"
export FROM_EMAIL="noreply@example.com"
export SUPER_ADMIN_EMAIL="admin@example.com"

# Run tests
go run main.go
```

Expected output:
```
=== Testing Auth v2 ===

1. Running migrations and bootstrap...
   ✓ Bootstrap complete

2. Creating OTP for dharaniadithya1998.da@gmail.com...
   ✓ OTP created: 737171

3. Sending OTP email...
   ✓ Email sent

4. Testing password auth...
   ✓ User registered
   ✓ Logged in

5. Testing password reset...
   ✓ Reset token created

6. Testing token generation...
   ✓ Access token generated
   ✓ Refresh token generated

=== All tests passed! ===
```

## Next Steps

- Read [README.md](./README.md) for complete feature overview
- Check [STORE_API.md](./STORE_API.md) for full API reference
- Review [HELPERS.md](./HELPERS.md) for helper functions
- Study [SECURITY.md](./SECURITY.md) for security best practices

## Troubleshooting

### "database connection refused"
- Ensure PostgreSQL is running
- Check DATABASE_URL in .env
- Verify credentials

### "invalid password format"
- Password must be 8+ chars
- Must include: uppercase, lowercase, digit, special char
- Example: `MyPassword123!`

### "email already registered"
- User already exists with that email
- Use login instead of register

### "invalid token"
- Token may be expired
- Token signature may be invalid
- Check JWT_SECRET matches

### "permission not found"
- Create permission first with CreatePermission
- Then assign to user/group

## Support

- Issues: [GitHub Issues](https://github.com/meikuraledutech/auth/issues)
- Documentation: See README.md, STORE_API.md, SECURITY.md
