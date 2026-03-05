# Helper Functions Reference

Helper functions for password hashing, validation, and token generation.

## Password Helpers

### HashPassword

```go
func HashPassword(cfg Config, plain string) (string, error)
```

Validates password strength, then hashes with bcrypt.

**Parameters:**
- `cfg` - Auth config (provides BcryptCost)
- `plain` - Plain text password to hash

**Returns:**
- `string` - Bcrypt hash (starts with "$2a$")
- Error if validation fails or hashing fails

**Validation:**
- Length: min 8, max 72 characters
- Must contain: uppercase, lowercase, digit, special character

**Example:**
```go
cfg := auth.DefaultConfig(jwtSecret, adminEmail)

hash, err := auth.HashPassword(cfg, "MyPassword123!")
if err == auth.ErrPasswordTooWeak {
	log.Println("Password too weak")
	return
}
if err != nil {
	log.Fatal(err)
}

// hash = "$2a$10$..."
// Store hash in database
```

---

### CheckPassword

```go
func CheckPassword(plain, hash string) error
```

Compares plain text password against bcrypt hash.

**Parameters:**
- `plain` - Plain text password to verify
- `hash` - Bcrypt hash to compare against

**Returns:**
- `nil` if passwords match
- `ErrPasswordInvalid` if passwords don't match
- Error on other issues (shouldn't happen with valid bcrypt)

**Example:**
```go
// During login
storedHash := user.PasswordHash // from database

err := auth.CheckPassword(inputPassword, storedHash)
if err == auth.ErrPasswordInvalid {
	log.Println("Wrong password")
	return
}
if err != nil {
	log.Fatal(err)
}

// Password correct!
```

---

### ValidatePasswordStrength

```go
func ValidatePasswordStrength(cfg Config, plain string) error
```

Checks if password meets strength requirements.

**Parameters:**
- `cfg` - Auth config (provides min/max length)
- `plain` - Password to validate

**Returns:**
- `nil` if password is strong
- `ErrPasswordTooWeak` if doesn't meet requirements

**Requirements:**
- Minimum length: config.MinPasswordLength (default: 8)
- Maximum length: config.MaxPasswordLength (default: 72 - bcrypt limit)
- Must contain: uppercase letter
- Must contain: lowercase letter
- Must contain: digit
- Must contain: special character (punct or symbol)

**Example:**
```go
cfg := auth.DefaultConfig(jwtSecret, adminEmail)

err := auth.ValidatePasswordStrength(cfg, "weak")
if err == auth.ErrPasswordTooWeak {
	log.Println("Password must be 8+ chars with uppercase, lowercase, digit, special char")
	return
}

err = auth.ValidatePasswordStrength(cfg, "Strong@Pass123")
if err != nil {
	log.Fatal(err)
}

log.Println("Password is strong")
```

**Valid Examples:**
- `MyPassword123!`
- `Secure@Pass456`
- `P@ssw0rd!`

**Invalid Examples:**
- `weak` - Too short, no uppercase/special
- `PASSWORD123!` - No lowercase
- `password123!` - No uppercase
- `Password123` - No special character
- `MyPass!1` - Too short (8 chars minimum)

---

## Token Helpers

### GenerateResetToken

```go
func GenerateResetToken() (string, error)
```

Generates a cryptographically secure 32-byte token, returned as base64url string.

**Returns:**
- `string` - Base64url-encoded token (43 characters)
- Error if random generation fails (very rare)

**Security:**
- 32 bytes = 256 bits of entropy
- Uses crypto/rand for CSPRNG
- No padding or special characters
- URL-safe base64url encoding

**Example:**
```go
token, err := auth.GenerateResetToken()
if err != nil {
	log.Fatal(err)
}

// token = "es_MOHB3ersvedm7IAGjIP16wGbXcGMz6CveZLVEhB8="
// Send token in reset URL, then hash it before storing

hash := auth.HashResetToken(token)
// hash = "a1b2c3d4..." (SHA-256 hex)
// Store hash in database
```

---

### HashResetToken

```go
func HashResetToken(rawToken string) string
```

Returns SHA-256 hex hash of the raw token. One-way function (non-reversible).

**Parameters:**
- `rawToken` - Raw token from GenerateResetToken

**Returns:**
- `string` - SHA-256 hash as hex (64 characters)

**Why?**
- Raw token never stored in database
- If DB is breached, attacker can't forge reset tokens
- Database only contains hash - security through one-way function

**Example:**
```go
rawToken, expiresAt, err := store.CreatePasswordReset(ctx, "user@example.com")
// rawToken = "es_MOHB3ersvedm7IAGjIP16wGbXcGMz6CveZLVEhB8="

// Inside CreatePasswordReset:
tokenHash := auth.HashResetToken(rawToken)
// tokenHash = "a1b2c3d4e5f6..." (64-char hex)
// Store tokenHash in database

// Later, when user submits token:
submittedHash := auth.HashResetToken(submittedToken)
// Compare submittedHash with stored hash
// If match, token is valid (without ever storing raw token)
```

---

## Token Generation (JWT)

### GenerateTokenPair

```go
func GenerateTokenPair(cfg Config, user *User, permissions []string, groups []string) (*TokenPair, error)
```

Creates signed access and refresh JWT tokens with embedded permissions.

**Parameters:**
- `cfg` - Auth config (provides JWTSecret, expiry times)
- `user` - User object (ID, Email)
- `permissions` - Permission keys (e.g., ["forms:create", "forms:delete"])
- `groups` - Group names (e.g., ["Admins", "Editors"])

**Returns:**
- `*TokenPair` - Contains AccessToken and RefreshToken (both JWT strings)
- Error if signing fails

**Token Details:**

**Access Token (15 min default):**
- Contains: user_id, email, permissions, groups
- Use for API authorization
- Check embedded permissions for access control
- Shorter expiry (more frequent refresh)

**Refresh Token (7 days default):**
- Contains: user_id, email (no permissions)
- Use to request new access token
- Can be stored in persistent cookie
- Longer expiry (reduce re-auth frequency)

**Example:**
```go
user, err := store.LoginWithPassword(ctx, "user@example.com", "password")
if err != nil {
	log.Fatal(err)
}

// Get user permissions
perms, err := store.GetResolvedPermissions(ctx, user.ID)
if err != nil {
	log.Fatal(err)
}

permKeys := make([]string, len(perms))
for i, p := range perms {
	permKeys[i] = p.Key
}

// Get user groups
groups, err := store.GetUserGroups(ctx, user.ID)
if err != nil {
	log.Fatal(err)
}

groupNames := make([]string, len(groups))
for i, g := range groups {
	groupNames[i] = g.Name
}

// Generate tokens
cfg := auth.DefaultConfig(jwtSecret, adminEmail)
tokens, err := auth.GenerateTokenPair(cfg, user, permKeys, groupNames)
if err != nil {
	log.Fatal(err)
}

// tokens.AccessToken = "eyJhbGciOiJIUzI1NiI..."
// tokens.RefreshToken = "eyJhbGciOiJIUzI1NiI..."

// Return to client
json.NewEncoder(w).Encode(tokens)
```

---

### ValidateToken

```go
func ValidateToken(cfg Config, tokenStr string) (*Claims, error)
```

Parses and validates JWT token, returns claims.

**Parameters:**
- `cfg` - Auth config (provides JWTSecret)
- `tokenStr` - JWT string to validate

**Returns:**
- `*Claims` - Token claims (UserID, Email, Type, Permissions, Groups)
- Error if invalid/expired/malformed

**Claim Fields:**
```go
type Claims struct {
	UserID      string   // User's ID
	Email       string   // User's email
	Type        string   // "access" or "refresh"
	Permissions []string // Only in access tokens
	Groups      []string // Only in access tokens
}
```

**Example - Using in HTTP Middleware:**
```go
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		// Parse "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		// Validate token
		cfg := auth.DefaultConfig(jwtSecret, adminEmail)
		claims, err := auth.ValidateToken(cfg, parts[1])
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Store claims in context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "email", claims.Email)
		ctx = context.WithValue(ctx, "permissions", claims.Permissions)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

**Example - Authorization Check:**
```go
func canCreateForms(claims *auth.Claims) bool {
	for _, perm := range claims.Permissions {
		if perm == "forms:create" {
			return true
		}
	}
	return false
}

// In handler:
claims, err := auth.ValidateToken(cfg, token)
if err != nil {
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return
}

if !canCreateForms(claims) {
	http.Error(w, "Forbidden", http.StatusForbidden)
	return
}

// User can create forms
```

---

## Usage Patterns

### Complete Login Flow

```go
func handleLogin(w http.ResponseWriter, r *http.Request, store auth.Store, cfg auth.Config) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	// Authenticate user
	user, err := store.LoginWithPassword(r.Context(), req.Email, req.Password)
	if err != nil {
		switch err {
		case auth.ErrPasswordInvalid:
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		default:
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
		return
	}

	// Get permissions
	perms, _ := store.GetResolvedPermissions(r.Context(), user.ID)
	permKeys := make([]string, len(perms))
	for i, p := range perms {
		permKeys[i] = p.Key
	}

	// Get groups
	groups, _ := store.GetUserGroups(r.Context(), user.ID)
	groupNames := make([]string, len(groups))
	for i, g := range groups {
		groupNames[i] = g.Name
	}

	// Generate tokens
	tokens, err := auth.GenerateTokenPair(cfg, user, permKeys, groupNames)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Return tokens
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}
```

### Complete Password Reset Flow

```go
// Step 1: Request reset
func handleForgotPassword(w http.ResponseWriter, r *http.Request, store auth.Store, mailer auth.Mailer, cfg auth.Config) {
	email := r.FormValue("email")

	rawToken, expiresAt, err := store.CreatePasswordReset(r.Context(), email)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Build reset URL
	resetURL := fmt.Sprintf("https://example.com/reset?token=%s", url.QueryEscape(rawToken))

	// Send email
	err = mailer.SendPasswordReset(r.Context(), email, resetURL, cfg.PasswordResetExpiry)
	if err != nil {
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Reset link sent to %s (expires: %s)", email, expiresAt)
}

// Step 2: Reset password with token
func handleResetPassword(w http.ResponseWriter, r *http.Request, store auth.Store, cfg auth.Config) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	// Validate new password
	err := auth.ValidatePasswordStrength(cfg, req.Password)
	if err == auth.ErrPasswordTooWeak {
		http.Error(w, "Password too weak", http.StatusBadRequest)
		return
	}

	// Reset password
	err = store.ResetPassword(r.Context(), req.Token, req.Password)
	if err != nil {
		switch err {
		case auth.ErrResetTokenInvalid, auth.ErrResetTokenUsed:
			http.Error(w, "Invalid or expired reset link", http.StatusBadRequest)
		case auth.ErrPasswordTooWeak:
			http.Error(w, "Password too weak", http.StatusBadRequest)
		default:
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Password reset successfully. Please login.")
}
```

---

## Security Best Practices

### Password Handling
- ✅ Always hash passwords before storage
- ✅ Use bcrypt with appropriate cost (default 10 is good for 2024)
- ✅ Validate strength before accepting
- ✅ Never log plain passwords
- ✅ Use HTTPS for password transmission
- ❌ Don't accept weak passwords
- ❌ Don't use MD5, SHA1, or custom hashing
- ❌ Don't return password hints

### Token Handling
- ✅ Use HTTPS for token transmission
- ✅ Include expiry in token
- ✅ Verify signature before using claims
- ✅ Store refresh tokens securely (httpOnly cookie)
- ✅ Support token revocation if needed
- ❌ Don't trust tokens without signature verification
- ❌ Don't log token contents
- ❌ Don't use overly long expiries

### Reset Tokens
- ✅ Use high-entropy tokens (256 bits minimum)
- ✅ Only store hash in database
- ✅ Mark as used immediately after verification
- ✅ Set reasonable expiry (1 hour typical)
- ✅ Invalidate on new reset request
- ❌ Don't store raw tokens
- ❌ Don't reuse tokens
- ❌ Don't use predictable formats
